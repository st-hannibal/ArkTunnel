// HTTP CONNECT proxy server (RFC 7231 §4.3.6).
//
// Listens on 127.0.0.1:8118 by default.  Only the CONNECT method is
// supported — all other HTTP methods receive 405 Method Not Allowed.
//
// Protocol:
//   Client → proxy:  CONNECT <host>:<port> HTTP/1.x\r\n
//                    Host: <host>:<port>\r\n
//                    \r\n
//   Proxy → client:  HTTP/1.1 200 Connection Established\r\n\r\n
//   Then: bidirectional raw tunnel.

use crate::pool::Pool;
use crate::proxy::Target;
use crate::uri::ArkUri;
use anyhow::{bail, Result};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error};

/// Run the HTTP CONNECT proxy until an unrecoverable listener error.
pub async fn run_http_proxy(addr: &str, uri: Arc<ArkUri>, pool: Arc<Pool>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("HTTP CONNECT proxy listening on {addr}");
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                debug!("HTTP proxy new connection from {peer}");
                let uri = uri.clone();
                let pool = pool.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_http_connect(stream, uri, pool).await {
                        debug!("HTTP proxy connection closed: {e}");
                    }
                });
            }
            Err(e) => error!("HTTP proxy accept error: {e}"),
        }
    }
}

async fn handle_http_connect(stream: TcpStream, _uri: Arc<ArkUri>, pool: Arc<Pool>) -> Result<()> {
    let mut buf_reader = BufReader::new(stream);

    // Read request line.
    let mut request_line = String::new();
    buf_reader.read_line(&mut request_line).await?;

    // Drain remaining headers (until blank line).
    loop {
        let mut line = String::new();
        let n = buf_reader.read_line(&mut line).await?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }

    let mut client = buf_reader.into_inner();
    let target = match parse_connect_target(request_line.trim()) {
        Ok(t) => t,
        Err(e) => {
            client
                .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                .await?;
            return Err(e);
        }
    };

    // Acquire stream from pool (or open fresh transport if pool is empty).
    let mut stream = match pool.acquire(&target).await {
        Ok(s) => s,
        Err(e) => {
            client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await?;
            return Err(e);
        }
    };

    // Signal success to the HTTP client.
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    // Bidirectional copy.
    tokio::io::copy_bidirectional(&mut client, &mut stream).await?;
    Ok(())
}

/// Parse the host and port from an HTTP CONNECT request line.
///
/// Expected: `CONNECT <host>:<port> HTTP/1.x`
fn parse_connect_target(line: &str) -> Result<Target> {
    let mut parts = line.splitn(3, ' ');
    let method = parts.next().unwrap_or("");
    let hostport = parts.next().unwrap_or("");

    if !method.eq_ignore_ascii_case("CONNECT") {
        bail!("HTTP proxy: expected CONNECT, got {method:?}");
    }
    if hostport.is_empty() {
        bail!("HTTP CONNECT: missing host:port");
    }

    let (host_raw, port_str) = hostport
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("HTTP CONNECT: missing port in {hostport:?}"))?;

    let port: u16 = port_str
        .parse()
        .map_err(|_| anyhow::anyhow!("HTTP CONNECT: invalid port {port_str:?}"))?;

    // Strip IPv6 brackets.
    let host = host_raw.trim_matches(|c: char| c == '[' || c == ']');

    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        return Ok(Target::Ipv4(v4.octets(), port));
    }
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        return Ok(Target::Ipv6(v6.octets(), port));
    }
    Ok(Target::Domain(host.to_string(), port))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_domain_target() {
        let t = parse_connect_target("CONNECT example.com:443 HTTP/1.1").unwrap();
        match t {
            Target::Domain(d, p) => {
                assert_eq!(d, "example.com");
                assert_eq!(p, 443);
            }
            _ => panic!("expected Domain"),
        }
    }

    #[test]
    fn parse_ipv4_target() {
        let t = parse_connect_target("CONNECT 1.2.3.4:80 HTTP/1.1").unwrap();
        match t {
            Target::Ipv4(addr, p) => {
                assert_eq!(addr, [1, 2, 3, 4]);
                assert_eq!(p, 80);
            }
            _ => panic!("expected Ipv4"),
        }
    }

    #[test]
    fn reject_non_connect() {
        assert!(parse_connect_target("GET / HTTP/1.1").is_err());
    }
}
