//! Bundled DoH stub (Phase 12 / WP12).
//!
//! Listens on a local UDP port (default `127.0.0.1:5353`) and forwards
//! incoming DNS queries as RFC 8484 DoH POSTs (`application/dns-message`)
//! to a chosen upstream resolver. The HTTPS request is routed through the
//! local `ark-client` SOCKS5 listener so the actual DNS lookup egresses
//! via the tunnel — neither the LAN/ISP nor the ark-server operator can
//! see the queried hostname.
//!
//! Why this exists:
//!   * v0.1.9 already routes DNS *bytes* via the tunnel in TUN mode, but
//!     plaintext UDP/53 still goes to the user's configured resolver
//!     (often the ISP), and the server *operator* sees the queries.
//!   * DoH inside the tunnel gives end-to-end confidentiality of the
//!     query name — the operator only sees encrypted bytes to e.g.
//!     `cloudflare-dns.com`.
//!
//! Threat-model caveats:
//!   * The chosen DoH provider can still see your queries — pick one
//!     you trust (Cloudflare, Quad9, Mullvad, NextDNS, etc.).
//!   * This is *not* a replacement for system DoH/DoT — it's a one-binary
//!     option for users who can't reconfigure their OS resolver.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

/// Maximum DNS-over-UDP message size we will accept. Standard limit is
/// 512 bytes, EDNS0 commonly bumps this to 4096; we use 4096 to be safe.
const MAX_DNS_MSG: usize = 4096;

/// Per-query timeout for the upstream DoH POST.
const DOH_TIMEOUT: Duration = Duration::from_secs(5);

/// Default upstream DoH endpoint. Cloudflare's `1.1.1.1` resolver, RFC
/// 8484 endpoint. Operators / users can override via `--upstream`.
pub const DEFAULT_UPSTREAM: &str = "https://cloudflare-dns.com/dns-query";

/// Default UDP listen address.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:5353";

/// Configuration for the DoH stub.
#[derive(Debug, Clone)]
pub struct DohConfig {
    /// Local UDP listen address (e.g. `127.0.0.1:5353`).
    pub listen: SocketAddr,
    /// Upstream DoH endpoint (must be HTTPS).
    pub upstream: String,
    /// Local SOCKS5 listener to route the DoH POST through. When `None`,
    /// the request goes out over the host's normal network — useful for
    /// unit tests but defeats the purpose in production.
    pub socks5: Option<String>,
}

impl DohConfig {
    pub fn new(listen: SocketAddr, upstream: String, socks5: Option<String>) -> Result<Self> {
        if !upstream.starts_with("https://") {
            bail!("DoH upstream must be HTTPS, got: {upstream}");
        }
        Ok(Self { listen, upstream, socks5 })
    }
}

/// Build a `reqwest::Client` configured for DoH POSTs, optionally
/// tunneled through a local SOCKS5 listener.
fn build_client(socks5: Option<&str>) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder().timeout(DOH_TIMEOUT);
    if let Some(addr) = socks5 {
        // reqwest expects `socks5://host:port` (DNS resolved locally) or
        // `socks5h://host:port` (DNS resolved at the proxy). We use `h`
        // so the upstream hostname (e.g. cloudflare-dns.com) is resolved
        // by the ark-server, not by the host running the stub.
        let proxy_url = format!("socks5h://{addr}");
        let proxy = reqwest::Proxy::all(&proxy_url)
            .with_context(|| format!("invalid SOCKS5 proxy URL: {proxy_url}"))?;
        b = b.proxy(proxy);
    }
    b.build().context("building reqwest client")
}

/// Forward a single raw DNS query through DoH. Public so unit tests can
/// drive it against a stub HTTPS server.
pub async fn forward_one(
    client: &reqwest::Client,
    upstream: &str,
    query: &[u8],
) -> Result<Vec<u8>> {
    if query.is_empty() {
        bail!("empty DNS query");
    }
    if query.len() > MAX_DNS_MSG {
        bail!("DNS query too large ({} > {MAX_DNS_MSG})", query.len());
    }
    let resp = client
        .post(upstream)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(query.to_vec())
        .send()
        .await
        .with_context(|| format!("POST {upstream}"))?;
    let status = resp.status();
    if !status.is_success() {
        bail!("DoH upstream returned HTTP {status}");
    }
    let bytes = resp.bytes().await.context("reading DoH response body")?;
    if bytes.is_empty() {
        bail!("DoH upstream returned empty body");
    }
    if bytes.len() > MAX_DNS_MSG {
        bail!("DoH response too large ({} > {MAX_DNS_MSG})", bytes.len());
    }
    Ok(bytes.to_vec())
}

/// Run the DoH stub forever. Returns only on a fatal error (bind / accept).
pub async fn run(cfg: DohConfig) -> Result<()> {
    let socket = UdpSocket::bind(cfg.listen)
        .await
        .with_context(|| format!("binding DoH UDP listener on {}", cfg.listen))?;
    let socket = Arc::new(socket);
    let client = Arc::new(build_client(cfg.socks5.as_deref())?);
    let upstream: Arc<str> = Arc::from(cfg.upstream.as_str());

    info!(
        listen = %cfg.listen,
        upstream = %cfg.upstream,
        socks5 = ?cfg.socks5,
        "DoH stub listening"
    );

    let mut buf = vec![0u8; MAX_DNS_MSG];
    loop {
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                error!(error = %e, "DoH recv_from failed");
                continue;
            }
        };
        if n == 0 {
            continue;
        }
        let query = buf[..n].to_vec();
        let socket_c = socket.clone();
        let client_c = client.clone();
        let upstream_c = upstream.clone();
        tokio::spawn(async move {
            match forward_one(&client_c, &upstream_c, &query).await {
                Ok(reply) => {
                    if let Err(e) = socket_c.send_to(&reply, peer).await {
                        warn!(peer = %peer, error = %e, "failed to send DoH reply");
                    } else {
                        debug!(peer = %peer, q = query.len(), a = reply.len(), "DoH ok");
                    }
                }
                Err(e) => {
                    warn!(peer = %peer, error = %e, "DoH forward failed");
                    // Best-effort SERVFAIL so the client doesn't hang. We
                    // mirror the query header (first 12 bytes) and set
                    // QR=1, RCODE=2 (SERVFAIL).
                    if let Some(servfail) = build_servfail(&query) {
                        let _ = socket_c.send_to(&servfail, peer).await;
                    }
                }
            }
        });
    }
}

/// Build a minimal SERVFAIL response for the given query so the client
/// gets a quick failure instead of a timeout. Returns `None` if the
/// query is too short to even contain a DNS header.
fn build_servfail(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut r = query.to_vec();
    // Set QR=1 (response), preserve the RD bit, clear AA/TC/opcode-extras.
    r[2] = 0b1000_0000 | (query[2] & 0b0000_0001); // QR=1 + RD bit copied
    r[3] = 0b1000_0010; // RA=1, Z=0, RCODE=2 (SERVFAIL)
    // Zero ANCOUNT, NSCOUNT, ARCOUNT (keep QDCOUNT).
    r[6] = 0; r[7] = 0;
    r[8] = 0; r[9] = 0;
    r[10] = 0; r[11] = 0;
    // Truncate any answer section the upstream might have left appended.
    // For SERVFAIL we only return the question section; find its end by
    // walking from offset 12 — but the question may be malformed under
    // error conditions, so just return the header + original tail and
    // let the resolver re-parse: most resolvers tolerate trailing bytes.
    Some(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns_query_a_example_com(id: u16) -> Vec<u8> {
        // Minimal DNS query: header(12) + QNAME + QTYPE(A=1) + QCLASS(IN=1).
        let mut q = Vec::new();
        q.extend_from_slice(&id.to_be_bytes()); // ID
        q.extend_from_slice(&[0x01, 0x00]);     // RD=1, otherwise zero
        q.extend_from_slice(&[0x00, 0x01]);     // QDCOUNT=1
        q.extend_from_slice(&[0x00, 0x00]);     // ANCOUNT
        q.extend_from_slice(&[0x00, 0x00]);     // NSCOUNT
        q.extend_from_slice(&[0x00, 0x00]);     // ARCOUNT
        // QNAME = "example" "com" 0
        for label in ["example", "com"] {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
        q.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
        q
    }

    #[test]
    fn cfg_rejects_non_https_upstream() {
        let r = DohConfig::new(
            "127.0.0.1:5353".parse().unwrap(),
            "http://insecure.example/dns-query".to_string(),
            None,
        );
        assert!(r.is_err());
    }

    #[test]
    fn cfg_accepts_https_upstream() {
        let r = DohConfig::new(
            "127.0.0.1:5353".parse().unwrap(),
            "https://cloudflare-dns.com/dns-query".to_string(),
            Some("127.0.0.1:1080".to_string()),
        );
        assert!(r.is_ok());
    }

    #[test]
    fn servfail_sets_response_and_rcode2() {
        let q = dns_query_a_example_com(0x1234);
        let r = build_servfail(&q).expect("servfail");
        // Same ID echoed back.
        assert_eq!(&r[..2], &q[..2]);
        // QR bit set.
        assert_eq!(r[2] & 0x80, 0x80);
        // RCODE = 2 (SERVFAIL).
        assert_eq!(r[3] & 0x0f, 0x02);
        // No answers.
        assert_eq!(&r[6..8], &[0, 0]);
    }

    #[test]
    fn build_client_invalid_proxy_errors() {
        // Bogus proxy URL should be rejected by reqwest.
        let r = build_client(Some("not a url"));
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn forward_one_rejects_oversized_query() {
        let client = build_client(None).unwrap();
        let huge = vec![0u8; MAX_DNS_MSG + 1];
        let r = forward_one(&client, "https://127.0.0.1:1/dns-query", &huge).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn forward_one_round_trip_against_local_http_stub() {
        // Spin up a tiny TCP server that pretends to be an HTTP/1.1 endpoint
        // and echoes the request body back as the response body. This is
        // *not* TLS, so we can only exercise the request path by pointing
        // forward_one() at a `http://` URL — but DohConfig::new rejects
        // those, so we call `forward_one` directly (it does not validate
        // the scheme; only DohConfig does). This proves the wire format.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            // Read until we have headers + body. Reqwest sends content-length,
            // so just slurp once and split.
            let n = s.read(&mut buf).await.unwrap();
            let req = &buf[..n];
            let body_idx = req
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|p| p + 4)
                .unwrap_or(n);
            let body = req[body_idx..].to_vec();
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/dns-message\r\ncontent-length: {}\r\n\r\n",
                body.len()
            );
            s.write_all(resp.as_bytes()).await.unwrap();
            s.write_all(&body).await.unwrap();
            s.flush().await.unwrap();
        });

        let q = dns_query_a_example_com(0xBEEF);
        let client = reqwest::Client::builder()
            .timeout(DOH_TIMEOUT)
            .build()
            .unwrap();
        let url = format!("http://{addr}/dns-query");
        let r = forward_one(&client, &url, &q).await;
        server.await.ok();
        let reply = r.expect("forward_one ok");
        assert_eq!(reply, q, "echo server should mirror the body");
    }

    #[allow(dead_code)]
    fn _force_unused_imports() {
        // intentionally empty: keeps test imports honest if a feature
        // flag drops a path under conditional compilation.
    }
}
