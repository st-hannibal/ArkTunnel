//! ARK-frame v0 — native ArkTunnel application protocol.
//!
//! Sent by the client as the second application packet over a BIP 324
//! channel (the first packet is `ARK1 || uuid`).  The server replies with
//! a single status byte; on `STATUS_OK` raw bytes flow bidirectionally.
//!
//! Wire format:
//!
//! ```text
//!  client → server
//!  +------+-------+----------+--------+
//!  | cmd  | atype |   addr   |  port  |
//!  | u8   |  u8   | variable |  u16BE |
//!  +------+-------+----------+--------+
//!
//!  server → client
//!  +--------+
//!  | status |  (0x00 = OK, then bidi data)
//!  +--------+
//! ```

use anyhow::{bail, Result};
use std::net::IpAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const CMD_TCP_CONNECT: u8 = 0x01;

pub const ATYPE_IPV4: u8 = 0x01;
pub const ATYPE_DOMAIN: u8 = 0x03;
pub const ATYPE_IPV6: u8 = 0x04;

pub const STATUS_OK: u8 = 0x00;
pub const STATUS_CONN_REFUSED: u8 = 0x01;
pub const STATUS_UNREACHABLE: u8 = 0x02;
pub const STATUS_GENERIC: u8 = 0xFF;

/// Parsed ARK-frame request target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameTarget {
    Ipv4([u8; 4], u16),
    Domain(String, u16),
    Ipv6([u8; 16], u16),
}

impl FrameTarget {
    pub fn port(&self) -> u16 {
        match self {
            FrameTarget::Ipv4(_, p) | FrameTarget::Domain(_, p) | FrameTarget::Ipv6(_, p) => *p,
        }
    }

    /// Render as a `host:port` string for `tokio::net::lookup_host`.
    pub fn to_connect_string(&self) -> String {
        match self {
            FrameTarget::Ipv4(a, p) => {
                let ip = std::net::Ipv4Addr::from(*a);
                format!("{ip}:{p}")
            }
            FrameTarget::Ipv6(a, p) => {
                let ip = std::net::Ipv6Addr::from(*a);
                format!("[{ip}]:{p}")
            }
            FrameTarget::Domain(d, p) => format!("{d}:{p}"),
        }
    }
}

/// Build a TCP-connect ARK-frame request for the given destination.
pub fn build_request_ipv4(addr: [u8; 4], port: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(8);
    v.push(CMD_TCP_CONNECT);
    v.push(ATYPE_IPV4);
    v.extend_from_slice(&addr);
    v.extend_from_slice(&port.to_be_bytes());
    v
}

pub fn build_request_ipv6(addr: [u8; 16], port: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(20);
    v.push(CMD_TCP_CONNECT);
    v.push(ATYPE_IPV6);
    v.extend_from_slice(&addr);
    v.extend_from_slice(&port.to_be_bytes());
    v
}

pub fn build_request_domain(domain: &str, port: u16) -> Result<Vec<u8>> {
    let bytes = domain.as_bytes();
    if bytes.is_empty() || bytes.len() > 253 {
        bail!("domain length out of range (1..=253): {}", bytes.len());
    }
    let mut v = Vec::with_capacity(5 + bytes.len());
    v.push(CMD_TCP_CONNECT);
    v.push(ATYPE_DOMAIN);
    v.push(bytes.len() as u8);
    v.extend_from_slice(bytes);
    v.extend_from_slice(&port.to_be_bytes());
    Ok(v)
}

/// Convenience: build from the target enum used by callers.
pub fn build_request(target: &FrameTarget) -> Result<Vec<u8>> {
    match target {
        FrameTarget::Ipv4(a, p) => Ok(build_request_ipv4(*a, *p)),
        FrameTarget::Ipv6(a, p) => Ok(build_request_ipv6(*a, *p)),
        FrameTarget::Domain(d, p) => build_request_domain(d, *p),
    }
}

/// Read and parse an ARK-frame request from `reader` (server side).
pub async fn read_request<R: AsyncRead + Unpin>(reader: &mut R) -> Result<FrameTarget> {
    let mut hdr = [0u8; 2];
    reader.read_exact(&mut hdr).await?;
    let cmd = hdr[0];
    let atype = hdr[1];
    if cmd != CMD_TCP_CONNECT {
        bail!("ARK-frame: unsupported cmd 0x{cmd:02x}");
    }
    let target = match atype {
        ATYPE_IPV4 => {
            let mut a = [0u8; 4];
            reader.read_exact(&mut a).await?;
            let mut p = [0u8; 2];
            reader.read_exact(&mut p).await?;
            FrameTarget::Ipv4(a, u16::from_be_bytes(p))
        }
        ATYPE_IPV6 => {
            let mut a = [0u8; 16];
            reader.read_exact(&mut a).await?;
            let mut p = [0u8; 2];
            reader.read_exact(&mut p).await?;
            FrameTarget::Ipv6(a, u16::from_be_bytes(p))
        }
        ATYPE_DOMAIN => {
            let mut len_buf = [0u8; 1];
            reader.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            if len == 0 {
                bail!("ARK-frame: zero-length domain");
            }
            let mut name = vec![0u8; len];
            reader.read_exact(&mut name).await?;
            let domain = String::from_utf8(name)
                .map_err(|e| anyhow::anyhow!("ARK-frame: domain not utf-8: {e}"))?;
            let mut p = [0u8; 2];
            reader.read_exact(&mut p).await?;
            FrameTarget::Domain(domain, u16::from_be_bytes(p))
        }
        other => bail!("ARK-frame: unknown atype 0x{other:02x}"),
    };
    Ok(target)
}

/// Write a single status byte (server side).
pub async fn write_status<W: AsyncWrite + Unpin>(writer: &mut W, status: u8) -> Result<()> {
    writer.write_all(&[status]).await?;
    writer.flush().await?;
    Ok(())
}

/// Read and validate the server's status byte (client side).
pub async fn read_status<R: AsyncRead + Unpin>(reader: &mut R) -> Result<()> {
    let mut s = [0u8; 1];
    reader.read_exact(&mut s).await?;
    match s[0] {
        STATUS_OK => Ok(()),
        STATUS_CONN_REFUSED => bail!("ARK-frame status: connection refused"),
        STATUS_UNREACHABLE => bail!("ARK-frame status: host unreachable"),
        other => bail!("ARK-frame status: error 0x{other:02x}"),
    }
}

/// Map a `std::io::Error` to the most appropriate ARK-frame status byte.
pub fn status_for_io_error(err: &std::io::Error) -> u8 {
    use std::io::ErrorKind::*;
    match err.kind() {
        ConnectionRefused => STATUS_CONN_REFUSED,
        HostUnreachable | NetworkUnreachable | AddrNotAvailable | NotFound => STATUS_UNREACHABLE,
        _ => STATUS_GENERIC,
    }
}

/// Helper for the server to also accept an `IpAddr` directly.
impl From<(IpAddr, u16)> for FrameTarget {
    fn from((ip, port): (IpAddr, u16)) -> Self {
        match ip {
            IpAddr::V4(v4) => FrameTarget::Ipv4(v4.octets(), port),
            IpAddr::V6(v6) => FrameTarget::Ipv6(v6.octets(), port),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn roundtrip_ipv4() {
        let req = build_request_ipv4([1, 2, 3, 4], 80);
        assert_eq!(req, vec![0x01, 0x01, 1, 2, 3, 4, 0x00, 0x50]);
        let mut r = BufReader::new(req.as_slice());
        let parsed = read_request(&mut r).await.unwrap();
        assert_eq!(parsed, FrameTarget::Ipv4([1, 2, 3, 4], 80));
    }

    #[tokio::test]
    async fn roundtrip_ipv6() {
        let addr = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let req = build_request_ipv6(addr, 443);
        let mut r = BufReader::new(req.as_slice());
        let parsed = read_request(&mut r).await.unwrap();
        assert_eq!(parsed, FrameTarget::Ipv6(addr, 443));
    }

    #[tokio::test]
    async fn roundtrip_domain() {
        let req = build_request_domain("example.com", 443).unwrap();
        let mut r = BufReader::new(req.as_slice());
        let parsed = read_request(&mut r).await.unwrap();
        assert_eq!(parsed, FrameTarget::Domain("example.com".to_string(), 443));
    }

    #[test]
    fn domain_length_validation() {
        assert!(build_request_domain("", 80).is_err());
        let too_long = "a".repeat(254);
        assert!(build_request_domain(&too_long, 80).is_err());
    }

    #[tokio::test]
    async fn status_ok_passes() {
        let mut r = BufReader::new(&[0u8][..]);
        read_status(&mut r).await.unwrap();
    }

    #[tokio::test]
    async fn status_error_fails() {
        let mut r = BufReader::new(&[0x01u8][..]);
        let err = read_status(&mut r).await.unwrap_err();
        assert!(err.to_string().contains("connection refused"));
    }

    #[test]
    fn unknown_atype_rejected() {
        // not actually decoded by build helpers, but the read path is the
        // one we care about; that's covered indirectly here via a manual frame:
        let bad = [CMD_TCP_CONNECT, 0xAA, 0, 0];
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let res = rt.block_on(async {
            let mut r = BufReader::new(&bad[..]);
            read_request(&mut r).await
        });
        assert!(res.is_err());
    }

    #[test]
    fn connect_string_renders() {
        assert_eq!(
            FrameTarget::Ipv4([8, 8, 8, 8], 53).to_connect_string(),
            "8.8.8.8:53"
        );
        assert_eq!(
            FrameTarget::Domain("example.com".into(), 443).to_connect_string(),
            "example.com:443"
        );
    }
}
