//! ARK-frame — native ArkTunnel application protocol.
//!
//! Sent by the client as the second application packet over a BIP 324
//! channel (the first packet is `ARK1 || uuid`).  The server replies with
//! a single status byte; on `STATUS_OK`:
//!  - for `CMD_TCP_CONNECT` (v0): raw bytes flow bidirectionally.
//!  - for `CMD_UDP_ASSOCIATE` (v1): a stream of length-prefixed datagrams
//!    flows in both directions — see `read_udp_datagram`/`write_udp_datagram`.
//!
//! Wire format (request, common to both commands):
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
//!  | status |  (0x00 = OK)
//!  +--------+
//! ```
//!
//! For UDP_ASSOCIATE the request `addr/port` is a binding hint (typically
//! all-zero — the client doesn't know yet which destinations it will use).
//! After STATUS_OK, both sides exchange datagrams framed as:
//!
//! ```text
//!  +-------+-------+----------+--------+--------+----------+
//!  | total | atype |   addr   |  port  |  dlen  | payload  |
//!  | u16BE |  u8   | variable |  u16BE |  u16BE |  bytes   |
//!  +-------+-------+----------+--------+--------+----------+
//! ```
//!
//! `total` covers all bytes after itself (atype..payload), so a receiver
//! can frame without parsing the inner address. Max payload size is bounded
//! by `MAX_UDP_PAYLOAD` (65000) to keep total within u16 range.

use anyhow::{bail, Result};
use std::net::IpAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const CMD_TCP_CONNECT: u8 = 0x01;
pub const CMD_UDP_ASSOCIATE: u8 = 0x02;

/// Largest UDP payload we will frame (keeps `total` < u16::MAX with header room).
pub const MAX_UDP_PAYLOAD: usize = 65000;

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

/// Build a UDP_ASSOCIATE request. `addr/port` is a binding hint, typically zero.
pub fn build_udp_associate(addr: [u8; 4], port: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(8);
    v.push(CMD_UDP_ASSOCIATE);
    v.push(ATYPE_IPV4);
    v.extend_from_slice(&addr);
    v.extend_from_slice(&port.to_be_bytes());
    v
}

/// Read and parse an ARK-frame request from `reader` (server side).
///
/// Returns `(cmd, target)` so the server can dispatch on TCP vs UDP.
pub async fn read_request_full<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(u8, FrameTarget)> {
    let mut hdr = [0u8; 2];
    reader.read_exact(&mut hdr).await?;
    let cmd = hdr[0];
    let atype = hdr[1];
    if cmd != CMD_TCP_CONNECT && cmd != CMD_UDP_ASSOCIATE {
        bail!("ARK-frame: unsupported cmd 0x{cmd:02x}");
    }
    let target = read_addr_port(reader, atype).await?;
    Ok((cmd, target))
}

/// Back-compat: read a TCP_CONNECT request (errors on any other cmd).
pub async fn read_request<R: AsyncRead + Unpin>(reader: &mut R) -> Result<FrameTarget> {
    let (cmd, target) = read_request_full(reader).await?;
    if cmd != CMD_TCP_CONNECT {
        bail!("ARK-frame: expected TCP_CONNECT, got 0x{cmd:02x}");
    }
    Ok(target)
}

async fn read_addr_port<R: AsyncRead + Unpin>(reader: &mut R, atype: u8) -> Result<FrameTarget> {
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

// ---------------------------------------------------------------------------
// UDP datagram framing (v1)
// ---------------------------------------------------------------------------

/// Serialize a UDP datagram with its source/destination address into the
/// length-prefixed framing used after a successful UDP_ASSOCIATE handshake.
pub fn build_udp_datagram(target: &FrameTarget, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > MAX_UDP_PAYLOAD {
        bail!("ARK-frame UDP payload too large: {} > {}", payload.len(), MAX_UDP_PAYLOAD);
    }
    let addr_part: Vec<u8> = match target {
        FrameTarget::Ipv4(a, p) => {
            let mut v = Vec::with_capacity(1 + 4 + 2);
            v.push(ATYPE_IPV4);
            v.extend_from_slice(a);
            v.extend_from_slice(&p.to_be_bytes());
            v
        }
        FrameTarget::Ipv6(a, p) => {
            let mut v = Vec::with_capacity(1 + 16 + 2);
            v.push(ATYPE_IPV6);
            v.extend_from_slice(a);
            v.extend_from_slice(&p.to_be_bytes());
            v
        }
        FrameTarget::Domain(d, p) => {
            let bytes = d.as_bytes();
            if bytes.is_empty() || bytes.len() > 253 {
                bail!("ARK-frame UDP: domain length out of range");
            }
            let mut v = Vec::with_capacity(1 + 1 + bytes.len() + 2);
            v.push(ATYPE_DOMAIN);
            v.push(bytes.len() as u8);
            v.extend_from_slice(bytes);
            v.extend_from_slice(&p.to_be_bytes());
            v
        }
    };
    // total = addr_part + dlen(2) + payload
    let total = addr_part.len() + 2 + payload.len();
    if total > u16::MAX as usize {
        bail!("ARK-frame UDP frame too large: {}", total);
    }
    let mut out = Vec::with_capacity(2 + total);
    out.extend_from_slice(&(total as u16).to_be_bytes());
    out.extend_from_slice(&addr_part);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Read one UDP datagram + address from the framed stream. Returns
/// `(target, payload)`. EOF returns `Err`.
pub async fn read_udp_datagram<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<(FrameTarget, Vec<u8>)> {
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).await?;
    let total = u16::from_be_bytes(len_buf) as usize;
    if total < 1 + 2 {
        bail!("ARK-frame UDP: total too small ({total})");
    }
    // Slurp the whole frame so we can parse without partial reads on the wire.
    let mut buf = vec![0u8; total];
    reader.read_exact(&mut buf).await?;
    if buf.is_empty() {
        bail!("ARK-frame UDP: empty body");
    }
    let atype = buf[0];
    let (target, addr_consumed) = parse_addr_port(&buf[1..], atype)?;
    let consumed = 1 + addr_consumed;
    if buf.len() < consumed + 2 {
        bail!("ARK-frame UDP: truncated dlen");
    }
    let dlen = u16::from_be_bytes([buf[consumed], buf[consumed + 1]]) as usize;
    let payload_start = consumed + 2;
    if buf.len() != payload_start + dlen {
        bail!(
            "ARK-frame UDP: dlen={} doesn't match remaining {}",
            dlen,
            buf.len() - payload_start
        );
    }
    Ok((target, buf[payload_start..].to_vec()))
}

/// Synchronous address parser. Returns `(target, bytes_consumed)`.
fn parse_addr_port(buf: &[u8], atype: u8) -> Result<(FrameTarget, usize)> {
    match atype {
        ATYPE_IPV4 => {
            if buf.len() < 6 {
                bail!("ARK-frame: short IPv4 addr");
            }
            let mut a = [0u8; 4];
            a.copy_from_slice(&buf[..4]);
            let p = u16::from_be_bytes([buf[4], buf[5]]);
            Ok((FrameTarget::Ipv4(a, p), 6))
        }
        ATYPE_IPV6 => {
            if buf.len() < 18 {
                bail!("ARK-frame: short IPv6 addr");
            }
            let mut a = [0u8; 16];
            a.copy_from_slice(&buf[..16]);
            let p = u16::from_be_bytes([buf[16], buf[17]]);
            Ok((FrameTarget::Ipv6(a, p), 18))
        }
        ATYPE_DOMAIN => {
            if buf.is_empty() {
                bail!("ARK-frame: missing domain length");
            }
            let dlen = buf[0] as usize;
            if dlen == 0 {
                bail!("ARK-frame: zero-length domain");
            }
            if buf.len() < 1 + dlen + 2 {
                bail!("ARK-frame: short domain frame");
            }
            let domain = std::str::from_utf8(&buf[1..1 + dlen])
                .map_err(|e| anyhow::anyhow!("ARK-frame: domain not utf-8: {e}"))?
                .to_string();
            let p = u16::from_be_bytes([buf[1 + dlen], buf[2 + dlen]]);
            Ok((FrameTarget::Domain(domain, p), 1 + dlen + 2))
        }
        other => bail!("ARK-frame: unknown atype 0x{other:02x}"),
    }
}

/// Write a single UDP datagram frame.
pub async fn write_udp_datagram<W: AsyncWrite + Unpin>(
    writer: &mut W,
    target: &FrameTarget,
    payload: &[u8],
) -> Result<()> {
    let frame = build_udp_datagram(target, payload)?;
    writer.write_all(&frame).await?;
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

    #[tokio::test]
    async fn udp_associate_request_roundtrip() {
        let req = build_udp_associate([0, 0, 0, 0], 0);
        assert_eq!(req[0], CMD_UDP_ASSOCIATE);
        let mut r = BufReader::new(req.as_slice());
        let (cmd, target) = read_request_full(&mut r).await.unwrap();
        assert_eq!(cmd, CMD_UDP_ASSOCIATE);
        assert_eq!(target, FrameTarget::Ipv4([0, 0, 0, 0], 0));
    }

    #[tokio::test]
    async fn udp_datagram_roundtrip_ipv4() {
        let target = FrameTarget::Ipv4([1, 1, 1, 1], 53);
        let payload = b"\x00\x01\x01\x00 hello dns";
        let frame = build_udp_datagram(&target, payload).unwrap();
        let mut r = BufReader::new(frame.as_slice());
        let (got_t, got_p) = read_udp_datagram(&mut r).await.unwrap();
        assert_eq!(got_t, target);
        assert_eq!(got_p, payload);
    }

    #[tokio::test]
    async fn udp_datagram_roundtrip_domain() {
        let target = FrameTarget::Domain("example.com".into(), 443);
        let payload = b"quic-initial-bytes";
        let frame = build_udp_datagram(&target, payload).unwrap();
        let mut r = BufReader::new(frame.as_slice());
        let (got_t, got_p) = read_udp_datagram(&mut r).await.unwrap();
        assert_eq!(got_t, target);
        assert_eq!(got_p, payload);
    }

    #[tokio::test]
    async fn udp_datagram_two_back_to_back() {
        let t1 = FrameTarget::Ipv4([8, 8, 8, 8], 53);
        let t2 = FrameTarget::Ipv6([0; 16], 9);
        let mut wire = build_udp_datagram(&t1, b"first").unwrap();
        wire.extend(build_udp_datagram(&t2, b"second").unwrap());
        let mut r = BufReader::new(wire.as_slice());
        let (a_t, a_p) = read_udp_datagram(&mut r).await.unwrap();
        let (b_t, b_p) = read_udp_datagram(&mut r).await.unwrap();
        assert_eq!(a_t, t1);
        assert_eq!(a_p, b"first");
        assert_eq!(b_t, t2);
        assert_eq!(b_p, b"second");
    }

    #[test]
    fn udp_payload_too_large_rejected() {
        let oversize = vec![0u8; MAX_UDP_PAYLOAD + 1];
        let r = build_udp_datagram(&FrameTarget::Ipv4([0; 4], 0), &oversize);
        assert!(r.is_err());
    }
}
