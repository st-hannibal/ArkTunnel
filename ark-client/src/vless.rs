// VLESS v0 protocol helpers.
//
// VLESS is the thin framing protocol used by sing-box as a VLESS inbound.
// After the ark-server routes an ArkTunnel connection to sing-box, the client
// must speak VLESS to tell sing-box where to connect.
//
// Request format (client → sing-box, via server relay):
//   [0x00]          version (1 byte)
//   [UUID 16B]      user identity
//   [0x00]          addon length (1 byte, no addons for v0)
//   [0x01]          command: TCP CONNECT
//   [port 2B BE]    destination port
//   [atyp 1B]       address type (0x01=IPv4, 0x02=domain, 0x03=IPv6)
//   [addr]          destination address (variable)
//
// Response format (sing-box → client, via server relay):
//   [0x00]          version (1 byte)
//   [N]             addon length (1 byte)
//   [addons N bytes] (ignored)
//
// After the response header, raw application bytes flow bidirectionally.

use crate::proxy::Target;
use anyhow::{bail, Result};
use tokio::io::AsyncReadExt;
use uuid::Uuid;

const VLESS_VERSION: u8 = 0x00;
const VLESS_CMD_TCP: u8 = 0x01;
const VLESS_ATYP_IPV4: u8 = 0x01;
const VLESS_ATYP_DOMAIN: u8 = 0x02;
const VLESS_ATYP_IPV6: u8 = 0x03;

/// Build a VLESS v0 TCP CONNECT request header for `target`.
pub fn build_request(uuid: &Uuid, target: &Target) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);

    buf.push(VLESS_VERSION);             // version
    buf.extend_from_slice(uuid.as_bytes()); // 16-byte UUID
    buf.push(0x00);                      // no addons
    buf.push(VLESS_CMD_TCP);             // command: TCP

    // Destination port (big-endian).
    let port = target.port();
    buf.push((port >> 8) as u8);
    buf.push(port as u8);

    // Address type + address.
    match target {
        Target::Ipv4(addr, _) => {
            buf.push(VLESS_ATYP_IPV4);
            buf.extend_from_slice(addr);
        }
        Target::Domain(domain, _) => {
            let bytes = domain.as_bytes();
            buf.push(VLESS_ATYP_DOMAIN);
            buf.push(bytes.len() as u8); // 1-byte length prefix
            buf.extend_from_slice(bytes);
        }
        Target::Ipv6(addr, _) => {
            buf.push(VLESS_ATYP_IPV6);
            buf.extend_from_slice(addr);
        }
    }

    buf
}

/// Read and validate the VLESS v0 response header from `reader`.
pub async fn read_response<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> Result<()> {
    let mut hdr = [0u8; 2]; // version + addon_len
    reader.read_exact(&mut hdr).await?;
    if hdr[0] != VLESS_VERSION {
        bail!("VLESS: unexpected response version: 0x{:02x}", hdr[0]);
    }
    let addon_len = hdr[1] as usize;
    if addon_len > 0 {
        let mut addons = vec![0u8; addon_len];
        reader.read_exact(&mut addons).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn build_ipv4_request() {
        let uuid = Uuid::nil();
        let target = Target::Ipv4([1, 2, 3, 4], 80);
        let req = build_request(&uuid, &target);
        // version
        assert_eq!(req[0], 0x00);
        // uuid (16B) at [1..17]
        assert_eq!(&req[1..17], uuid.as_bytes());
        // no addons
        assert_eq!(req[17], 0x00);
        // command TCP
        assert_eq!(req[18], 0x01);
        // port 80 = 0x00 0x50
        assert_eq!(req[19], 0x00);
        assert_eq!(req[20], 0x50);
        // atyp IPv4
        assert_eq!(req[21], 0x01);
        assert_eq!(&req[22..26], &[1, 2, 3, 4]);
        assert_eq!(req.len(), 26);
    }

    #[test]
    fn build_domain_request() {
        let uuid = Uuid::nil();
        let target = Target::Domain("example.com".to_string(), 443);
        let req = build_request(&uuid, &target);
        // port 443 = 0x01 0xBB
        assert_eq!(req[19], 0x01);
        assert_eq!(req[20], 0xBB);
        // atyp domain
        assert_eq!(req[21], 0x02);
        // length
        assert_eq!(req[22], 11);
        assert_eq!(&req[23..34], b"example.com");
    }
}
