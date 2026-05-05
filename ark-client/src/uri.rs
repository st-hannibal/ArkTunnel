// ArkTunnel URI parser.
//
// Format: arktunnel://<uuid>@<host>:<port>?transport=bip324[&nodekey=<hex128>]

use anyhow::{bail, Context, Result};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportKind {
    Bip324,
    Rlpx,
}

impl std::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportKind::Bip324 => write!(f, "bip324"),
            TransportKind::Rlpx => write!(f, "rlpx"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ArkUri {
    pub uuid: Uuid,
    pub host: String,
    pub port: u16,
    pub transport: TransportKind,
    /// RLPx static public key (64 bytes, x||y). Required for rlpx transport.
    pub nodekey: Option<[u8; 64]>,
}

impl ArkUri {
    /// Parse an `arktunnel://` URI.
    ///
    /// Format: `arktunnel://<uuid>@<host>:<port>?transport=bip324[&nodekey=<hex128>]`
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let rest = s
            .strip_prefix("arktunnel://")
            .context("URI must start with arktunnel://")?;

        let (userinfo, rest) = rest
            .split_once('@')
            .context("URI missing '@' (expected arktunnel://<uuid>@<host>:<port>)")?;

        let uuid = Uuid::parse_str(userinfo)
            .with_context(|| format!("invalid UUID in URI: {userinfo}"))?;

        let (hostport, query) = match rest.split_once('?') {
            Some((hp, q)) => (hp, q),
            None => (rest, ""),
        };

        let (host_raw, port_str) = hostport
            .rsplit_once(':')
            .context("URI missing port (expected <host>:<port>)")?;

        // Strip IPv6 brackets.
        let host = host_raw
            .trim_matches(|c: char| c == '[' || c == ']')
            .to_string();
        if host.is_empty() {
            bail!("URI has empty host");
        }

        let port: u16 = port_str
            .parse()
            .with_context(|| format!("invalid port in URI: {port_str}"))?;

        let mut transport = TransportKind::Bip324;
        let mut nodekey: Option<[u8; 64]> = None;

        for param in query.split('&') {
            if param.is_empty() {
                continue;
            }
            let (key, val) = match param.split_once('=') {
                Some(kv) => kv,
                None => continue,
            };
            match key {
                "transport" => {
                    transport = match val {
                        "bip324" => TransportKind::Bip324,
                        "rlpx" => TransportKind::Rlpx,
                        other => bail!("unknown transport: {other} (expected bip324 or rlpx)"),
                    };
                }
                "nodekey" => {
                    let bytes = decode_hex(val)
                        .context("nodekey must be a hex-encoded 64-byte key")?;
                    if bytes.len() != 64 {
                        bail!(
                            "nodekey must be 64 bytes (128 hex chars), got {} bytes",
                            bytes.len()
                        );
                    }
                    let mut arr = [0u8; 64];
                    arr.copy_from_slice(&bytes);
                    nodekey = Some(arr);
                }
                _ => {} // ignore unknown params for forward compatibility
            }
        }

        if transport == TransportKind::Rlpx && nodekey.is_none() {
            bail!("rlpx transport requires nodekey= query parameter in URI");
        }

        Ok(Self {
            uuid,
            host,
            port,
            transport,
            nodekey,
        })
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        bail!("hex string has odd length ({})", s.len());
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .with_context(|| format!("invalid hex character at position {}", 2 * i))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bip324_uri() {
        let uri = ArkUri::parse(
            "arktunnel://550e8400-e29b-41d4-a716-446655440000@1.2.3.4:8333?transport=bip324",
        )
        .unwrap();
        assert_eq!(uri.host, "1.2.3.4");
        assert_eq!(uri.port, 8333);
        assert_eq!(uri.transport, TransportKind::Bip324);
        assert!(uri.nodekey.is_none());
    }

    #[test]
    fn parse_rlpx_uri() {
        let nodekey = "aa".repeat(64);
        let uri_str = format!(
            "arktunnel://550e8400-e29b-41d4-a716-446655440000@1.2.3.4:30303?transport=rlpx&nodekey={}",
            nodekey
        );
        let uri = ArkUri::parse(&uri_str).unwrap();
        assert_eq!(uri.transport, TransportKind::Rlpx);
        assert!(uri.nodekey.is_some());
    }

    #[test]
    fn reject_rlpx_without_nodekey() {
        let result = ArkUri::parse(
            "arktunnel://550e8400-e29b-41d4-a716-446655440000@1.2.3.4:30303?transport=rlpx",
        );
        assert!(result.is_err());
    }

    #[test]
    fn reject_missing_scheme() {
        assert!(ArkUri::parse("vless://something").is_err());
    }

    #[test]
    fn parse_default_transport_bip324() {
        // No ?transport= param → default to bip324
        let uri = ArkUri::parse(
            "arktunnel://550e8400-e29b-41d4-a716-446655440000@example.com:8333",
        )
        .unwrap();
        assert_eq!(uri.transport, TransportKind::Bip324);
    }
}
