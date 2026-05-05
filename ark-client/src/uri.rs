// ArkTunnel URI parser.
//
// Format (single endpoint, v0.1.x compatible):
//   arktunnel://<uuid>@<host>:<port>?transport=bip324[&nodekey=<hex128>]
//
// Format (multi-endpoint, v0.2.0+):
//   arktunnel://<uuid>@<h1>:<p1>,<h2>:<p2>,...?transport=bip324
// or with `&backup=` query params:
//   arktunnel://<uuid>@<h1>:<p1>?transport=bip324&backup=<h2>:<p2>&backup=<h3>:<p3>
//
// The first entry is the primary endpoint. Additional entries are tried in
// order on connect failure (see `ark-client::proxy`). Order is preserved;
// duplicates (same host+port string match) are deduped while preserving
// first-occurrence order.

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

/// A single `(host, port)` endpoint. `host` may be a DNS name, IPv4 literal,
/// or bracket-stripped IPv6 literal. Resolved lazily by callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.host.contains(':') {
            // IPv6 literal — re-bracket for readability.
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

#[derive(Debug, Clone)]
pub struct ArkUri {
    pub uuid: Uuid,
    /// All endpoints in URI order. Always non-empty; index 0 is the primary.
    pub endpoints: Vec<Endpoint>,
    pub transport: TransportKind,
    /// RLPx static public key (64 bytes, x||y). Required for rlpx transport.
    pub nodekey: Option<[u8; 64]>,
}

impl ArkUri {
    /// Primary endpoint host. Convenience accessor for the first endpoint.
    pub fn host(&self) -> &str {
        &self.endpoints[0].host
    }

    /// Primary endpoint port. Convenience accessor for the first endpoint.
    pub fn port(&self) -> u16 {
        self.endpoints[0].port
    }
}

impl ArkUri {
    /// Parse an `arktunnel://` URI.
    ///
    /// See module-level docs for the supported grammar.
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

        let (hostlist, query) = match rest.split_once('?') {
            Some((hp, q)) => (hp, q),
            None => (rest, ""),
        };

        let mut endpoints: Vec<Endpoint> = Vec::new();
        for entry in hostlist.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                bail!("URI contains an empty host:port entry");
            }
            endpoints.push(parse_host_port(entry)?);
        }

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
                "backup" => {
                    endpoints.push(parse_host_port(val)?);
                }
                _ => {} // ignore unknown params for forward compatibility
            }
        }

        // Dedupe while preserving order.
        let mut seen: std::collections::HashSet<(String, u16)> =
            std::collections::HashSet::new();
        endpoints.retain(|e| seen.insert((e.host.clone(), e.port)));

        if endpoints.is_empty() {
            bail!("URI must contain at least one host:port endpoint");
        }

        if transport == TransportKind::Rlpx && nodekey.is_none() {
            bail!("rlpx transport requires nodekey= query parameter in URI");
        }

        if transport == TransportKind::Rlpx && endpoints.len() > 1 {
            bail!("rlpx transport does not support multi-endpoint URIs");
        }

        Ok(Self {
            uuid,
            endpoints,
            transport,
            nodekey,
        })
    }
}

/// Parse a single `host:port` entry. Accepts bracketed IPv6 literals.
fn parse_host_port(s: &str) -> Result<Endpoint> {
    let s = s.trim();
    // Bracketed IPv6: `[::1]:8333`.
    let (host_raw, port_str) = if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .with_context(|| format!("unterminated IPv6 bracket in {s}"))?;
        let port_str = after
            .strip_prefix(':')
            .with_context(|| format!("missing port after IPv6 bracket in {s}"))?;
        (host.to_string(), port_str)
    } else {
        let (h, p) = s
            .rsplit_once(':')
            .with_context(|| format!("missing port in endpoint: {s}"))?;
        (h.to_string(), p)
    };

    if host_raw.is_empty() {
        bail!("empty host in endpoint: {s}");
    }
    let port: u16 = port_str
        .parse()
        .with_context(|| format!("invalid port in endpoint {s}: {port_str}"))?;

    Ok(Endpoint {
        host: host_raw,
        port,
    })
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
        assert_eq!(uri.host(), "1.2.3.4");
        assert_eq!(uri.port(), 8333);
        assert_eq!(uri.endpoints.len(), 1);
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

    #[test]
    fn parse_multi_endpoint_comma() {
        let uri = ArkUri::parse(
            "arktunnel://550e8400-e29b-41d4-a716-446655440000@h1.example:8333,h2.example:8334,1.2.3.4:9000?transport=bip324",
        )
        .unwrap();
        assert_eq!(uri.endpoints.len(), 3);
        assert_eq!(uri.endpoints[0].host, "h1.example");
        assert_eq!(uri.endpoints[0].port, 8333);
        assert_eq!(uri.endpoints[1].host, "h2.example");
        assert_eq!(uri.endpoints[1].port, 8334);
        assert_eq!(uri.endpoints[2].host, "1.2.3.4");
        assert_eq!(uri.endpoints[2].port, 9000);
        // Primary accessors return the first.
        assert_eq!(uri.host(), "h1.example");
        assert_eq!(uri.port(), 8333);
    }

    #[test]
    fn parse_multi_endpoint_backup_param() {
        let uri = ArkUri::parse(
            "arktunnel://550e8400-e29b-41d4-a716-446655440000@h1.example:8333?transport=bip324&backup=h2.example:8334&backup=h3.example:8335",
        )
        .unwrap();
        assert_eq!(uri.endpoints.len(), 3);
        assert_eq!(uri.endpoints[0].host, "h1.example");
        assert_eq!(uri.endpoints[1].host, "h2.example");
        assert_eq!(uri.endpoints[2].host, "h3.example");
    }

    #[test]
    fn parse_multi_endpoint_mixed() {
        // Comma-separated primary list + extra `&backup=` entries.
        let uri = ArkUri::parse(
            "arktunnel://550e8400-e29b-41d4-a716-446655440000@h1:8333,h2:8334?transport=bip324&backup=h3:8335",
        )
        .unwrap();
        assert_eq!(uri.endpoints.len(), 3);
        assert_eq!(uri.endpoints[0].host, "h1");
        assert_eq!(uri.endpoints[1].host, "h2");
        assert_eq!(uri.endpoints[2].host, "h3");
    }

    #[test]
    fn dedupe_identical_endpoints_preserves_first_order() {
        let uri = ArkUri::parse(
            "arktunnel://550e8400-e29b-41d4-a716-446655440000@h1:8333,h2:8334,h1:8333?transport=bip324&backup=h2:8334",
        )
        .unwrap();
        assert_eq!(uri.endpoints.len(), 2);
        assert_eq!(uri.endpoints[0].host, "h1");
        assert_eq!(uri.endpoints[1].host, "h2");
    }

    #[test]
    fn reject_empty_entry_in_list() {
        assert!(ArkUri::parse(
            "arktunnel://550e8400-e29b-41d4-a716-446655440000@h1:8333,,h2:8334?transport=bip324",
        )
        .is_err());
    }

    #[test]
    fn parse_ipv6_bracketed_endpoint() {
        let uri = ArkUri::parse(
            "arktunnel://550e8400-e29b-41d4-a716-446655440000@[2001:db8::1]:8333?transport=bip324",
        )
        .unwrap();
        assert_eq!(uri.endpoints.len(), 1);
        assert_eq!(uri.endpoints[0].host, "2001:db8::1");
        assert_eq!(uri.endpoints[0].port, 8333);
    }

    #[test]
    fn reject_rlpx_with_multiple_endpoints() {
        let nodekey = "aa".repeat(64);
        let uri_str = format!(
            "arktunnel://550e8400-e29b-41d4-a716-446655440000@h1:30303,h2:30304?transport=rlpx&nodekey={}",
            nodekey
        );
        assert!(ArkUri::parse(&uri_str).is_err());
    }
}
