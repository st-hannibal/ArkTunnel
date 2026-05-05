// Signed JSON pool registry (Phase 12 / WP3).
//
// Operators publish a tiny JSON document describing the current pool of
// ark-server endpoints. The client fetches it once at start, verifies a
// detached Ed25519 signature against a pinned public key, and uses the
// returned endpoint list in place of the URI's static list. The verified
// document is cached on disk and used as a fallback if the next start-up
// fetch fails (e.g. censor block).
//
// Document schema (all fields required unless noted):
//
//   {
//     "version": 1,
//     "updated": "2026-05-05T09:00:00Z",
//     "servers": [
//       {"host": "h1.example", "port": 8333,
//        "weight": 1, "transport": "bip324"}
//     ],
//     "sig": "<hex-encoded 64-byte Ed25519 signature>"
//   }
//
// The signature covers the canonical JSON of {version, updated, servers}
// (i.e. the document with `sig` removed) serialized with serde_json's
// default formatter and sorted top-level key order: `servers`, `updated`,
// `version`. See `canonical_payload` for the exact bytes.
//
// Deliberately minimal: no gossip, no DHT, no push updates — a static
// signed file fetched over HTTPS.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::uri::{Endpoint, TransportKind};

const CACHE_FILENAME: &str = "pool.json";
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// Hard cap on the registry document size (defends against a malicious or
/// misconfigured server returning multi-megabyte garbage).
const MAX_BODY_BYTES: usize = 64 * 1024;
/// Hard cap on the number of endpoints accepted from a registry.
const MAX_SERVERS: usize = 128;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEntry {
    pub host: String,
    pub port: u16,
    #[serde(default = "default_weight")]
    pub weight: u32,
    pub transport: String,
}

fn default_weight() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolDoc {
    pub version: u32,
    pub updated: String,
    pub servers: Vec<ServerEntry>,
    pub sig: String,
}

/// The subset of a `PoolDoc` that is actually signed. Field order is
/// deliberate (alphabetical) so canonical serialization is reproducible
/// across implementations.
#[derive(Debug, Serialize)]
struct SignedPayload<'a> {
    servers: &'a [ServerEntry],
    updated: &'a str,
    version: u32,
}

fn canonical_payload(doc: &PoolDoc) -> Result<Vec<u8>> {
    let p = SignedPayload {
        servers: &doc.servers,
        updated: &doc.updated,
        version: doc.version,
    };
    serde_json::to_vec(&p).context("serializing signed payload")
}

fn verify(doc: &PoolDoc, pubkey: &VerifyingKey) -> Result<()> {
    let sig_bytes = hex::decode(doc.sig.trim())
        .context("pool sig is not valid hex")?;
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("pool sig must be 64 bytes (got {})", sig_bytes.len()))?;
    let sig = Signature::from_bytes(&sig_array);
    let payload = canonical_payload(doc)?;
    pubkey
        .verify(&payload, &sig)
        .context("pool registry signature verification failed")
}

fn parse_pubkey(hex_str: &str) -> Result<VerifyingKey> {
    let bytes = hex::decode(hex_str.trim()).context("--pool-pubkey is not valid hex")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("--pool-pubkey must be 32 bytes (got {})", bytes.len()))?;
    VerifyingKey::from_bytes(&arr).context("--pool-pubkey is not a valid Ed25519 public key")
}

fn cache_path() -> Option<PathBuf> {
    dirs::cache_dir().map(|d| d.join("arktunnel").join(CACHE_FILENAME))
}

async fn fetch(url: &str) -> Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .build()
        .context("building HTTP client")?;
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?
        .error_for_status()
        .with_context(|| format!("GET {url}: non-2xx"))?;

    let bytes = resp
        .bytes()
        .await
        .with_context(|| format!("reading body from {url}"))?;
    if bytes.len() > MAX_BODY_BYTES {
        bail!(
            "pool registry too large: {} bytes (max {MAX_BODY_BYTES})",
            bytes.len()
        );
    }
    Ok(bytes.to_vec())
}

fn parse_and_verify(raw: &[u8], pubkey: &VerifyingKey) -> Result<PoolDoc> {
    if raw.len() > MAX_BODY_BYTES {
        bail!("pool registry too large: {} bytes", raw.len());
    }
    let doc: PoolDoc = serde_json::from_slice(raw).context("parsing pool registry JSON")?;
    if doc.version != 1 {
        bail!("unsupported pool registry version: {}", doc.version);
    }
    if doc.servers.is_empty() {
        bail!("pool registry contains zero servers");
    }
    if doc.servers.len() > MAX_SERVERS {
        bail!(
            "pool registry has too many servers ({} > {MAX_SERVERS})",
            doc.servers.len()
        );
    }
    verify(&doc, pubkey)?;
    Ok(doc)
}

fn write_cache(raw: &[u8]) {
    let Some(path) = cache_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&path, raw) {
        warn!(path = %path.display(), error = %e, "failed to write pool registry cache");
    } else {
        debug!(path = %path.display(), "wrote pool registry cache");
    }
}

fn read_cache() -> Option<Vec<u8>> {
    let path = cache_path()?;
    match std::fs::read(&path) {
        Ok(b) if b.len() <= MAX_BODY_BYTES => Some(b),
        Ok(b) => {
            warn!(
                path = %path.display(),
                "cached pool registry too large ({} bytes); ignoring",
                b.len()
            );
            None
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "failed to read pool cache");
            None
        }
    }
}

/// Convert a verified pool document into endpoints filtered by the URI's
/// transport. Entries with a different transport are dropped (logged).
pub fn doc_to_endpoints(doc: &PoolDoc, want: &TransportKind) -> Vec<Endpoint> {
    let want_str = want.to_string();
    let mut out = Vec::with_capacity(doc.servers.len());
    for s in &doc.servers {
        if s.transport != want_str {
            debug!(
                host = %s.host,
                port = s.port,
                transport = %s.transport,
                "skipping pool entry: transport mismatch"
            );
            continue;
        }
        out.push(Endpoint {
            host: s.host.clone(),
            port: s.port,
        });
    }
    out
}

/// Fetch (or fall back to cached) and verify the pool registry. Returns the
/// verified document. Errors only if no acceptable document can be obtained.
pub async fn load(url: &str, pubkey_hex: &str) -> Result<PoolDoc> {
    let pubkey = parse_pubkey(pubkey_hex)?;

    match fetch(url).await {
        Ok(raw) => match parse_and_verify(&raw, &pubkey) {
            Ok(doc) => {
                info!(
                    url = %url,
                    servers = doc.servers.len(),
                    updated = %doc.updated,
                    "pool registry fetched and verified"
                );
                write_cache(&raw);
                return Ok(doc);
            }
            Err(e) => {
                warn!(url = %url, error = %format!("{e:#}"), "fresh pool fetch failed verification");
            }
        },
        Err(e) => {
            warn!(url = %url, error = %format!("{e:#}"), "pool fetch failed");
        }
    }

    // Fall back to cache.
    if let Some(raw) = read_cache() {
        match parse_and_verify(&raw, &pubkey) {
            Ok(doc) => {
                info!(
                    servers = doc.servers.len(),
                    updated = %doc.updated,
                    "using cached pool registry"
                );
                return Ok(doc);
            }
            Err(e) => {
                warn!(error = %format!("{e:#}"), "cached pool registry failed verification; ignoring");
            }
        }
    }

    Err(anyhow!(
        "pool registry unavailable from {url} and no valid cached copy"
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_doc(servers: Vec<ServerEntry>, sk: &SigningKey) -> PoolDoc {
        let mut doc = PoolDoc {
            version: 1,
            updated: "2026-05-05T00:00:00Z".to_string(),
            servers,
            sig: String::new(),
        };
        let payload = canonical_payload(&doc).unwrap();
        let sig = sk.sign(&payload);
        doc.sig = hex::encode(sig.to_bytes());
        doc
    }

    fn srv(host: &str, port: u16, transport: &str) -> ServerEntry {
        ServerEntry {
            host: host.to_string(),
            port,
            weight: 1,
            transport: transport.to_string(),
        }
    }

    #[test]
    fn signed_doc_round_trip() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let doc = make_doc(vec![srv("h1", 8333, "bip324")], &sk);
        let raw = serde_json::to_vec(&doc).unwrap();
        let parsed = parse_and_verify(&raw, &sk.verifying_key()).unwrap();
        assert_eq!(parsed.servers.len(), 1);
        assert_eq!(parsed.servers[0].host, "h1");
    }

    #[test]
    fn tampered_doc_fails_verification() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let mut doc = make_doc(vec![srv("h1", 8333, "bip324")], &sk);
        // Mutate a field that is part of the signed payload.
        doc.servers[0].port = 9999;
        let raw = serde_json::to_vec(&doc).unwrap();
        assert!(parse_and_verify(&raw, &sk.verifying_key()).is_err());
    }

    #[test]
    fn wrong_pubkey_fails_verification() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let other = SigningKey::from_bytes(&[8u8; 32]);
        let doc = make_doc(vec![srv("h1", 8333, "bip324")], &sk);
        let raw = serde_json::to_vec(&doc).unwrap();
        assert!(parse_and_verify(&raw, &other.verifying_key()).is_err());
    }

    #[test]
    fn unsupported_version_rejected() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let mut doc = make_doc(vec![srv("h1", 8333, "bip324")], &sk);
        doc.version = 2;
        // Re-sign so the signature isn't the failure reason.
        let payload = canonical_payload(&doc).unwrap();
        doc.sig = hex::encode(sk.sign(&payload).to_bytes());
        let raw = serde_json::to_vec(&doc).unwrap();
        assert!(parse_and_verify(&raw, &sk.verifying_key()).is_err());
    }

    #[test]
    fn empty_server_list_rejected() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let doc = make_doc(vec![], &sk);
        let raw = serde_json::to_vec(&doc).unwrap();
        assert!(parse_and_verify(&raw, &sk.verifying_key()).is_err());
    }

    #[test]
    fn doc_to_endpoints_filters_by_transport() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let doc = make_doc(
            vec![
                srv("h1", 8333, "bip324"),
                srv("h2", 30303, "rlpx"),
                srv("h3", 8334, "bip324"),
            ],
            &sk,
        );
        let eps = doc_to_endpoints(&doc, &TransportKind::Bip324);
        assert_eq!(eps.len(), 2);
        assert_eq!(eps[0].host, "h1");
        assert_eq!(eps[1].host, "h3");
    }

    #[test]
    fn parse_pubkey_validates_length() {
        assert!(parse_pubkey(&"aa".repeat(32)).is_ok());
        assert!(parse_pubkey(&"aa".repeat(31)).is_err());
        assert!(parse_pubkey("not-hex").is_err());
    }
}
