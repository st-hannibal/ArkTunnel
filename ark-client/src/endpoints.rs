// Endpoint health tracking + connect-with-failover.
//
// Phase 12 / WP2: client-side multi-endpoint dispatch with sticky preference
// and short-lived demotion of failing endpoints. Process-local, in-memory
// only — there is no on-disk state.
//
// Order of candidates on each connect attempt:
//   1. Sticky-preferred endpoint (last one that succeeded), if not demoted.
//   2. Remaining endpoints in URI order, skipping demoted ones.
//   3. If everything is demoted, retry demoted endpoints in URI order
//      (a last-ditch attempt rather than failing immediately).
//
// On success: clear failures, refresh `last_success`, set as preferred.
// On failure: increment failures; on the 3rd consecutive failure, demote
// the endpoint for 60s and reset the counter.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use ark_core::{
    bip324::Bip324Transport, rlpx::RlpxTransport, transport::{BoxedAsyncReadWrite, Transport},
};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::uri::{ArkUri, Endpoint, TransportKind};

/// Maximum consecutive connect failures before an endpoint is demoted.
const FAILURE_THRESHOLD: u32 = 3;
/// How long an endpoint stays demoted after hitting the threshold.
const DEMOTION_DURATION: Duration = Duration::from_secs(60);
/// Per-endpoint TCP-connect + transport-handshake deadline.
const CONNECT_DEADLINE: Duration = Duration::from_secs(3);

#[derive(Debug, Default, Clone)]
struct Health {
    consecutive_failures: u32,
    demoted_until: Option<Instant>,
    last_success: Option<Instant>,
}

impl Health {
    fn is_demoted(&self, now: Instant) -> bool {
        matches!(self.demoted_until, Some(t) if t > now)
    }
}

#[derive(Debug, Default)]
struct RegistryInner {
    health: HashMap<(String, u16), Health>,
    /// Index into `ArkUri::endpoints` of the most-recently-successful one.
    preferred_idx: Option<usize>,
}

#[derive(Debug, Default)]
pub struct EndpointRegistry {
    inner: Mutex<RegistryInner>,
}

impl EndpointRegistry {
    fn record_success(&self, idx: usize, ep: &Endpoint) {
        let mut g = self.inner.lock().unwrap();
        let entry = g.health.entry((ep.host.clone(), ep.port)).or_default();
        entry.consecutive_failures = 0;
        entry.demoted_until = None;
        entry.last_success = Some(Instant::now());
        g.preferred_idx = Some(idx);
    }

    /// Returns true if the endpoint was just demoted.
    fn record_failure(&self, ep: &Endpoint) -> bool {
        let mut g = self.inner.lock().unwrap();
        let entry = g.health.entry((ep.host.clone(), ep.port)).or_default();
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        if entry.consecutive_failures >= FAILURE_THRESHOLD {
            entry.demoted_until = Some(Instant::now() + DEMOTION_DURATION);
            entry.consecutive_failures = 0;
            true
        } else {
            false
        }
    }

    fn snapshot(&self) -> (Option<usize>, HashMap<(String, u16), Health>) {
        let g = self.inner.lock().unwrap();
        (g.preferred_idx, g.health.clone())
    }
}

/// Process-wide registry. Lazily initialized on first use; one URI per process.
pub fn registry() -> &'static EndpointRegistry {
    static REGISTRY: OnceLock<EndpointRegistry> = OnceLock::new();
    REGISTRY.get_or_init(EndpointRegistry::default)
}

/// Build the prioritized try-order for the configured endpoints.
///
/// Returns (live_indices, demoted_indices). Callers should try `live_indices`
/// first and only fall back to `demoted_indices` if every live attempt fails.
fn ordered_candidates(uri: &ArkUri) -> (Vec<usize>, Vec<usize>) {
    let now = Instant::now();
    let (preferred, health) = registry().snapshot();

    let mut live = Vec::with_capacity(uri.endpoints.len());
    let mut demoted = Vec::new();

    // Sticky preferred first (only if currently live and still in the list).
    let mut preferred_pushed_live = false;
    if let Some(idx) = preferred {
        if let Some(ep) = uri.endpoints.get(idx) {
            let h = health.get(&(ep.host.clone(), ep.port));
            if h.is_none_or(|h| !h.is_demoted(now)) {
                live.push(idx);
                preferred_pushed_live = true;
            }
        }
    }

    for (i, ep) in uri.endpoints.iter().enumerate() {
        if preferred_pushed_live && Some(i) == preferred {
            continue; // already pushed to live
        }
        let h = health.get(&(ep.host.clone(), ep.port));
        if h.is_some_and(|h| h.is_demoted(now)) {
            demoted.push(i);
        } else {
            live.push(i);
        }
    }

    (live, demoted)
}

/// Resolve a single `Endpoint` to socket addresses. Accepts IP literals
/// (no DNS round-trip) and DNS names.
async fn resolve(ep: &Endpoint) -> Result<Vec<std::net::SocketAddr>> {
    if let Ok(ip) = ep.host.parse::<std::net::IpAddr>() {
        return Ok(vec![std::net::SocketAddr::new(ip, ep.port)]);
    }
    let addrs = tokio::net::lookup_host((ep.host.as_str(), ep.port))
        .await
        .with_context(|| format!("resolving endpoint host {}", ep.host))?;
    let v: Vec<_> = addrs.collect();
    if v.is_empty() {
        return Err(anyhow!("no addresses resolved for {}:{}", ep.host, ep.port));
    }
    Ok(v)
}

/// Try a single endpoint: TCP connect (with timeout) + transport handshake.
async fn try_endpoint(uri: &ArkUri, ep: &Endpoint) -> Result<BoxedAsyncReadWrite> {
    let addrs = resolve(ep).await?;

    // Try the resolved addresses in order. We give the *whole* attempt
    // (including transport handshake) a single CONNECT_DEADLINE budget so
    // a slow handshake counts the same as a slow TCP SYN.
    let attempt = async {
        let mut last_err: Option<anyhow::Error> = None;
        for addr in &addrs {
            match TcpStream::connect(addr).await {
                Ok(tcp) => {
                    let _ = tcp.set_nodelay(true);
                    return handshake(uri, tcp, *addr).await;
                }
                Err(e) => {
                    last_err =
                        Some(anyhow::Error::new(e).context(format!("TCP connect to {addr}")));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("no addresses tried for {}:{}", ep.host, ep.port)))
    };

    match tokio::time::timeout(CONNECT_DEADLINE, attempt).await {
        Ok(r) => r,
        Err(_) => Err(anyhow!(
            "endpoint {}:{} timed out after {:?}",
            ep.host,
            ep.port,
            CONNECT_DEADLINE
        )),
    }
}

async fn handshake(
    uri: &ArkUri,
    tcp: TcpStream,
    addr: std::net::SocketAddr,
) -> Result<BoxedAsyncReadWrite> {
    match uri.transport {
        TransportKind::Bip324 => Bip324Transport::connect(tcp, addr)
            .await
            .context("BIP 324 handshake failed"),
        TransportKind::Rlpx => {
            if let Some(nodekey) = uri.nodekey {
                ark_core::rlpx::set_peer_pub(nodekey);
            }
            RlpxTransport::connect(tcp, addr)
                .await
                .context("RLPx handshake failed")
        }
    }
}

/// Connect to the configured ark-server with multi-endpoint failover.
///
/// Returns a transport-handshaked stream from the first endpoint that
/// succeeds. If every live endpoint fails, retries demoted endpoints once
/// before giving up.
pub async fn connect_with_failover(uri: &ArkUri) -> Result<BoxedAsyncReadWrite> {
    let (live, demoted) = ordered_candidates(uri);
    let mut errors: Vec<String> = Vec::new();

    for idx in live.iter().chain(demoted.iter()).copied() {
        let ep = &uri.endpoints[idx];
        debug!(endpoint = %ep, "trying endpoint");
        match try_endpoint(uri, ep).await {
            Ok(stream) => {
                if !errors.is_empty() {
                    info!(endpoint = %ep, "connected after {} failure(s)", errors.len());
                }
                registry().record_success(idx, ep);
                return Ok(stream);
            }
            Err(e) => {
                let demoted_now = registry().record_failure(ep);
                if demoted_now {
                    warn!(endpoint = %ep, "demoted for {:?}", DEMOTION_DURATION);
                } else {
                    debug!(endpoint = %ep, error = %e, "endpoint connect failed");
                }
                errors.push(format!("{ep}: {e:#}"));
            }
        }
    }

    Err(anyhow!(
        "all {} endpoint(s) failed: {}",
        errors.len(),
        errors.join("; ")
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(host: &str, port: u16) -> Endpoint {
        Endpoint {
            host: host.to_string(),
            port,
        }
    }

    #[test]
    fn health_default_not_demoted() {
        let h = Health::default();
        assert!(!h.is_demoted(Instant::now()));
    }

    #[test]
    fn record_failure_demotes_after_threshold() {
        let r = EndpointRegistry::default();
        let e = ep("h1", 8333);
        assert!(!r.record_failure(&e)); // 1
        assert!(!r.record_failure(&e)); // 2
        assert!(r.record_failure(&e));  // 3 → demoted
        let (_, h) = r.snapshot();
        let entry = h.get(&("h1".to_string(), 8333)).unwrap();
        assert!(entry.is_demoted(Instant::now()));
        // Counter resets after demotion.
        assert_eq!(entry.consecutive_failures, 0);
    }

    #[test]
    fn record_success_clears_state_and_sets_preferred() {
        let r = EndpointRegistry::default();
        let e = ep("h1", 8333);
        r.record_failure(&e);
        r.record_failure(&e);
        r.record_success(2, &e);
        let (preferred, h) = r.snapshot();
        assert_eq!(preferred, Some(2));
        let entry = h.get(&("h1".to_string(), 8333)).unwrap();
        assert_eq!(entry.consecutive_failures, 0);
        assert!(entry.demoted_until.is_none());
        assert!(entry.last_success.is_some());
    }

    /// Mirrors the orchestration logic used by `ordered_candidates`, but
    /// against an ad-hoc registry so the test does not touch the global one.
    fn order(registry: &EndpointRegistry, endpoints: &[Endpoint]) -> (Vec<usize>, Vec<usize>) {
        let now = Instant::now();
        let (preferred, health) = registry.snapshot();
        let mut live = Vec::new();
        let mut demoted = Vec::new();
        let mut preferred_pushed_live = false;
        if let Some(idx) = preferred {
            if let Some(ep) = endpoints.get(idx) {
                let h = health.get(&(ep.host.clone(), ep.port));
                if h.is_none_or(|h| !h.is_demoted(now)) {
                    live.push(idx);
                    preferred_pushed_live = true;
                }
            }
        }
        for (i, ep) in endpoints.iter().enumerate() {
            if preferred_pushed_live && Some(i) == preferred {
                continue;
            }
            let h = health.get(&(ep.host.clone(), ep.port));
            if h.is_some_and(|h| h.is_demoted(now)) {
                demoted.push(i);
            } else {
                live.push(i);
            }
        }
        (live, demoted)
    }

    #[test]
    fn ordering_uri_order_when_no_state() {
        let r = EndpointRegistry::default();
        let eps = vec![ep("a", 1), ep("b", 2), ep("c", 3)];
        let (live, demoted) = order(&r, &eps);
        assert_eq!(live, vec![0, 1, 2]);
        assert!(demoted.is_empty());
    }

    #[test]
    fn ordering_preferred_floats_to_front() {
        let r = EndpointRegistry::default();
        let eps = vec![ep("a", 1), ep("b", 2), ep("c", 3)];
        r.record_success(2, &eps[2]);
        let (live, demoted) = order(&r, &eps);
        assert_eq!(live, vec![2, 0, 1]);
        assert!(demoted.is_empty());
    }

    #[test]
    fn ordering_demoted_endpoint_drops_to_back() {
        let r = EndpointRegistry::default();
        let eps = vec![ep("a", 1), ep("b", 2), ep("c", 3)];
        // Knock 'b' into demotion.
        r.record_failure(&eps[1]);
        r.record_failure(&eps[1]);
        assert!(r.record_failure(&eps[1]));
        let (live, demoted) = order(&r, &eps);
        assert_eq!(live, vec![0, 2]);
        assert_eq!(demoted, vec![1]);
    }

    #[test]
    fn ordering_preferred_but_demoted_falls_back() {
        let r = EndpointRegistry::default();
        let eps = vec![ep("a", 1), ep("b", 2)];
        r.record_success(0, &eps[0]);
        // Now 'a' fails 3 times → demoted.
        r.record_failure(&eps[0]);
        r.record_failure(&eps[0]);
        assert!(r.record_failure(&eps[0]));
        let (live, demoted) = order(&r, &eps);
        // Preferred is demoted, so 'b' is the only live candidate.
        assert_eq!(live, vec![1]);
        assert_eq!(demoted, vec![0]);
    }
}
