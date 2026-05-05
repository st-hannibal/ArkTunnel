//! Active-probe resistance (Phase 12 WP6).
//!
//! Censorship probers (Iran/China-style) connect to suspected proxy IPs and
//! replay or fuzz handshakes. To stay indistinguishable from a real
//! Bitcoin / Ethereum node, every malformed-input failure path on the
//! server must:
//!
//! 1. **Never** send an error byte back — that's a fingerprint.
//! 2. Hold the TCP connection open for a uniformly random delay in
//!    `[10s, 60s]`, then close. (Mimics "client opened TCP, sent nothing,
//!    server eventually timed out.")
//! 3. Track failures per source IP. If an IP exceeds `MAX_FAILS_PER_WINDOW`
//!    failed handshakes within `WINDOW`, tarpit it for `TARPIT_DURATION`:
//!    new connections from that IP are accepted, held idle for the random
//!    delay, and dropped without even attempting a handshake.
//!
//! All of these knobs are intentionally constants (no config) — they're
//! security parameters, not user preferences.

use rand::Rng;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tracing::{debug, warn};

/// Lower bound of the "looks like a stalled real-peer connection" delay.
pub const TARPIT_DELAY_MIN: Duration = Duration::from_secs(10);

/// Upper bound of the random delay before dropping a probe-like connection.
pub const TARPIT_DELAY_MAX: Duration = Duration::from_secs(60);

/// Sliding window over which we count failed handshakes per source IP.
pub const FAIL_WINDOW: Duration = Duration::from_secs(60);

/// Failures within `FAIL_WINDOW` that trip the per-IP tarpit.
pub const MAX_FAILS_PER_WINDOW: u32 = 10;

/// How long a tripped IP stays in tarpit mode.
pub const TARPIT_DURATION: Duration = Duration::from_secs(5 * 60);

/// Per-IP failure record.
#[derive(Debug, Clone)]
struct IpRecord {
    /// Timestamps of recent failures (oldest first).
    fails: Vec<Instant>,
    /// If `Some`, the IP is currently tarpitted until this instant.
    tarpit_until: Option<Instant>,
}

impl IpRecord {
    fn new() -> Self {
        Self { fails: Vec::new(), tarpit_until: None }
    }
}

/// In-memory per-IP probe-failure tracker.
///
/// Lookups and updates are O(k) in the number of failures within the
/// current window — small (at most `MAX_FAILS_PER_WINDOW + 1`).
#[derive(Debug, Default)]
pub struct ProbeTracker {
    inner: Mutex<HashMap<IpAddr, IpRecord>>,
}

impl ProbeTracker {
    pub fn new() -> Self { Self::default() }

    /// Returns `true` if `ip` is currently in tarpit mode.
    pub fn is_tarpitted(&self, ip: IpAddr) -> bool {
        self.is_tarpitted_at(ip, Instant::now())
    }

    fn is_tarpitted_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut g = self.inner.lock().unwrap();
        match g.get_mut(&ip) {
            Some(rec) => match rec.tarpit_until {
                Some(until) if until > now => true,
                Some(_) => {
                    // tarpit expired — clear it but keep failure history pruned.
                    rec.tarpit_until = None;
                    rec.fails.retain(|t| now.duration_since(*t) < FAIL_WINDOW);
                    false
                }
                None => false,
            },
            None => false,
        }
    }

    /// Record a probe-like failure from `ip`. Returns `true` if this
    /// failure tripped the tarpit (caller may want to log it once).
    pub fn record_failure(&self, ip: IpAddr) -> bool {
        self.record_failure_at(ip, Instant::now())
    }

    fn record_failure_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut g = self.inner.lock().unwrap();
        let rec = g.entry(ip).or_insert_with(IpRecord::new);

        // If still tarpitted, no need to keep counting — already quarantined.
        if matches!(rec.tarpit_until, Some(until) if until > now) {
            return false;
        }

        rec.fails.retain(|t| now.duration_since(*t) < FAIL_WINDOW);
        rec.fails.push(now);

        if rec.fails.len() as u32 >= MAX_FAILS_PER_WINDOW {
            rec.tarpit_until = Some(now + TARPIT_DURATION);
            rec.fails.clear();
            return true;
        }
        false
    }

    /// Drop expired records; safe to call periodically. Returns number of
    /// IPs evicted. (Optional — the map is bounded in practice by attacker
    /// behavior, but worth pruning for long-running daemons.)
    pub fn gc(&self) -> usize {
        let now = Instant::now();
        let mut g = self.inner.lock().unwrap();
        let before = g.len();
        g.retain(|_, rec| {
            if let Some(until) = rec.tarpit_until {
                if until > now { return true; }
                rec.tarpit_until = None;
            }
            rec.fails.retain(|t| now.duration_since(*t) < FAIL_WINDOW);
            !rec.fails.is_empty()
        });
        before - g.len()
    }
}

/// Sample a uniformly-random delay in `[TARPIT_DELAY_MIN, TARPIT_DELAY_MAX]`.
pub fn random_tarpit_delay() -> Duration {
    let mut rng = rand::thread_rng();
    let lo = TARPIT_DELAY_MIN.as_millis() as u64;
    let hi = TARPIT_DELAY_MAX.as_millis() as u64;
    Duration::from_millis(rng.gen_range(lo..=hi))
}

/// Hold `stream` open for a uniformly-random delay in `[10s, 60s]` then
/// drop it. Reads are discarded; no bytes are ever written. Looks like a
/// stalled connection from the censor's side.
///
/// This **must not** send any data — sending an error byte (or anything at
/// all) would be a fingerprint.
pub async fn tarpit_close(stream: TcpStream) {
    let delay = random_tarpit_delay();
    debug!(?delay, "tarpit-close engaged");
    let _ = stream.set_nodelay(true);

    // Drain anything the peer sends so they don't hit a TCP RST from us
    // refusing reads. We never write back.
    let drain = async {
        let mut buf = [0u8; 1024];
        loop {
            match stream.try_read(&mut buf) {
                Ok(0) => return,                            // peer closed
                Ok(_) => {}                                 // discard
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Wait for readable; ignore errors.
                    if stream.readable().await.is_err() { return; }
                }
                Err(_) => return,
            }
        }
    };

    tokio::select! {
        _ = tokio::time::sleep(delay) => {}
        _ = drain => {}
    }
    // Stream drops here — graceful FIN.
}

/// Convenience: log + tarpit when an IP just tripped the threshold.
pub fn warn_tripped(ip: IpAddr) {
    warn!(
        %ip,
        threshold = MAX_FAILS_PER_WINDOW,
        window_secs = FAIL_WINDOW.as_secs(),
        duration_secs = TARPIT_DURATION.as_secs(),
        "probe-defense tarpit engaged"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip() -> IpAddr { IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)) }

    #[test]
    fn record_failure_below_threshold_does_not_tarpit() {
        let t = ProbeTracker::new();
        for _ in 0..(MAX_FAILS_PER_WINDOW - 1) {
            assert!(!t.record_failure(ip()));
        }
        assert!(!t.is_tarpitted(ip()));
    }

    #[test]
    fn record_failure_at_threshold_trips_tarpit() {
        let t = ProbeTracker::new();
        let mut tripped = false;
        for _ in 0..MAX_FAILS_PER_WINDOW {
            tripped |= t.record_failure(ip());
        }
        assert!(tripped, "tarpit must trip on the Nth failure");
        assert!(t.is_tarpitted(ip()));
    }

    #[test]
    fn old_failures_outside_window_are_pruned() {
        let t = ProbeTracker::new();
        let now = Instant::now();
        let old = now - FAIL_WINDOW - Duration::from_secs(1);
        for _ in 0..(MAX_FAILS_PER_WINDOW - 1) {
            t.record_failure_at(ip(), old);
        }
        // Old failures shouldn't carry forward; this single fresh one
        // must NOT trip the threshold.
        assert!(!t.record_failure_at(ip(), now));
        assert!(!t.is_tarpitted_at(ip(), now));
    }

    #[test]
    fn tarpit_expires_after_duration() {
        let t = ProbeTracker::new();
        let now = Instant::now();
        for _ in 0..MAX_FAILS_PER_WINDOW {
            t.record_failure_at(ip(), now);
        }
        assert!(t.is_tarpitted_at(ip(), now));
        let later = now + TARPIT_DURATION + Duration::from_secs(1);
        assert!(!t.is_tarpitted_at(ip(), later));
    }

    #[test]
    fn random_tarpit_delay_within_bounds() {
        for _ in 0..100 {
            let d = random_tarpit_delay();
            assert!(d >= TARPIT_DELAY_MIN && d <= TARPIT_DELAY_MAX);
        }
    }

    #[test]
    fn gc_removes_stale_records() {
        let t = ProbeTracker::new();
        let old = Instant::now() - FAIL_WINDOW - Duration::from_secs(10);
        t.record_failure_at(ip(), old);
        // Force one entry to exist
        assert_eq!(t.inner.lock().unwrap().len(), 1);
        let evicted = t.gc();
        assert_eq!(evicted, 1);
    }

    #[test]
    fn separate_ips_tracked_independently() {
        let t = ProbeTracker::new();
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        for _ in 0..MAX_FAILS_PER_WINDOW {
            t.record_failure(a);
        }
        assert!(t.is_tarpitted(a));
        assert!(!t.is_tarpitted(b));
    }
}
