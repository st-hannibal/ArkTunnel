//! Indistinguishability assertions used by integration tests.
//!
//! These intentionally check the *envelope* of behaviour
//! (`bytes_received == 0`, `time_to_close ∈ [lo, hi]`) rather than
//! pinning a specific timing distribution against a captured
//! `bitcoind` recording.
//!
//! The plan calls for a recorded reference distribution; that
//! reference can be added later without changing the assertion API
//! — `EnvelopeBounds` doubles as the "approved envelope" derived
//! from such a recording.

use crate::measure::ProbeOutcome;
use std::time::Duration;

/// The acceptable envelope for a probe's externally observable
/// outcome. Defaults match the WP6 server tarpit configuration
/// (`[10s, 60s]` random close window, with a small slack to absorb
/// scheduling jitter).
#[derive(Debug, Clone, Copy)]
pub struct EnvelopeBounds {
    pub min_close: Duration,
    pub max_close: Duration,
}

impl EnvelopeBounds {
    /// The bounds that mirror the WP6 server tarpit constants
    /// (`TARPIT_DELAY_MIN = 10s`, `TARPIT_DELAY_MAX = 60s`) with a
    /// small slack on each side for scheduler jitter.
    pub fn wp6_tarpit() -> Self {
        Self {
            min_close: Duration::from_secs(8),
            max_close: Duration::from_secs(65),
        }
    }
}

impl Default for EnvelopeBounds {
    fn default() -> Self { Self::wp6_tarpit() }
}

/// Assert: the server emitted **zero** application bytes and closed
/// within the envelope. Panics with a clear message on failure so it
/// can be used directly inside `#[test]` functions.
pub fn assert_silent_close_in_envelope(outcome: &ProbeOutcome, bounds: EnvelopeBounds) {
    assert_eq!(
        outcome.bytes_received, 0,
        "scenario `{}`: server returned {} byte(s) — that is a fingerprint",
        outcome.scenario, outcome.bytes_received
    );
    assert!(
        outcome.closed_within_cap,
        "scenario `{}`: server did not close within the observation cap",
        outcome.scenario
    );
    assert!(
        outcome.time_to_close >= bounds.min_close,
        "scenario `{}`: closed too quickly ({:?} < {:?}) — distinguishable from a stalled real peer",
        outcome.scenario, outcome.time_to_close, bounds.min_close
    );
    assert!(
        outcome.time_to_close <= bounds.max_close,
        "scenario `{}`: closed too slowly ({:?} > {:?})",
        outcome.scenario, outcome.time_to_close, bounds.max_close
    );
}

/// Assert: a batch of outcomes all sit inside the envelope (silent
/// close + timing in `[min, max]`). Returns the close-time samples
/// for any further analysis the caller wants to do.
pub fn assert_distribution_matches_envelope(
    outcomes: &[ProbeOutcome],
    bounds: EnvelopeBounds,
) -> Vec<Duration> {
    assert!(!outcomes.is_empty(), "no outcomes to assert against");
    let mut samples = Vec::with_capacity(outcomes.len());
    for o in outcomes {
        assert_silent_close_in_envelope(o, bounds);
        samples.push(o.time_to_close);
    }
    samples
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_outcome(secs: u64) -> ProbeOutcome {
        ProbeOutcome {
            scenario: "idle".into(),
            bytes_received: 0,
            time_to_close: Duration::from_secs(secs),
            closed_within_cap: true,
        }
    }

    #[test]
    fn silent_close_in_envelope_passes() {
        assert_silent_close_in_envelope(&ok_outcome(20), EnvelopeBounds::wp6_tarpit());
    }

    #[test]
    #[should_panic(expected = "fingerprint")]
    fn nonzero_bytes_fails() {
        let mut o = ok_outcome(20);
        o.bytes_received = 1;
        assert_silent_close_in_envelope(&o, EnvelopeBounds::wp6_tarpit());
    }

    #[test]
    #[should_panic(expected = "too quickly")]
    fn early_close_fails() {
        assert_silent_close_in_envelope(&ok_outcome(2), EnvelopeBounds::wp6_tarpit());
    }

    #[test]
    #[should_panic(expected = "too slowly")]
    fn late_close_fails() {
        assert_silent_close_in_envelope(&ok_outcome(120), EnvelopeBounds::wp6_tarpit());
    }

    #[test]
    fn distribution_returns_samples() {
        let v = vec![ok_outcome(15), ok_outcome(30), ok_outcome(45)];
        let s = assert_distribution_matches_envelope(&v, EnvelopeBounds::wp6_tarpit());
        assert_eq!(s.len(), 3);
    }
}
