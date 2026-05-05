//! Live integration test: requires `ARK_PROBE_TARGET=host:port`
//! pointing at a running `ark-server`. Skipped otherwise so that
//! `cargo test` in CI does not require a daemon.
//!
//! Each scenario takes up to ~75s (the WP6 max-close + slack). The
//! test runs them sequentially to avoid tripping the per-IP tarpit
//! mid-run; for the parallel stress mode use the `ark-probe` CLI
//! with `--parallel`.

use ark_probe::{
    assert_distribution_matches_envelope, run_scenario, EnvelopeBounds, Scenario,
};
use std::net::SocketAddr;
use std::time::Duration;

fn target_from_env() -> Option<SocketAddr> {
    let raw = std::env::var("ARK_PROBE_TARGET").ok()?;
    raw.parse().ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "live: set ARK_PROBE_TARGET=host:port and run with --ignored"]
async fn live_envelope_against_running_server() {
    let Some(target) = target_from_env() else {
        eprintln!("ARK_PROBE_TARGET unset — skipping live test");
        return;
    };

    let cap = Duration::from_secs(75);
    let bounds = EnvelopeBounds::wp6_tarpit();

    let mut outcomes = Vec::new();
    for s in Scenario::all().iter().copied() {
        let o = run_scenario(target, s, cap)
            .await
            .unwrap_or_else(|e| panic!("run_scenario({:?}) failed: {e}", s.label()));
        eprintln!(
            "scenario={:<24} bytes={} time_to_close={:?} closed={}",
            s.label(),
            o.bytes_received,
            o.time_to_close,
            o.closed_within_cap
        );
        outcomes.push(o);
    }

    assert_distribution_matches_envelope(&outcomes, bounds);
}
