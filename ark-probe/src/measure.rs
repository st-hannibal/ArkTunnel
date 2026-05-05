//! Run a probe scenario against a target server and record the
//! externally observable outcome.

use crate::scenarios::{drain_until_close_or_deadline, Scenario};
use anyhow::{Context, Result};
use serde::Serialize;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::Instant;

/// What the censor would see for one probe attempt.
#[derive(Debug, Clone, Serialize)]
pub struct ProbeOutcome {
    pub scenario: String,
    /// Bytes the server sent before closing. Any non-zero count from
    /// a probe is a hard fingerprint failure.
    pub bytes_received: usize,
    /// Time from the moment we finished writing our probe payload
    /// until the server closed the connection (or the cap elapsed).
    pub time_to_close: Duration,
    /// `true` if the server closed cleanly within the observation
    /// cap; `false` if we hit the cap while it was still open.
    pub closed_within_cap: bool,
}

/// Run one scenario end-to-end:
///
///   1. Open TCP to `target`, set NODELAY.
///   2. `scenario.drive()` writes the probe payload (or nothing for
///      `Idle`).
///   3. Drain the server side until FIN or `cap` elapses.
///   4. Return the outcome.
pub async fn run_scenario(
    target: SocketAddr,
    scenario: Scenario,
    cap: Duration,
) -> Result<ProbeOutcome> {
    let mut stream = TcpStream::connect(target)
        .await
        .with_context(|| format!("connecting to {target}"))?;
    let _ = stream.set_nodelay(true);

    scenario
        .drive(&mut stream)
        .await
        .with_context(|| format!("driving scenario {}", scenario.label()))?;

    let started = Instant::now();
    let deadline = started + cap;
    let bytes = drain_until_close_or_deadline(&mut stream, deadline).await;
    let elapsed = started.elapsed();

    Ok(ProbeOutcome {
        scenario: scenario.label().to_string(),
        bytes_received: bytes.len(),
        time_to_close: elapsed,
        closed_within_cap: elapsed < cap,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    /// A toy "well-behaved tarpit" server: accept, hold the connection
    /// open for `delay`, then drop. Used to verify our measurement
    /// machinery without depending on a running ark-server.
    async fn spawn_silent_close(delay: Duration) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                tokio::time::sleep(delay).await;
                let _ = s.shutdown().await;
            }
        });
        addr
    }

    /// A toy "fingerprinting" server: accept, send a single byte
    /// immediately, then close. Anything we measure must report
    /// `bytes_received > 0`.
    async fn spawn_chatty() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let _ = s.write_all(b"X").await;
                let _ = s.shutdown().await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn run_scenario_records_silent_close() {
        let addr = spawn_silent_close(Duration::from_millis(120)).await;
        let out = run_scenario(addr, Scenario::Idle, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(out.bytes_received, 0);
        assert!(out.closed_within_cap);
        assert!(out.time_to_close >= Duration::from_millis(80));
    }

    #[tokio::test]
    async fn run_scenario_detects_chatty_server() {
        let addr = spawn_chatty().await;
        let out = run_scenario(addr, Scenario::Idle, Duration::from_secs(2))
            .await
            .unwrap();
        assert!(out.bytes_received >= 1, "chatty server must be detected");
    }

    #[tokio::test]
    async fn run_scenario_random_short_against_silent_close() {
        let addr = spawn_silent_close(Duration::from_millis(50)).await;
        let out = run_scenario(addr, Scenario::RandomShort, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(out.bytes_received, 0);
        assert_eq!(out.scenario, "random_short");
    }
}
