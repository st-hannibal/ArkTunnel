//! `ark-probe` CLI — run all canonical probe scenarios against a
//! target server and emit a JSON summary.
//!
//! Useful for ad-hoc checks against a deployed `ark-server`:
//!
//! ```text
//! cargo run -p ark-probe -- --target 18.196.101.239:8333 --cap-secs 75
//! ```

use anyhow::Result;
use ark_probe::{run_scenario, EnvelopeBounds, Scenario};
use clap::Parser;
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(version, about = "Active-probe simulator for ArkTunnel servers")]
struct Args {
    /// `host:port` of the ark-server (or any TCP target) to probe.
    #[arg(long)]
    target: SocketAddr,

    /// Per-scenario observation cap, seconds. Should comfortably
    /// exceed `EnvelopeBounds::wp6_tarpit().max_close`.
    #[arg(long, default_value_t = 75)]
    cap_secs: u64,

    /// Run scenarios sequentially (default) or all-in-parallel
    /// (stresses the server's per-IP tarpit).
    #[arg(long)]
    parallel: bool,

    /// Skip the envelope assertion at the end (only print results).
    #[arg(long)]
    no_assert: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let cap = Duration::from_secs(args.cap_secs);

    let outcomes = if args.parallel {
        let handles: Vec<_> = Scenario::all()
            .iter()
            .copied()
            .map(|s| tokio::spawn(async move { run_scenario(args.target, s, cap).await }))
            .collect();
        let mut out = Vec::new();
        for h in handles {
            out.push(h.await??);
        }
        out
    } else {
        let mut out = Vec::new();
        for s in Scenario::all().iter().copied() {
            out.push(run_scenario(args.target, s, cap).await?);
        }
        out
    };

    println!("{}", serde_json::to_string_pretty(&outcomes)?);

    if !args.no_assert {
        ark_probe::assert_distribution_matches_envelope(&outcomes, EnvelopeBounds::wp6_tarpit());
        eprintln!("OK — all scenarios passed envelope assertion");
    }

    Ok(())
}
