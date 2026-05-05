//! `ark-probe` — active-probe simulator + indistinguishability test
//! harness for ArkTunnel servers (Phase 12 WP7).
//!
//! The censorship threat model: an adversary with the suspected
//! ArkTunnel IP and port runs canonical probe attacks (random bytes,
//! handshake replay, valid handshake + wrong UUID, partial handshake +
//! idle, plain idle). To pass the indistinguishability bar, the
//! server's externally observable response must look the same as a
//! real Bitcoin / Ethereum node responding to the same probe:
//!
//!   * **No application-level bytes** are ever returned in response
//!     to a probe — the server must never emit an error byte or
//!     status code, because that's a fingerprint.
//!   * The TCP connection must stay open for a uniformly-random delay
//!     in the same envelope a stalled real-peer connection would
//!     occupy (we expect `[10s, 60s]` per WP6's tarpit constants),
//!     then close cleanly with FIN.
//!   * Once an IP exceeds the per-IP failure threshold, every fresh
//!     connection from it must be silently held + dropped — same
//!     externally observable envelope.
//!
//! This crate is split into:
//!
//!   * `scenarios` — the canonical probe attacks as small async
//!     functions that drive a `TcpStream`.
//!   * `measure`   — `ProbeOutcome { bytes_received, time_to_close }`
//!     plus the helper that runs a scenario against a target and
//!     records the outcome.
//!   * `assert`    — high-level assertions used by integration tests
//!     (`assert_silent_close_in_envelope`,
//!     `assert_distribution_matches_envelope`).
//!
//! Live tests against a running `ark-server` are gated behind the
//! `ARK_PROBE_TARGET` environment variable so that ordinary
//! `cargo test` in CI does not require a running daemon.

pub mod assert;
pub mod measure;
pub mod scenarios;

pub use assert::{
    assert_distribution_matches_envelope, assert_silent_close_in_envelope, EnvelopeBounds,
};
pub use measure::{run_scenario, ProbeOutcome};
pub use scenarios::Scenario;
