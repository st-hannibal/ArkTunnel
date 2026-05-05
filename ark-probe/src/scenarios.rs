//! Canonical probe-attack scenarios.
//!
//! Each scenario is a small async function that takes a connected
//! `TcpStream` and exercises one of the censor playbook entries.
//! All scenarios deliberately stop short of returning an error: the
//! caller (`measure::run_scenario`) is responsible for then watching
//! how long the server takes to FIN and how many bytes (if any) it
//! sends back.

use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// One of the canonical probe attacks. The variants intentionally
/// model the moves a real censor (Iran/China-style active prober)
/// would make against a suspected proxy IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    /// Connect, send nothing, wait for the server to FIN.
    Idle,
    /// Send a small chunk of uniformly-random bytes (sub-handshake
    /// length), then go idle.
    RandomShort,
    /// Send a large chunk of uniformly-random bytes (well past any
    /// reasonable handshake length), then go idle.
    RandomLong,
    /// Send a tiny prefix (the first ~16 bytes of what *might* be a
    /// BIP 324 handshake) then go idle. Models a truncated handshake.
    TruncatedHandshake,
    /// Replay 64 bytes that look superficially like an ephemeral
    /// pubkey message, then idle. The server can't possibly produce
    /// a valid session key from this — we want to see what it does.
    HandshakeShapedJunk,
    /// Send a "valid handshake bytes count, but the bytes themselves
    /// are random" payload, sized to match a real BIP 324 v2 hello
    /// (~64 bytes ephemeral pubkey + a few padding bytes). Models
    /// handshake-replay with a fresh random ephemeral key.
    HandshakeReplay,
}

impl Scenario {
    /// Stable string label for logs / JSON.
    pub fn label(self) -> &'static str {
        match self {
            Scenario::Idle => "idle",
            Scenario::RandomShort => "random_short",
            Scenario::RandomLong => "random_long",
            Scenario::TruncatedHandshake => "truncated_handshake",
            Scenario::HandshakeShapedJunk => "handshake_shaped_junk",
            Scenario::HandshakeReplay => "handshake_replay",
        }
    }

    /// All canonical scenarios, in a stable order.
    pub fn all() -> &'static [Scenario] {
        &[
            Scenario::Idle,
            Scenario::RandomShort,
            Scenario::RandomLong,
            Scenario::TruncatedHandshake,
            Scenario::HandshakeShapedJunk,
            Scenario::HandshakeReplay,
        ]
    }

    /// Drive the scenario on `stream`. After this returns the caller
    /// must observe how the server closes the connection.
    pub async fn drive(self, stream: &mut TcpStream) -> std::io::Result<()> {
        match self {
            Scenario::Idle => Ok(()),
            Scenario::RandomShort => write_random(stream, 32).await,
            Scenario::RandomLong => write_random(stream, 16 * 1024).await,
            Scenario::TruncatedHandshake => write_random(stream, 16).await,
            Scenario::HandshakeShapedJunk => write_random(stream, 64).await,
            Scenario::HandshakeReplay => write_random(stream, 88).await,
        }
    }
}

async fn write_random(stream: &mut TcpStream, n: usize) -> std::io::Result<()> {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

/// Best-effort: drain whatever the server sends until EOF or the
/// supplied deadline elapses. Returns the bytes received.
///
/// This is the helper `measure::run_scenario` uses to detect
/// (a) any application-level response (which would be a fingerprint)
/// and (b) the moment the server closes its side of the connection.
pub async fn drain_until_close_or_deadline(
    stream: &mut TcpStream,
    deadline: tokio::time::Instant,
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return out;
        }
        let remaining = deadline - now;
        match tokio::time::timeout(remaining, stream.read(&mut buf)).await {
            Ok(Ok(0)) => return out,                       // peer closed (FIN)
            Ok(Ok(n)) => out.extend_from_slice(&buf[..n]), // unexpected bytes
            Ok(Err(_)) => return out,                      // RST / IO error
            Err(_) => return out,                          // deadline
        }
    }
}
