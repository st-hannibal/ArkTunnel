//! Lightweight, localhost-only metrics endpoint. (Phase 13 WP3.)
//!
//! Exposes a single `GET /metrics` route on a configurable address
//! (default `127.0.0.1:9899`). The response is a Prometheus-style
//! plaintext document — but we intentionally do *not* depend on the
//! `prometheus` crate, to keep the binary small and the surface area
//! tiny. Operators can scrape it with `curl` over SSH, or point any
//! Prometheus-compatible agent at it.
//!
//! All counters are process-lifetime atomics; no histograms, no
//! per-label cardinality. The `bitcoind_*` lines are best-effort:
//! they shell out to `bitcoin-cli` if it is on `$PATH` and silently
//! omit otherwise.
//!
//! Security: the listener binds 127.0.0.1 by default. If an operator
//! sets `metrics_addr` to a non-loopback address, that is on them —
//! we log a warning but do not refuse.

use anyhow::{Context, Result};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

#[derive(Debug)]
pub struct Metrics {
    pub started: Instant,
    pub sessions_total: AtomicU64,
    pub sessions_active: AtomicU64,
    pub splice_total: AtomicU64,
    pub splice_fail_total: AtomicU64,
    pub probe_like_total: AtomicU64,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            started: Instant::now(),
            sessions_total: AtomicU64::new(0),
            sessions_active: AtomicU64::new(0),
            splice_total: AtomicU64::new(0),
            splice_fail_total: AtomicU64::new(0),
            probe_like_total: AtomicU64::new(0),
        })
    }

    pub fn inc_session_start(&self) {
        self.sessions_total.fetch_add(1, Ordering::Relaxed);
        self.sessions_active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_session_end(&self) {
        // Saturating subtract — never wrap below zero.
        let mut cur = self.sessions_active.load(Ordering::Relaxed);
        loop {
            if cur == 0 { break; }
            match self.sessions_active.compare_exchange_weak(
                cur, cur - 1, Ordering::Relaxed, Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(c) => cur = c,
            }
        }
    }

    pub fn inc_splice(&self) { self.splice_total.fetch_add(1, Ordering::Relaxed); }
    pub fn inc_splice_fail(&self) { self.splice_fail_total.fetch_add(1, Ordering::Relaxed); }
    pub fn inc_probe_like(&self) { self.probe_like_total.fetch_add(1, Ordering::Relaxed); }

    pub fn render(&self) -> String {
        let uptime = self.started.elapsed().as_secs();
        let mut out = String::new();
        out.push_str("# ArkTunnel server metrics (text/plain; version=0.0.4)\n");
        out.push_str(&format!("ark_uptime_seconds {uptime}\n"));
        out.push_str(&format!(
            "ark_sessions_total {}\n",
            self.sessions_total.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "ark_sessions_active {}\n",
            self.sessions_active.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "ark_splice_real_peer_total {}\n",
            self.splice_total.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "ark_splice_real_peer_fail_total {}\n",
            self.splice_fail_total.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "ark_probe_like_total {}\n",
            self.probe_like_total.load(Ordering::Relaxed)
        ));
        out
    }
}

/// Best-effort bitcoind status via `bitcoin-cli`. Returns an empty
/// string if `bitcoin-cli` is missing or any call fails.
async fn render_bitcoind(conf_path: &str) -> String {
    use tokio::process::Command;
    let mut out = String::new();

    let peer = Command::new("bitcoin-cli")
        .args([&format!("-conf={conf_path}"), "getconnectioncount"])
        .output().await;
    if let Ok(o) = peer {
        if o.status.success() {
            if let Ok(s) = std::str::from_utf8(&o.stdout) {
                if let Ok(n) = s.trim().parse::<u64>() {
                    out.push_str(&format!("bitcoind_peer_count {n}\n"));
                }
            }
        }
    }

    let blocks = Command::new("bitcoin-cli")
        .args([&format!("-conf={conf_path}"), "getblockcount"])
        .output().await;
    if let Ok(o) = blocks {
        if o.status.success() {
            if let Ok(s) = std::str::from_utf8(&o.stdout) {
                if let Ok(n) = s.trim().parse::<u64>() {
                    out.push_str(&format!("bitcoind_block_count {n}\n"));
                }
            }
        }
    }

    out
}

/// Spawn the metrics HTTP listener. Returns immediately. Logs and
/// exits the spawned task on bind failure (does not crash the server).
pub fn spawn(addr: SocketAddr, bitcoin_conf: Option<String>, m: Arc<Metrics>) {
    if !is_loopback(addr.ip()) {
        warn!(
            "metrics endpoint binding non-loopback address {addr} \
             — anyone who can reach this socket can read counters"
        );
    }
    tokio::spawn(async move {
        match TcpListener::bind(addr).await {
            Ok(listener) => {
                info!("metrics endpoint listening on http://{addr}/metrics");
                loop {
                    match listener.accept().await {
                        Ok((sock, _)) => {
                            let m = m.clone();
                            let conf = bitcoin_conf.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle(sock, m, conf).await {
                                    debug!("metrics conn error: {e}");
                                }
                            });
                        }
                        Err(e) => debug!("metrics accept error: {e}"),
                    }
                }
            }
            Err(e) => warn!("metrics listener bind {addr} failed: {e}"),
        }
    });
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

async fn handle(
    mut sock: tokio::net::TcpStream,
    m: Arc<Metrics>,
    bitcoin_conf: Option<String>,
) -> Result<()> {
    // Read until end-of-headers or 4 KiB, whichever comes first. This
    // is not a full HTTP parser — it doesn't need to be.
    let mut buf = [0u8; 4096];
    let mut filled = 0;
    loop {
        if filled == buf.len() { break; }
        let n = sock.read(&mut buf[filled..])
            .await.context("metrics read")?;
        if n == 0 { break; }
        filled += n;
        if buf[..filled].windows(4).any(|w| w == b"\r\n\r\n") { break; }
    }
    let req = std::str::from_utf8(&buf[..filled]).unwrap_or("");
    let first_line = req.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    let (status, body) = if method != "GET" {
        ("405 Method Not Allowed", String::from("method not allowed\n"))
    } else if path != "/metrics" {
        ("404 Not Found", String::from("not found\n"))
    } else {
        let mut body = m.render();
        if let Some(conf) = bitcoin_conf.as_deref() {
            body.push_str(&render_bitcoind(conf).await);
        }
        ("200 OK", body)
    };

    let resp = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: text/plain; version=0.0.4\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len(),
    );
    sock.write_all(resp.as_bytes()).await.context("metrics write")?;
    let _ = sock.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_includes_all_counters() {
        let m = Metrics::new();
        m.inc_session_start();
        m.inc_session_start();
        m.inc_session_end();
        m.inc_splice();
        m.inc_splice_fail();
        m.inc_probe_like();
        let out = m.render();
        assert!(out.contains("ark_sessions_total 2"));
        assert!(out.contains("ark_sessions_active 1"));
        assert!(out.contains("ark_splice_real_peer_total 1"));
        assert!(out.contains("ark_splice_real_peer_fail_total 1"));
        assert!(out.contains("ark_probe_like_total 1"));
        assert!(out.contains("ark_uptime_seconds"));
    }

    #[test]
    fn session_active_saturates_at_zero() {
        let m = Metrics::new();
        m.inc_session_end(); // would underflow
        m.inc_session_end();
        assert_eq!(m.sessions_active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn http_get_metrics_returns_200_and_body() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let m = Metrics::new();
        m.inc_session_start();
        let m_clone = m.clone();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            handle(sock, m_clone, None).await.unwrap();
        });

        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).await.unwrap();
        let txt = String::from_utf8_lossy(&resp);
        assert!(txt.starts_with("HTTP/1.1 200 OK"));
        assert!(txt.contains("ark_sessions_total 1"));
    }

    #[tokio::test]
    async fn http_unknown_path_returns_404() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let m = Metrics::new();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            handle(sock, m, None).await.unwrap();
        });
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /nope HTTP/1.1\r\n\r\n").await.unwrap();
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 404"));
    }
}
