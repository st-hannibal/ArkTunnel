// Connection pool for pre-established transport channels.
//
// Maintaining a small pool of pre-handshaked BIP 324 / RLPx connections
// amortizes the transport handshake cost (2–4 RTTs) across SOCKS5/HTTP
// requests.  Each pooled entry is a channel that has completed the transport
// handshake but has NOT yet sent ARK1 or the VLESS request — those are sent
// when the connection is acquired from the pool.
//
// Pool behaviour:
//   - Capacity: POOL_SIZE idle connections maximum.
//   - Background filler: a task continuously refills the pool to capacity.
//   - Stale detection: entries older than ENTRY_TTL_SECS are discarded
//     (idle transport connections may be silently dropped by the server).
//   - On acquire: pop an idle entry (if any), otherwise open a fresh one.
//     After acquiring, spawn a background refill so the pool stays warm.

use crate::proxy::{open_transport_only, activate_proxied_stream, Target};
use crate::uri::ArkUri;
use anyhow::Result;
use ark_core::transport::BoxedAsyncReadWrite;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, warn};

/// Maximum number of idle pre-established connections to keep in the pool.
const POOL_SIZE: usize = 3;

/// Discard pool entries older than this many seconds (idle transports can die).
const ENTRY_TTL_SECS: u64 = 45;

struct PoolEntry {
    stream: BoxedAsyncReadWrite,
    created: Instant,
}

pub struct Pool {
    uri: Arc<ArkUri>,
    idle: Mutex<VecDeque<PoolEntry>>,
}

impl Pool {
    /// Create a pool and start a background task that keeps it warm.
    pub fn new(uri: Arc<ArkUri>) -> Arc<Self> {
        let pool = Arc::new(Self {
            uri,
            idle: Mutex::new(VecDeque::new()),
        });
        // Background filler: runs for the lifetime of the process.
        let pool2 = pool.clone();
        tokio::spawn(async move { pool2.background_fill().await });
        pool
    }

    /// Acquire a ready connection for `target`.
    ///
    /// Tries the pool first (discarding stale entries).  If the pool is empty,
    /// opens a fresh transport.  After acquiring, triggers an async refill so
    /// the pool stays warm.
    pub async fn acquire(self: Arc<Self>, target: &Target) -> Result<BoxedAsyncReadWrite> {
        let transport = self.pop_fresh().await;

        let stream = match transport {
            Some(s) => {
                debug!("Pool: reusing pre-established transport connection");
                s
            }
            None => {
                debug!("Pool: opening fresh transport connection");
                open_transport_only(&self.uri).await?
            }
        };

        // Trigger background refill without waiting.
        let pool2 = self.clone();
        tokio::spawn(async move { pool2.maybe_refill().await });

        activate_proxied_stream(stream, &self.uri, target).await
    }

    /// Pop the freshest non-stale entry from the idle queue.
    async fn pop_fresh(&self) -> Option<BoxedAsyncReadWrite> {
        let ttl = Duration::from_secs(ENTRY_TTL_SECS);
        let mut idle = self.idle.lock().await;
        loop {
            let entry = idle.pop_front()?;
            if entry.created.elapsed() < ttl {
                return Some(entry.stream);
            }
            // Entry is stale — drop it and try the next.
            debug!("Pool: discarding stale idle entry");
        }
    }

    /// Add one pre-established connection if the pool is below capacity.
    async fn maybe_refill(&self) {
        let current = self.idle.lock().await.len();
        if current >= POOL_SIZE {
            return;
        }
        match open_transport_only(&self.uri).await {
            Ok(stream) => {
                self.idle.lock().await.push_back(PoolEntry {
                    stream,
                    created: Instant::now(),
                });
                debug!("Pool: added idle connection (size now {})", self.idle.lock().await.len());
            }
            Err(e) => warn!("Pool: failed to pre-establish connection: {e:#}"),
        }
    }

    /// Background task: continuously keep the pool at POOL_SIZE capacity.
    async fn background_fill(&self) {
        loop {
            self.maybe_refill().await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}
