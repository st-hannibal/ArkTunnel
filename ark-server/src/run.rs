use crate::config::{ServerConfig, TransportKind};
use crate::probe_defense::{self, ProbeTracker};
use anyhow::{Context, Result};
use ark_core::{
    arkframe,
    bip324::Bip324Transport,
    rlpx::RlpxTransport,
    transport::{BoxedAsyncReadWrite, Multiplexed, Transport},
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{watch, Mutex};
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

/// Outcome classification used by the probe-defense layer to decide
/// whether to tarpit the source IP.
enum ConnectionOutcome {
    /// Handshake completed and a legitimate session ran (or the peer
    /// turned out to be a real Bitcoin/Ethereum node we relayed). No
    /// tarpit accounting.
    Legitimate,
    /// Pre-UUID failure consistent with an active probe (garbage
    /// handshake, replay, valid handshake + wrong UUID, ...). Caller
    /// records a failure and holds the connection open silently.
    ProbeLike,
}

/// `ark-server run` — accept and mux incoming connections.
pub async fn run_server() -> Result<()> {
    let cfg = ServerConfig::load()?;

    let listen_addr: SocketAddr = cfg
        .listen_addr
        .parse()
        .with_context(|| format!("invalid listen_addr: {}", cfg.listen_addr))?;

    let listener = TcpListener::bind(listen_addr).await?;
    info!("ark-server listening on {} ({})", listen_addr, cfg.transport);

    // Drop root privileges after binding the privileged port.
    #[cfg(unix)]
    drop_privileges()?;

    // Shared config pointer — updated atomically on SIGHUP.
    let (cfg_tx, cfg_rx) = watch::channel(Arc::new(cfg));

    // Per-IP probe-defense tracker. Lives for the process lifetime.
    let probes = Arc::new(ProbeTracker::new());

    // Periodic GC of stale tracker entries.
    {
        let probes = probes.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            tick.tick().await; // skip the immediate first tick
            loop {
                tick.tick().await;
                let evicted = probes.gc();
                if evicted > 0 {
                    debug!(evicted, "probe-defense gc");
                }
            }
        });
    }

    // Spawn a task that listens for SIGHUP and reloads config.
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sighup = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    warn!("SIGHUP handler setup failed: {e}");
                    return;
                }
            };
            loop {
                sighup.recv().await;
                info!("SIGHUP received — reloading configuration");
                match ServerConfig::load() {
                    Ok(new_cfg) => {
                        let _ = cfg_tx.send(Arc::new(new_cfg));
                        info!("Configuration reloaded");
                    }
                    Err(e) => error!("failed to reload config on SIGHUP: {e}"),
                }
            }
        }
    });

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let _ = stream.set_nodelay(true);
                let cfg = cfg_rx.borrow().clone();
                let probes = probes.clone();
                let peer_ip = peer_addr.ip();

                // If the source IP is currently tarpitted, do not even
                // attempt a handshake — accept the connection, hold it
                // open silently for a uniformly random delay, then drop.
                if probes.is_tarpitted(peer_ip) {
                    debug!(%peer_ip, "tarpitted IP — silent hold");
                    tokio::spawn(async move {
                        probe_defense::tarpit_close(stream).await;
                    });
                    continue;
                }

                tokio::spawn(async move {
                    // Duplicate the underlying socket FD: one handle is
                    // consumed by the handshake machinery, the other is
                    // retained so that on a probe-like failure we can
                    // hold the TCP connection open for the random delay
                    // (no FIN, no error byte — just stalled, like a real
                    // peer that's waiting for us to talk first).
                    let tarpit_handle = match dup_tcp_stream(&stream) {
                        Ok(h) => Some(h),
                        Err(e) => {
                            debug!(%peer_ip, "fd dup failed: {e}");
                            None
                        }
                    };

                    let outcome = handle_connection(stream, cfg).await;

                    let probe_like = match &outcome {
                        Ok(ConnectionOutcome::Legitimate) => false,
                        Ok(ConnectionOutcome::ProbeLike) => true,
                        Err(e) => {
                            debug!(%peer_ip, "handle_connection error: {e}");
                            true
                        }
                    };

                    if probe_like {
                        if probes.record_failure(peer_ip) {
                            probe_defense::warn_tripped(peer_ip);
                        }
                        if let Some(h) = tarpit_handle {
                            probe_defense::tarpit_close(h).await;
                        }
                    }
                });
            }
            Err(e) => error!("accept error: {e}"),
        }
    }
}

/// Duplicate the underlying socket FD of a tokio `TcpStream` so we can
/// hold the TCP connection open from the server side after the handshake
/// machinery has consumed (or dropped) the original handle.
///
/// Both handles refer to the same kernel socket; the connection is only
/// closed when *every* duplicate has been dropped.
fn dup_tcp_stream(stream: &TcpStream) -> std::io::Result<TcpStream> {
    use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
    let fd = stream.as_fd();
    // SAFETY: dup(2) returns a fresh FD owned by us; we wrap it in an
    // OwnedFd immediately so it's closed on drop.
    let dup_fd = unsafe { libc::dup(fd.as_raw_fd()) };
    if dup_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(dup_fd) };
    let std_stream = std::net::TcpStream::from(owned);
    std_stream.set_nonblocking(true)?;
    TcpStream::from_std(std_stream)
}


/// Splice an already-accepted real Bitcoin peer to a local bitcoind:
/// connect to `upstream`, replay any bytes already peeked off the
/// peer's stream during BIP324 handshake detection, then pump
/// bidirectionally until either side closes. (Phase 13 WP1.)
pub(crate) async fn splice_real_peer(
    mut peer: BoxedAsyncReadWrite,
    peeked: Vec<u8>,
    upstream: SocketAddr,
) -> Result<()> {
    let mut node = TcpStream::connect(upstream)
        .await
        .with_context(|| format!("connecting to bitcoind at {upstream}"))?;
    if !peeked.is_empty() {
        node.write_all(&peeked).await?;
    }
    let _ = tokio::io::copy_bidirectional(&mut peer, &mut node).await;
    Ok(())
}

async fn handle_connection(stream: TcpStream, cfg: Arc<ServerConfig>) -> Result<ConnectionOutcome> {
    let crypto_node_addr: Option<SocketAddr> = cfg
        .crypto_node_addr()
        .and_then(|s| s.parse().ok());

    match cfg.transport {
        TransportKind::Bip324 => {
            // Handshake failure here is a probe-like signal — the peer
            // could not complete a valid BIP 324 handshake at all.
            let muxed = match Bip324Transport::accept(stream).await {
                Ok(m) => m,
                Err(e) => {
                    debug!("bip324 handshake failed: {e}");
                    return Ok(ConnectionOutcome::ProbeLike);
                }
            };
            match muxed {
                Multiplexed::ArkClient { mut stream, uuid, extra } => {
                    if validate_uuid(&cfg, &uuid).is_err() {
                        // Valid handshake, but unrecognized UUID — classic
                        // active-probe replay. Tarpit, no error byte.
                        debug!(%uuid, "unrecognized UUID — probe-like");
                        return Ok(ConnectionOutcome::ProbeLike);
                    }
                    // Past this point, the peer proved knowledge of a
                    // valid UUID — any later error is operational, not
                    // a probe signal.
                    let neg = arkframe::server_negotiate_v2(&mut stream, &extra).await;
                    match neg {
                        Ok(caps) => {
                            if caps != 0 {
                                info!(uuid = %uuid, caps = format!("0x{caps:02x}"), "ARK-frame v2 negotiated");
                            }
                            let _ = serve_arkframe(&mut stream).await;
                        }
                        Err(e) => debug!(%uuid, "v2 negotiation failed: {e}"),
                    }
                    Ok(ConnectionOutcome::Legitimate)
                }
                Multiplexed::RealPeer { stream, peeked } => {
                    // Real Bitcoin peer — relay to local bitcoind if the
                    // splice is configured, otherwise drop silently. Either
                    // way this is never a probe signal.
                    match crypto_node_addr {
                        Some(addr) => {
                            if let Err(e) = splice_real_peer(stream, peeked, addr).await {
                                debug!("RealPeer splice failed: {e}");
                            }
                        }
                        None => {
                            debug!(
                                "RealPeer detected but bitcoind splice is disabled \
                                 (set ARK_BITCOIND_ADDR or bitcoind_addr); dropping"
                            );
                        }
                    }
                    Ok(ConnectionOutcome::Legitimate)
                }
            }
        }
        TransportKind::Rlpx => {
            let muxed = match RlpxTransport::accept(stream).await {
                Ok(m) => m,
                Err(e) => {
                    debug!("rlpx handshake failed: {e}");
                    return Ok(ConnectionOutcome::ProbeLike);
                }
            };
            match muxed {
                Multiplexed::ArkClient { mut stream, uuid, extra } => {
                    if validate_uuid(&cfg, &uuid).is_err() {
                        debug!(%uuid, "unrecognized UUID — probe-like");
                        return Ok(ConnectionOutcome::ProbeLike);
                    }
                    let neg = arkframe::server_negotiate_v2(&mut stream, &extra).await;
                    match neg {
                        Ok(caps) => {
                            if caps != 0 {
                                info!(uuid = %uuid, caps = format!("0x{caps:02x}"), "ARK-frame v2 negotiated");
                            }
                            let _ = serve_arkframe(&mut stream).await;
                        }
                        Err(e) => debug!(%uuid, "v2 negotiation failed: {e}"),
                    }
                    Ok(ConnectionOutcome::Legitimate)
                }
                Multiplexed::RealPeer { stream, .. } => {
                    let upstream = match crypto_node_addr {
                        Some(a) => a,
                        None => {
                            debug!("RLPx RealPeer dropped — no upstream configured");
                            return Ok(ConnectionOutcome::Legitimate);
                        }
                    };
                    match ark_core::rlpx::read_local_geth_pubkey() {
                        Some(geth_pub) => {
                            let _ = ark_core::rlpx::relay_to_local_geth(stream, &geth_pub, upstream)
                                .await;
                        }
                        None => {
                            warn!(
                                "RLPx real Ethereum peer detected — \
                                 geth node key not found at /var/lib/reth/discovery-secret \
                                 or /var/lib/geth/geth/nodekey; dropping connection"
                            );
                        }
                    }
                    Ok(ConnectionOutcome::Legitimate)
                }
            }
        }
    }
}

/// Read the client's ARK-frame request, dial the requested target, send a
/// status byte, and pump bytes bidirectionally until either side closes.
async fn serve_arkframe(stream: &mut BoxedAsyncReadWrite) -> Result<()> {
    let (cmd, target) = arkframe::read_request_full(stream)
        .await
        .context("reading ARK-frame request")?;

    match cmd {
        arkframe::CMD_TCP_CONNECT => serve_tcp_connect(stream, target).await,
        arkframe::CMD_UDP_ASSOCIATE => serve_udp_associate(stream).await,
        other => {
            let _ = arkframe::write_status(stream, arkframe::STATUS_GENERIC).await;
            anyhow::bail!("ARK-frame: unknown cmd 0x{other:02x}")
        }
    }
}

async fn serve_tcp_connect(stream: &mut BoxedAsyncReadWrite, target: arkframe::FrameTarget) -> Result<()> {
    let connect_str = target.to_connect_string();
    info!("ARK-frame TCP connect → {}", connect_str);

    let upstream = match TcpStream::connect(&connect_str).await {
        Ok(s) => s,
        Err(e) => {
            let status = arkframe::status_for_io_error(&e);
            let _ = arkframe::write_status(stream, status).await;
            return Err(anyhow::Error::new(e)
                .context(format!("dialing upstream {connect_str}")));
        }
    };
    let _ = upstream.set_nodelay(true);

    arkframe::write_status(stream, arkframe::STATUS_OK)
        .await
        .context("sending ARK-frame OK status")?;

    let mut upstream = upstream;
    tokio::io::copy_bidirectional(stream, &mut upstream).await?;
    Ok(())
}

/// UDP_ASSOCIATE relay (v0.1.9 / Phase 11 WP2).
///
/// Multiplexes outbound UDP datagrams onto an ephemeral server-side UDP
/// socket, with per-destination NAT tracking and a 60s idle timeout. All
/// datagrams flow through the same TCP-framed ARK channel established
/// during the handshake — no second port is opened to the client.
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Hard cap on concurrent destinations per UDP_ASSOCIATE session (anti-abuse).
const UDP_MAX_DESTINATIONS: usize = 256;

async fn serve_udp_associate(stream: &mut BoxedAsyncReadWrite) -> Result<()> {
    info!("ARK-frame UDP_ASSOCIATE — opening relay socket");

    // One ephemeral socket per session; we re-use it for all destinations
    // (symmetric NAT semantics: replies come back on the same source IP/port
    // pair the destination saw).
    let udp = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            let status = arkframe::status_for_io_error(&e);
            let _ = arkframe::write_status(stream, status).await;
            return Err(anyhow::Error::new(e).context("binding UDP relay socket"));
        }
    };

    arkframe::write_status(stream, arkframe::STATUS_OK)
        .await
        .context("sending UDP_ASSOCIATE OK status")?;

    // Track which client destination corresponds to which actual remote
    // SocketAddr, so we can map replies back to the correct FrameTarget.
    // Key: resolved SocketAddr → (FrameTarget the client used, last_active).
    let nat: Arc<Mutex<HashMap<SocketAddr, (arkframe::FrameTarget, Instant)>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let (mut reader, mut writer) = tokio::io::split(stream);

    // Reply future: read from UDP socket → frame → write to client.
    let udp_r = udp.clone();
    let nat_r = nat.clone();
    let reply = async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, src) = match udp_r.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    debug!("UDP relay recv_from ended: {e}");
                    return Ok::<(), anyhow::Error>(());
                }
            };
            let target = {
                let mut g = nat_r.lock().await;
                if let Some((t, last)) = g.get_mut(&src) {
                    *last = Instant::now();
                    t.clone()
                } else {
                    debug!("UDP reply from unknown source {src} dropped");
                    continue;
                }
            };
            if let Err(e) = arkframe::write_udp_datagram(&mut writer, &target, &buf[..n]).await {
                debug!("UDP relay write to client failed: {e}");
                return Ok(());
            }
        }
    };

    // Forward future: read framed datagrams from client → resolve → send.
    let forward = async {
        loop {
            let (target, payload) = match arkframe::read_udp_datagram(&mut reader).await {
                Ok(v) => v,
                Err(e) => {
                    debug!("UDP forward read ended: {e}");
                    return Ok::<(), anyhow::Error>(());
                }
            };
            let dest_str = target.to_connect_string();
            let mut dests = match tokio::net::lookup_host(&dest_str).await {
                Ok(it) => it,
                Err(e) => {
                    debug!("UDP forward DNS failed for {dest_str}: {e}");
                    continue;
                }
            };
            let Some(dest) = dests.next() else {
                debug!("UDP forward no addrs for {dest_str}");
                continue;
            };
            {
                let mut g = nat.lock().await;
                if !g.contains_key(&dest) && g.len() >= UDP_MAX_DESTINATIONS {
                    if let Some(victim) = g
                        .iter()
                        .min_by_key(|(_, (_, t))| *t)
                        .map(|(k, _)| *k)
                    {
                        g.remove(&victim);
                    }
                }
                let now = Instant::now();
                g.retain(|_, (_, last)| now.duration_since(*last) < UDP_IDLE_TIMEOUT);
                g.insert(dest, (target.clone(), now));
            }
            if let Err(e) = udp.send_to(&payload, dest).await {
                debug!("UDP forward send_to {dest} failed: {e}");
            }
        }
    };

    tokio::select! {
        r = reply => r,
        f = forward => f,
    }
}

/// Validate that the connecting UUID is registered in the server config.
fn validate_uuid(cfg: &ServerConfig, uuid: &uuid::Uuid) -> Result<()> {
    let s = uuid.to_string();
    if cfg.uuids.iter().any(|u| u == &s) {
        Ok(())
    } else {
        anyhow::bail!("unrecognized UUID {}", uuid)
    }
}

/// Drop root privileges to an unprivileged user after the privileged socket has been bound.
///
/// Reads the `ARK_USER` environment variable (default: `"nobody"`). If the process is not
/// running as root, this is a no-op.
#[cfg(unix)]
fn drop_privileges() -> Result<()> {
    use nix::unistd::{setuid, setgid, getuid};
    use nix::unistd::User;

    if !getuid().is_root() {
        return Ok(()); // Not root — nothing to drop.
    }

    let target_user = std::env::var("ARK_USER").unwrap_or_else(|_| "nobody".to_string());
    let user = User::from_name(&target_user)
        .map_err(|e| anyhow::anyhow!("looking up user '{}': {}", target_user, e))?
        .ok_or_else(|| anyhow::anyhow!("user '{}' not found", target_user))?;

    setgid(user.gid).map_err(|e| anyhow::anyhow!("setgid: {e}"))?;
    setuid(user.uid).map_err(|e| anyhow::anyhow!("setuid: {e}"))?;
    info!("Dropped privileges to {}:{}", user.uid, user.gid);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_core::transport::BoxedAsyncReadWrite;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Phase 13 WP1: the RealPeer splice replays peeked bytes first,
    /// then bidirectionally pumps subsequent traffic to the upstream.
    #[tokio::test]
    async fn splice_real_peer_replays_peeked_then_pumps() {
        // Stub upstream "bitcoind" that echoes everything it receives,
        // up to the first 64 bytes, so we can assert ordering.
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut s, _) = upstream.accept().await.unwrap();
            let mut buf = vec![0u8; 64];
            let n = s.read(&mut buf).await.unwrap();
            buf.truncate(n);
            s.write_all(&buf).await.unwrap();
            buf
        });

        // The "peer" side — a real loopback TCP pair we hand into the
        // splice as the BoxedAsyncReadWrite half.
        let peer_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_listener.local_addr().unwrap();
        let peer_client = tokio::net::TcpStream::connect(peer_addr).await.unwrap();
        let (peer_server, _) = peer_listener.accept().await.unwrap();
        let peer_server_boxed = BoxedAsyncReadWrite(Box::new(peer_server));

        let peeked = b"PEEK".to_vec();
        let splice = tokio::spawn(splice_real_peer(peer_server_boxed, peeked, upstream_addr));

        // The client (acting as the real Bitcoin peer) sends extra bytes
        // *after* what was already peeked; upstream should see PEEK+POST,
        // and the echo should make its way back to the client.
        let mut peer_client = peer_client;
        peer_client.write_all(b"POST").await.unwrap();
        let mut reply = vec![0u8; 8];
        let n = peer_client.read(&mut reply).await.unwrap();
        reply.truncate(n);
        assert_eq!(&reply, b"PEEKPOST");

        drop(peer_client);
        let _ = splice.await.unwrap();
        let upstream_saw = upstream_task.await.unwrap();
        assert_eq!(&upstream_saw, b"PEEKPOST");
    }
}

