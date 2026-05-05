use crate::config::{ServerConfig, TransportKind};
use anyhow::{Context, Result};
use ark_core::{
    arkframe,
    bip324::Bip324Transport,
    rlpx::RlpxTransport,
    transport::{BoxedAsyncReadWrite, Multiplexed, Transport},
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{error, info, warn};

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
            Ok((stream, _peer_addr)) => {
                let _ = stream.set_nodelay(true);
                let cfg = cfg_rx.borrow().clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, cfg).await {
                        tracing::debug!("connection closed: {e}");
                    }
                });
            }
            Err(e) => error!("accept error: {e}"),
        }
    }
}


async fn handle_connection(stream: TcpStream, cfg: Arc<ServerConfig>) -> Result<()> {
    let crypto_node_addr: SocketAddr = cfg.crypto_node_addr().parse().unwrap();

    match cfg.transport {
        TransportKind::Bip324 => {
            match Bip324Transport::accept(stream).await? {
                Multiplexed::ArkClient { mut stream, uuid } => {
                    validate_uuid(&cfg, &uuid)?;
                    serve_arkframe(&mut stream).await?;
                }
                Multiplexed::RealPeer { mut stream, peeked } => {
                    let mut node = TcpStream::connect(crypto_node_addr).await
                        .context("connecting to bitcoind")?;
                    // Prepend the bytes consumed during v1 detection.
                    if !peeked.is_empty() {
                        node.write_all(&peeked).await?;
                    }
                    tokio::io::copy_bidirectional(&mut stream, &mut node).await?;
                }
            }
        }
        TransportKind::Rlpx => {
            match RlpxTransport::accept(stream).await? {
                Multiplexed::ArkClient { mut stream, uuid } => {
                    validate_uuid(&cfg, &uuid)?;
                    serve_arkframe(&mut stream).await?;
                }
                Multiplexed::RealPeer { stream, .. } => {
                    // Relay the real Ethereum peer to the local geth/reth node.
                    // We need geth's static public key to open a second RLPx session.
                    match ark_core::rlpx::read_local_geth_pubkey() {
                        Some(geth_pub) => {
                            ark_core::rlpx::relay_to_local_geth(stream, &geth_pub, crypto_node_addr)
                                .await
                                .context("RLPx real-peer relay to geth")?;
                        }
                        None => {
                            warn!(
                                "RLPx real Ethereum peer detected — \
                                 geth node key not found at /var/lib/reth/discovery-secret \
                                 or /var/lib/geth/geth/nodekey; dropping connection"
                            );
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Read the client's ARK-frame request, dial the requested target, send a
/// status byte, and pump bytes bidirectionally until either side closes.
async fn serve_arkframe(stream: &mut BoxedAsyncReadWrite) -> Result<()> {
    let target = arkframe::read_request(stream)
        .await
        .context("reading ARK-frame request")?;

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

