// Proxy target — the destination address for a proxied connection.
//
// Constructed from SOCKS5 or HTTP CONNECT address fields and passed
// to `open_proxied_stream` and to the ARK-frame request builder.

use anyhow::{Context, Result};
use ark_core::{
    ark1_payload,
    arkframe,
    bip324::Bip324Transport,
    rlpx::RlpxTransport,
    transport::{BoxedAsyncReadWrite, Transport},
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::uri::{ArkUri, TransportKind};

/// Destination address for a proxied connection.
#[derive(Debug, Clone)]
pub enum Target {
    Ipv4([u8; 4], u16),
    Domain(String, u16),
    Ipv6([u8; 16], u16),
}

impl Target {
    #[allow(dead_code)]
    pub fn port(&self) -> u16 {
        match self {
            Target::Ipv4(_, p) | Target::Domain(_, p) | Target::Ipv6(_, p) => *p,
        }
    }
}

/// Step 1: TCP connect + transport handshake only.
///
/// Opens a TCP connection to the ark-server and completes the transport-layer
/// handshake (BIP 324 or RLPx), returning the encrypted channel.
/// Does NOT send ARK1 or the VLESS request — call `activate_proxied_stream`
/// to complete the session.  This split allows the connection pool to
/// pre-establish channels without knowing the final target address.
pub async fn open_transport_only(uri: &ArkUri) -> Result<BoxedAsyncReadWrite> {
    let server_addr: std::net::SocketAddr =
        format!("{}:{}", uri.host(), uri.port())
            .parse()
            .with_context(|| format!("invalid server address: {}:{}", uri.host(), uri.port()))?;

    let tcp = TcpStream::connect(server_addr)
        .await
        .with_context(|| format!("TCP connect to ark-server {}:{}", uri.host(), uri.port()))?;
    let _ = tcp.set_nodelay(true);

    match uri.transport {
        TransportKind::Bip324 => Bip324Transport::connect(tcp, server_addr)
            .await
            .context("BIP 324 handshake failed"),
        TransportKind::Rlpx => {
            if let Some(nodekey) = uri.nodekey {
                ark_core::rlpx::set_peer_pub(nodekey);
            }
            RlpxTransport::connect(tcp, server_addr)
                .await
                .context("RLPx handshake failed")
        }
    }
}

/// Step 2: send ARK1 + ARK-frame request over an already-established transport channel.
///
/// Completes a channel returned by `open_transport_only` by:
/// 1. Sending `ARK1 || uuid` (server identifies this connection as ArkTunnel).
/// 2. Sending the ARK-frame v0 TCP-connect request for `target`.
/// 3. Reading the server's 1-byte status response.
///
/// Returns the stream ready for bidirectional application data.
pub async fn activate_proxied_stream(
    mut stream: BoxedAsyncReadWrite,
    uri: &ArkUri,
    target: &Target,
) -> Result<BoxedAsyncReadWrite> {
    // 1. ARK1+UUID — server identifies this connection as ArkTunnel.
    let ark1 = ark1_payload(&uri.uuid);
    stream.write_all(&ark1).await.context("sending ARK1 payload")?;
    stream.flush().await.context("flushing ARK1 payload")?;

    // 2. ARK-frame TCP-connect request.
    let frame_target = target_to_frame(target);
    let req = arkframe::build_request(&frame_target).context("building ARK-frame request")?;
    stream.write_all(&req).await.context("sending ARK-frame request")?;
    stream.flush().await.context("flushing ARK-frame request")?;

    // 3. Server status byte.
    arkframe::read_status(&mut stream)
        .await
        .context("reading ARK-frame status")?;

    Ok(stream)
}

fn target_to_frame(t: &Target) -> arkframe::FrameTarget {
    match t {
        Target::Ipv4(a, p) => arkframe::FrameTarget::Ipv4(*a, *p),
        Target::Domain(d, p) => arkframe::FrameTarget::Domain(d.clone(), *p),
        Target::Ipv6(a, p) => arkframe::FrameTarget::Ipv6(*a, *p),
    }
}

/// Open a fully authenticated proxy stream to `target` via the ark-server at `uri`.
///
/// Combines `open_transport_only` + `activate_proxied_stream` for callers that
/// do not use the connection pool.
pub async fn open_proxied_stream(uri: &ArkUri, target: &Target) -> Result<BoxedAsyncReadWrite> {
    let stream = open_transport_only(uri).await?;
    activate_proxied_stream(stream, uri, target).await
}

/// Open a UDP_ASSOCIATE channel: send ARK1 + UUID, then a UDP_ASSOCIATE
/// request, and verify the server's status byte. The returned stream then
/// carries length-prefixed ARK-frame UDP datagrams in both directions
/// (see `arkframe::{read_udp_datagram, write_udp_datagram}`).
pub async fn open_udp_associate_stream(uri: &ArkUri) -> Result<BoxedAsyncReadWrite> {
    let mut stream = open_transport_only(uri).await?;
    let ark1 = ark1_payload(&uri.uuid);
    stream.write_all(&ark1).await.context("sending ARK1 payload")?;
    stream.flush().await.context("flushing ARK1 payload")?;
    let req = arkframe::build_udp_associate([0; 4], 0);
    stream.write_all(&req).await.context("sending UDP_ASSOCIATE request")?;
    stream.flush().await.context("flushing UDP_ASSOCIATE request")?;
    arkframe::read_status(&mut stream)
        .await
        .context("reading UDP_ASSOCIATE status")?;
    Ok(stream)
}
