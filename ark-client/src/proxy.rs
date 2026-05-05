// Proxy target — the destination address for a proxied connection.
//
// Constructed from SOCKS5 or HTTP CONNECT address fields and passed
// to `open_proxied_stream` and to the VLESS header builder.

use anyhow::{Context, Result};
use ark_core::{
    ark1_payload,
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
        format!("{}:{}", uri.host, uri.port)
            .parse()
            .with_context(|| format!("invalid server address: {}:{}", uri.host, uri.port))?;

    let tcp = TcpStream::connect(server_addr)
        .await
        .with_context(|| format!("TCP connect to ark-server {}:{}", uri.host, uri.port))?;

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

/// Step 2: send ARK1 + VLESS request over an already-established transport channel.
///
/// Completes a channel returned by `open_transport_only` by:
/// 1. Sending `ARK1 || uuid` (server mux layer identifies this as ArkTunnel).
/// 2. Sending the VLESS v0 request header (routed to sing-box by the server).
/// 3. Reading the VLESS response header.
///
/// Returns the stream ready for bidirectional application data.
pub async fn activate_proxied_stream(
    mut stream: BoxedAsyncReadWrite,
    uri: &ArkUri,
    target: &Target,
) -> Result<BoxedAsyncReadWrite> {
    // Send ARK1+UUID — server mux layer identifies this connection as ArkTunnel.
    let ark1 = ark1_payload(&uri.uuid);
    stream.write_all(&ark1).await.context("sending ARK1 payload")?;
    stream.flush().await.context("flushing ARK1 payload")?;

    // Send VLESS request header — routed to sing-box VLESS inbound by the server.
    let vless_req = crate::vless::build_request(&uri.uuid, target);
    stream.write_all(&vless_req).await.context("sending VLESS request header")?;
    stream.flush().await.context("flushing VLESS request header")?;

    // Read VLESS response header from sing-box (via server relay).
    crate::vless::read_response(&mut stream)
        .await
        .context("reading VLESS response header")?;

    Ok(stream)
}

/// Open a fully authenticated proxy stream to `target` via the ark-server at `uri`.
///
/// Combines `open_transport_only` + `activate_proxied_stream` for callers that
/// do not use the connection pool.
pub async fn open_proxied_stream(uri: &ArkUri, target: &Target) -> Result<BoxedAsyncReadWrite> {
    let stream = open_transport_only(uri).await?;
    activate_proxied_stream(stream, uri, target).await
}
