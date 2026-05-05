// Proxy target — the destination address for a proxied connection.
//
// Constructed from SOCKS5 or HTTP CONNECT address fields and passed
// to `open_proxied_stream` and to the ARK-frame request builder.

use anyhow::{Context, Result};
use ark_core::shaping::Shape;
use ark_core::{
    ark1_payload,
    arkframe,
    transport::BoxedAsyncReadWrite,
};
use std::sync::OnceLock;
use tokio::io::AsyncWriteExt;

use crate::endpoints;
use crate::uri::ArkUri;

/// Process-wide traffic shaping policy. Set once from `main` before any
/// connection is opened. Defaults to [`Shape::Off`] if never set, which
/// preserves byte-for-byte v0.1.x wire behavior.
static SHAPE: OnceLock<Shape> = OnceLock::new();

/// Configure the global shaping policy for this process.
pub fn set_shape(shape: Shape) {
    let _ = SHAPE.set(shape);
}

fn shape() -> Shape {
    SHAPE.get().copied().unwrap_or(Shape::Off)
}

/// Capability bits the client wants for the current shaping policy.
fn requested_caps(shape: Shape) -> u8 {
    match shape {
        Shape::Off => 0,
        Shape::Light | Shape::Heavy => arkframe::CAP_COVER | arkframe::CAP_PAD_QUANTIZE,
    }
}

/// Maximum time we wait for the server's v2 ack before falling back to v1.
const V2_ACK_DEADLINE: std::time::Duration = std::time::Duration::from_secs(2);

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
///
/// As of v0.2.0 this honors multi-endpoint URIs and dispatches via
/// `endpoints::connect_with_failover` (sticky preference + demote-on-fail).
pub async fn open_transport_only(uri: &ArkUri) -> Result<BoxedAsyncReadWrite> {
    endpoints::connect_with_failover(uri).await
}

/// Step 2: send ARK1 + ARK-frame request over an already-established transport channel.
///
/// Completes a channel returned by `open_transport_only` by:
/// 1. Sending `ARK1 || uuid` (server identifies this connection as ArkTunnel).
///    When the configured `Shape` is non-off, an ARK-frame v2 hello is
///    appended to the same encrypted packet so the server can ack the
///    negotiated capability set before the request is sent.
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
    //    With shaping enabled, append the v2 hello in the same packet.
    let shape = shape();
    let caps_req = requested_caps(shape);
    let mut hello = Vec::with_capacity(20 + arkframe::V2_HELLO_LEN);
    hello.extend_from_slice(&ark1_payload(&uri.uuid));
    if caps_req != 0 {
        hello.extend_from_slice(&arkframe::build_v2_hello(caps_req));
    }
    stream.write_all(&hello).await.context("sending ARK1 payload")?;
    stream.flush().await.context("flushing ARK1 payload")?;

    // 1b. If we sent a v2 hello, read the server's ack (or fall back to v1).
    if caps_req != 0 {
        let agreed = arkframe::client_read_v2_ack(&mut stream, V2_ACK_DEADLINE).await;
        if agreed == 0 {
            tracing::warn!(
                shape = %shape,
                "server did not ack ARK-frame v2; falling back to v1 (no padding/cover)"
            );
        } else {
            tracing::info!(
                shape = %shape,
                caps = format!("0x{agreed:02x}"),
                "ARK-frame v2 negotiated"
            );
        }
    }

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
    let shape = shape();
    let caps_req = requested_caps(shape);
    let mut hello = Vec::with_capacity(20 + arkframe::V2_HELLO_LEN);
    hello.extend_from_slice(&ark1_payload(&uri.uuid));
    if caps_req != 0 {
        hello.extend_from_slice(&arkframe::build_v2_hello(caps_req));
    }
    stream.write_all(&hello).await.context("sending ARK1 payload")?;
    stream.flush().await.context("flushing ARK1 payload")?;
    if caps_req != 0 {
        let agreed = arkframe::client_read_v2_ack(&mut stream, V2_ACK_DEADLINE).await;
        if agreed == 0 {
            tracing::warn!(shape = %shape, "server did not ack ARK-frame v2 (UDP); falling back to v1");
        }
    }
    let req = arkframe::build_udp_associate([0; 4], 0);
    stream.write_all(&req).await.context("sending UDP_ASSOCIATE request")?;
    stream.flush().await.context("flushing UDP_ASSOCIATE request")?;
    arkframe::read_status(&mut stream)
        .await
        .context("reading UDP_ASSOCIATE status")?;
    Ok(stream)
}
