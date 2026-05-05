use std::net::SocketAddr;
use tokio::net::TcpStream;
use anyhow::Result;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// ---------------------------------------------------------------------------
// AsyncReadWrite — object-safe combination of AsyncRead + AsyncWrite + Unpin
// ---------------------------------------------------------------------------

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

// Newtype wrapper so we can box it as a trait object.
pub struct BoxedAsyncReadWrite(pub Box<dyn AsyncReadWrite>);

impl AsyncRead for BoxedAsyncReadWrite {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for BoxedAsyncReadWrite {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.0).poll_shutdown(cx)
    }
}

impl Unpin for BoxedAsyncReadWrite {}

// ---------------------------------------------------------------------------
// Multiplexed — result of Transport::accept()
// ---------------------------------------------------------------------------
//
// After the crypto handshake, the server reads the first decrypted payload:
//
//   • ArkClient: payload starts with ARK1 magic → proxy to sing-box VLESS.
//     The inner stream is the already-established encrypted channel, ready
//     for VLESS framing on top.
//
//   • RealPeer: payload is a standard crypto network message (Bitcoin "version"
//     or Ethereum "Hello") → forward the raw TCP stream to the local node
//     (bitcoind / geth). The unread bytes are buffered back so the local node
//     sees a complete stream.

pub enum Multiplexed {
    /// Incoming connection is an ArkTunnel client.
    /// The box wraps the decrypted channel — write/read VLESS directly.
    /// The `uuid` extracted from ARK1 payload identifies the user.
    ArkClient {
        stream: BoxedAsyncReadWrite,
        uuid: uuid::Uuid,
    },

    /// Incoming connection is a real crypto peer.
    /// For BIP 324: the stream is the raw TCP connection (peer was detected before handshake).
    /// For RLPx: the stream is the RLPx-encrypted session (peer detected after Hello exchange).
    /// `peeked` contains bytes already consumed from the stream during handshake detection;
    /// the server must write them to the upstream crypto node before starting the bidirectional copy.
    RealPeer {
        stream: BoxedAsyncReadWrite,
        /// Bytes consumed during v1-prefix detection that must be
        /// prepended when forwarding to the upstream crypto node.
        /// Always empty for RLPx (detection happens after full handshake).
        peeked: Vec<u8>,
    },
}

// ---------------------------------------------------------------------------
// Transport trait
// ---------------------------------------------------------------------------
//
// Each transport (BIP 324, RLPx, …) implements this trait.
// The trait is NOT object-safe because of the associated-function signatures,
// but that is intentional — callers select the concrete type at compile time
// (or via an enum dispatcher) rather than through dynamic dispatch.

pub trait Transport {
    /// Human-readable name, e.g. "bip324" or "rlpx".
    fn name() -> &'static str;

    /// Default TCP port for this transport.
    fn default_port() -> u16;

    /// Client side: perform the crypto handshake over an already-connected
    /// TCP stream and return an encrypted channel ready for VLESS framing.
    /// The caller must send ARK1 || uuid as the first application message.
    fn connect(
        stream: TcpStream,
        addr: SocketAddr,
    ) -> impl std::future::Future<Output = Result<BoxedAsyncReadWrite>> + Send;

    /// Server side: perform the crypto handshake and determine whether the
    /// peer is an ArkTunnel client or a real crypto network node.
    fn accept(
        stream: TcpStream,
    ) -> impl std::future::Future<Output = Result<Multiplexed>> + Send;
}

// ---------------------------------------------------------------------------
// ARK1 session marker helpers
// ---------------------------------------------------------------------------

/// Magic bytes sent by the client as the first application-level payload,
/// inside the transport ciphertext. Invisible to DPI.
pub const ARK1_MAGIC: &[u8; 4] = b"ARK1";

/// Build the ARK1 marker payload: `ARK1 (4B) || uuid (16B)` = 20 bytes.
pub fn ark1_payload(uuid: &uuid::Uuid) -> [u8; 20] {
    let mut buf = [0u8; 20];
    buf[..4].copy_from_slice(ARK1_MAGIC);
    buf[4..].copy_from_slice(uuid.as_bytes());
    buf
}

/// Parse an ARK1 payload received from a client.
/// Returns `None` if the payload does not start with ARK1_MAGIC or is too short.
pub fn parse_ark1(payload: &[u8]) -> Option<uuid::Uuid> {
    if payload.len() < 20 {
        return None;
    }
    if &payload[..4] != ARK1_MAGIC {
        return None;
    }
    uuid::Uuid::from_slice(&payload[4..20]).ok()
}
