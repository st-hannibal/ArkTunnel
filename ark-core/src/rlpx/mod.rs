// RLPx transport implementation (Phase 3)

pub mod ecies;
pub mod framing;
pub mod handshake;

use crate::transport::{BoxedAsyncReadWrite, Multiplexed, Transport};
use anyhow::{anyhow, Result};
use handshake::{do_initiator_handshake, do_responder_handshake, RlpxEncryptedStream, ResponderOutcome};
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use std::net::SocketAddr;
use std::sync::OnceLock;
use tokio::net::TcpStream;

// ---------------------------------------------------------------------------
// Module-level static key store (server side) and peer-pub store (client side)
// ---------------------------------------------------------------------------

/// Server's static keypair — generated once per process, reused for all accepts.
static STATIC_KEY: OnceLock<(SecretKey, [u8; 64])> = OnceLock::new();

/// Expected server static public key — set by ark-client before calling connect().
static EXPECTED_PEER_PUB: OnceLock<[u8; 64]> = OnceLock::new();

/// Set the server's static public key for client-side handshakes.
///
/// Must be called before the first `RlpxTransport::connect()`.
/// `pub_bytes`: 64-byte x || y (no 04 prefix) secp256k1 public key.
pub fn set_peer_pub(pub_bytes: [u8; 64]) {
    let _ = EXPECTED_PEER_PUB.set(pub_bytes);
}

/// Get the server's static public key bytes (for publishing in arktunnel:// URI).
pub fn server_pub_bytes() -> [u8; 64] {
    get_static_key().1
}

fn get_static_key() -> &'static (SecretKey, [u8; 64]) {
    STATIC_KEY.get_or_init(|| {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let pk = PublicKey::from_secret_key(SECP256K1, &sk);
        let pk_bytes: [u8; 64] = pk.serialize_uncompressed()[1..].try_into().unwrap();
        (sk, pk_bytes)
    })
}

// ---------------------------------------------------------------------------
// AsyncRead/AsyncWrite shim for RlpxEncryptedStream
// ---------------------------------------------------------------------------
//
// RLPx uses packet framing, so we can't implement AsyncRead/AsyncWrite directly.
// We buffer a full plaintext frame in `read_buf` and serve bytes from it.
// Writes accumulate in `write_buf` and are flushed as one frame on poll_flush.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Thin async wrapper that exposes `RlpxEncryptedStream` as `AsyncRead + AsyncWrite`.
pub struct RlpxStream {
    inner: RlpxEncryptedStream,
    read_buf: Vec<u8>,
    read_pos: usize,
    write_buf: Vec<u8>,
    /// Cancel-safety: `write_buf` is encrypted into `flush_buf` exactly once so
    /// a dropped future never re-encrypts and corrupts the MAC/AES state.
    flush_buf: Option<Vec<u8>>,
    flush_pos: usize,
}

impl RlpxStream {
    pub fn new(inner: RlpxEncryptedStream) -> Self {
        Self {
            inner,
            read_buf: Vec::new(),
            read_pos: 0,
            write_buf: Vec::new(),
            flush_buf: None,
            flush_pos: 0,
        }
    }
}

impl Unpin for RlpxStream {}

impl AsyncRead for RlpxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Serve from buffer if available
        if this.read_pos < this.read_buf.len() {
            let avail = &this.read_buf[this.read_pos..];
            let n = avail.len().min(buf.remaining());
            buf.put_slice(&avail[..n]);
            this.read_pos += n;
            return Poll::Ready(Ok(()));
        }

        // Receive a new frame
        let recv_fut = this.inner.recv_frame();
        let mut boxed = Box::pin(recv_fut);
        match boxed.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            Poll::Ready(Ok(plaintext)) => {
                this.read_buf = plaintext;
                this.read_pos = 0;
                let avail = &this.read_buf[this.read_pos..];
                let n = avail.len().min(buf.remaining());
                buf.put_slice(&avail[..n]);
                this.read_pos += n;
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for RlpxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.get_mut().write_buf.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Step 1: encrypt write_buf into flush_buf exactly once.
        if this.flush_buf.is_none() {
            if this.write_buf.is_empty() {
                return Pin::new(this.inner.tcp_stream_mut()).poll_flush(cx);
            }
            let data = std::mem::take(&mut this.write_buf);
            let encrypted = this.inner.encrypt_frame_only(&data);
            this.flush_buf = Some(encrypted);
            this.flush_pos = 0;
        }

        // Step 2: write flush_buf to TCP, handling partial writes without re-encrypting.
        loop {
            let remaining = {
                let buf = this.flush_buf.as_ref().unwrap();
                buf.len() - this.flush_pos
            };
            if remaining == 0 {
                break;
            }
            let buf = this.flush_buf.as_ref().unwrap();
            let tcp = Pin::new(this.inner.tcp_stream_mut());
            match tcp.poll_write(cx, &buf[this.flush_pos..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "write returned 0 bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => this.flush_pos += n,
            }
        }

        // All bytes written — clear flush state and flush the TCP socket.
        this.flush_buf = None;
        this.flush_pos = 0;
        Pin::new(this.inner.tcp_stream_mut()).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.poll_flush(cx)
    }
}

// ---------------------------------------------------------------------------
// RlpxTransport — implements the Transport trait
// ---------------------------------------------------------------------------

pub struct RlpxTransport;

impl Transport for RlpxTransport {
    fn name() -> &'static str {
        "rlpx"
    }

    fn default_port() -> u16 {
        30303
    }

    async fn connect(stream: TcpStream, _addr: SocketAddr) -> Result<BoxedAsyncReadWrite> {
        let peer_pub = EXPECTED_PEER_PUB
            .get()
            .ok_or_else(|| anyhow!(
                "RLPx: server static pub key not configured; call rlpx::set_peer_pub() first"
            ))?;
        let enc = do_initiator_handshake(stream, peer_pub).await?;
        Ok(BoxedAsyncReadWrite(Box::new(RlpxStream::new(enc))))
    }

    async fn accept(stream: TcpStream) -> Result<Multiplexed> {
        let (static_priv, static_pub) = get_static_key();
        match do_responder_handshake(stream, static_priv, static_pub).await? {
            ResponderOutcome::ArkClient { stream: enc, uuid } => Ok(Multiplexed::ArkClient {
                stream: BoxedAsyncReadWrite(Box::new(RlpxStream::new(enc))),
                uuid,
            }),
            ResponderOutcome::RealPeer(enc) => Ok(Multiplexed::RealPeer {
                // The connection is already inside an RLPx encrypted session; wrap it so
                // ark-server can relay frames to local geth via relay_to_local_geth().
                stream: BoxedAsyncReadWrite(Box::new(RlpxStream::new(enc))),
                peeked: vec![],
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// RLPx real-peer relay helpers (used by ark-server)
// ---------------------------------------------------------------------------

/// Read the local geth/reth static private key from disk and return the
/// corresponding 64-byte secp256k1 public key (x || y, no 04 prefix).
///
/// Tries (in order):
///   `/var/lib/reth/discovery-secret` — reth stores its discovery key here
///   `/var/lib/geth/geth/nodekey`      — geth stores its node key here
///
/// Both files contain the 32-byte private key as a lowercase hex string.
/// Returns `None` if neither file exists or cannot be parsed.
pub fn read_local_geth_pubkey() -> Option<[u8; 64]> {
    const PATHS: &[&str] = &["/var/lib/reth/discovery-secret", "/var/lib/geth/geth/nodekey"];
    for path in PATHS {
        if let Ok(hex_str) = std::fs::read_to_string(path) {
            let hex_str = hex_str.trim();
            if let Ok(bytes) = decode_hex_32(hex_str) {
                if let Ok(sk) = SecretKey::from_slice(&bytes) {
                    let pk = PublicKey::from_secret_key(SECP256K1, &sk);
                    let mut pk_bytes = [0u8; 64];
                    pk_bytes.copy_from_slice(&pk.serialize_uncompressed()[1..]);
                    return Some(pk_bytes);
                }
            }
        }
    }
    None
}

/// Relay a real Ethereum peer's already-established RLPx session to the local
/// geth/reth node by opening a second RLPx connection as the initiator.
///
/// Byte-level bidirectional copy between the two encrypted streams handles
/// frame relay transparently: each `RlpxStream` decrypts from one side and
/// re-encrypts for the other.
///
/// `peer_stream`: `BoxedAsyncReadWrite` wrapping the peer's `RlpxStream`.
/// `geth_pub`: geth's 64-byte static public key (x || y, no 04 prefix).
/// `geth_addr`: socket address of the local geth p2p port (e.g. 127.0.0.1:30304).
pub async fn relay_to_local_geth(
    mut peer_stream: BoxedAsyncReadWrite,
    geth_pub: &[u8; 64],
    geth_addr: SocketAddr,
) -> Result<()> {
    use anyhow::Context as _;
    let geth_tcp = TcpStream::connect(geth_addr)
        .await
        .context("connecting to local geth for RLPx real-peer relay")?;
    let geth_enc = do_initiator_handshake(geth_tcp, geth_pub)
        .await
        .context("RLPx handshake with local geth")?;
    let mut geth_stream = BoxedAsyncReadWrite(Box::new(RlpxStream::new(geth_enc)));
    tokio::io::copy_bidirectional(&mut peer_stream, &mut geth_stream).await?;
    Ok(())
}

/// Decode a hex string to exactly 32 bytes; returns `Err(())` on any parse failure.
fn decode_hex_32(s: &str) -> std::result::Result<[u8; 32], ()> {
    if s.len() != 64 {
        return Err(());
    }
    let mut out = [0u8; 32];
    let bytes = s.as_bytes();
    for (i, chunk) in bytes.chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0]).ok_or(())?;
        let lo = hex_nibble(chunk[1]).ok_or(())?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
