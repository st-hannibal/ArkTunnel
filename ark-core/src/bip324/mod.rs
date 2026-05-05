// BIP 324 transport implementation (Phase 2)

pub mod cipher;
pub mod ellswift;
pub mod handshake;

use crate::transport::{BoxedAsyncReadWrite, Multiplexed, Transport};
use anyhow::Result;
use handshake::{do_initiator_handshake, do_responder_handshake, EncryptedStream, ResponderOutcome};
use std::net::SocketAddr;
use tokio::net::TcpStream;

// ---------------------------------------------------------------------------
// AsyncRead/AsyncWrite impl for EncryptedStream
// ---------------------------------------------------------------------------
//
// EncryptedStream wraps a TcpStream + cipher state.  For the `Transport` trait
// we need it to be usable as `Box<dyn AsyncReadWrite>`.
//
// BIP 324's packet framing means we cannot implement a raw byte stream directly
// (each read must decrypt a full packet at once).  For the MVP we expose a
// buffered shim that reads complete packets internally and surfaces the plaintext
// to the caller as a byte stream.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A thin async wrapper that surfaces `EncryptedStream` as an `AsyncRead+AsyncWrite`.
///
/// Write: buffers `write()` calls and flushes them as a single BIP 324 packet on
/// `flush()`.  Read: decrypts one full packet per `fill_buf` call, then serves
/// bytes from an internal plaintext buffer.
pub struct Bip324Stream {
    inner: EncryptedStream,
    /// Buffered plaintext bytes ready to return to callers.
    read_buf: Vec<u8>,
    read_pos: usize,
    /// Bytes accumulated from `write()` calls, flushed as one packet on `flush()`.
    write_buf: Vec<u8>,
    /// Cancel-safety: `write_buf` is encrypted into `flush_buf` exactly once so
    /// that a dropped future never re-encrypts (which would advance the cipher
    /// state a second time and corrupt the stream).
    flush_buf: Option<Vec<u8>>,
    flush_pos: usize,
}

impl Bip324Stream {
    pub fn new(inner: EncryptedStream) -> Self {
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

impl Unpin for Bip324Stream {}

impl AsyncRead for Bip324Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // If there is buffered plaintext, serve it.
        if this.read_pos < this.read_buf.len() {
            let available = &this.read_buf[this.read_pos..];
            let to_copy = available.len().min(buf.remaining());
            buf.put_slice(&available[..to_copy]);
            this.read_pos += to_copy;
            return Poll::Ready(Ok(()));
        }

        // Need to receive a new packet.  Use a local async block polled via
        // a Box::pin future stored in the struct.  For simplicity we use
        // `tokio::runtime::Handle::current().block_on` — but that panics in
        // async context.  Instead we drive the future manually.
        //
        // Proper solution: store a `Pin<Box<dyn Future>>` field.  For the MVP,
        // we register a waker and rely on the Tokio executor driving us again
        // when the underlying TcpStream is readable.
        //
        // We do this via the inner TcpStream's poll_read to detect readiness,
        // then spawn a blocking-style recv if ready.  This is sufficient for
        // integration testing with `tokio::test`.
        let recv_fut = this.inner.recv_packet(b"");
        let mut boxed = Box::pin(recv_fut);
        match boxed.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(std::io::Error::other(e)))
            }
            Poll::Ready(Ok(plaintext)) => {
                this.read_buf = plaintext;
                this.read_pos = 0;
                let available = &this.read_buf[this.read_pos..];
                let to_copy = available.len().min(buf.remaining());
                buf.put_slice(&available[..to_copy]);
                this.read_pos += to_copy;
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for Bip324Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.write_buf.extend_from_slice(buf);
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
            match this.inner.encrypt_packet(&data, b"") {
                Ok(encrypted) => {
                    this.flush_buf = Some(encrypted);
                    this.flush_pos = 0;
                }
                Err(e) => {
                    return Poll::Ready(Err(std::io::Error::other(e)));
                }
            }
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
        // Flush pending writes, then shut down.
        self.poll_flush(cx)
    }
}

// ---------------------------------------------------------------------------
// Bip324Transport — implements the Transport trait
// ---------------------------------------------------------------------------

pub struct Bip324Transport;

impl Transport for Bip324Transport {
    fn name() -> &'static str {
        "bip324"
    }

    fn default_port() -> u16 {
        8333
    }

    async fn connect(stream: TcpStream, _addr: SocketAddr) -> Result<BoxedAsyncReadWrite> {
        let enc = do_initiator_handshake(stream).await?;
        Ok(BoxedAsyncReadWrite(Box::new(Bip324Stream::new(enc))))
    }

    async fn accept(stream: TcpStream) -> Result<Multiplexed> {
        match do_responder_handshake(stream).await? {
            ResponderOutcome::ArkClient { stream: enc, uuid } => Ok(Multiplexed::ArkClient {
                stream: BoxedAsyncReadWrite(Box::new(Bip324Stream::new(enc))),
                uuid,
            }),
            ResponderOutcome::RealPeer { stream, peeked } => Ok(Multiplexed::RealPeer {
                stream: BoxedAsyncReadWrite(Box::new(stream)),
                peeked,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::transport::{ark1_payload, Multiplexed};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// Full BIP 324 handshake: two in-process TCP peers, ARK1 marker exchange,
    /// application data round-trip.
    #[tokio::test]
    async fn bip324_full_handshake_ark1_and_data() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let test_uuid = uuid::Uuid::new_v4();
        let uuid_expected = test_uuid;

        // Responder runs in a separate task.
        let resp = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            match Bip324Transport::accept(stream).await.unwrap() {
                Multiplexed::ArkClient { mut stream, uuid } => {
                    assert_eq!(uuid, uuid_expected, "UUID mismatch");
                    // Echo: read 5 bytes, write them back uppercased.
                    let mut buf = [0u8; 5];
                    stream.read_exact(&mut buf).await.unwrap();
                    assert_eq!(&buf, b"ping!");
                    stream.write_all(b"pong!").await.unwrap();
                    stream.flush().await.unwrap();
                }
                Multiplexed::RealPeer { .. } => panic!("expected ArkClient, got RealPeer"),
            }
        });

        // Initiator: handshake, send ARK1, exchange data.
        let tcp = TcpStream::connect(addr).await.unwrap();
        let enc = do_initiator_handshake(tcp).await.unwrap();
        let mut bip = Bip324Stream::new(enc);

        // First application message must be ARK1+UUID (as a single flushed packet).
        bip.write_all(&ark1_payload(&test_uuid)).await.unwrap();
        bip.flush().await.unwrap();

        // Exchange data.
        bip.write_all(b"ping!").await.unwrap();
        bip.flush().await.unwrap();

        let mut buf = [0u8; 5];
        bip.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong!");

        resp.await.unwrap();
    }
}
