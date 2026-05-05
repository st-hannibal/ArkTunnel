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
// (each read must decrypt a full packet at once).  We expose a buffered shim that
// reads complete packets internally and surfaces the plaintext as a byte stream.
//
// CANCEL SAFETY: `poll_read` must not drop partially-read bytes on `Poll::Pending`.
// We implement a persistent state machine (`RecvState`) stored in the struct so
// that partially-read length/body bytes survive across polls.  The old approach of
// creating a new `recv_packet` future on every poll and dropping it on Pending
// worked on loopback (atomic delivery) but silently corrupted the stream over real
// networks where TCP delivers data in fragments.

use cipher::{v2_receive_contents, v2_receive_length, LENGTH_FIELD_LEN};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// In-progress state for receiving one BIP 324 packet.
enum RecvState {
    /// Waiting to start a new packet.
    Idle,
    /// Accumulating the 3-byte encrypted length field.
    ReadingLength { buf: [u8; LENGTH_FIELD_LEN], filled: usize },
    /// Accumulating the AEAD ciphertext body.
    ReadingBody { aead_len: usize, buf: Vec<u8>, filled: usize },
}

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
    /// Persistent state for the in-progress packet receive (cancel-safe).
    recv_state: RecvState,
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
            recv_state: RecvState::Idle,
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

        // Serve any buffered plaintext.
        if this.read_pos < this.read_buf.len() {
            let available = &this.read_buf[this.read_pos..];
            let to_copy = available.len().min(buf.remaining());
            buf.put_slice(&available[..to_copy]);
            this.read_pos += to_copy;
            return Poll::Ready(Ok(()));
        }

        // Drive the receive state machine.  We loop so that transitioning from
        // ReadingLength -> ReadingBody -> serving data can happen without returning
        // to the executor if all bytes are already in the TCP buffer.
        loop {
            match &mut this.recv_state {
                RecvState::Idle => {
                    this.recv_state = RecvState::ReadingLength {
                        buf: [0u8; LENGTH_FIELD_LEN],
                        filled: 0,
                    };
                }

                RecvState::ReadingLength { buf: len_buf, filled } => {
                    while *filled < LENGTH_FIELD_LEN {
                        let mut rb = ReadBuf::new(&mut len_buf[*filled..]);
                        match Pin::new(this.inner.tcp_stream_mut()).poll_read(cx, &mut rb) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Ready(Ok(())) => {
                                let n = rb.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "connection closed during BIP324 length read",
                                    )));
                                }
                                *filled += n;
                            }
                        }
                    }
                    // All 3 length bytes present -- decrypt to get AEAD body size.
                    let aead_len = v2_receive_length(this.inner.recv_l_mut(), len_buf);
                    this.recv_state = RecvState::ReadingBody {
                        aead_len,
                        buf: vec![0u8; aead_len],
                        filled: 0,
                    };
                }

                RecvState::ReadingBody { aead_len, buf: body_buf, filled } => {
                    while *filled < *aead_len {
                        let mut rb = ReadBuf::new(&mut body_buf[*filled..]);
                        match Pin::new(this.inner.tcp_stream_mut()).poll_read(cx, &mut rb) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Ready(Ok(())) => {
                                let n = rb.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "connection closed during BIP324 body read",
                                    )));
                                }
                                *filled += n;
                            }
                        }
                    }
                    // Full body present -- decrypt.
                    let body_clone = body_buf.clone();
                    match v2_receive_contents(this.inner.recv_p_mut(), &body_clone, b"") {
                        Err(e) => {
                            return Poll::Ready(Err(io::Error::other(e)));
                        }
                        Ok(None) => {
                            // Decoy packet -- discard and read the next one.
                            this.recv_state = RecvState::Idle;
                        }
                        Ok(Some(plaintext)) => {
                            this.recv_state = RecvState::Idle;
                            this.read_buf = plaintext;
                            this.read_pos = 0;
                            let available = &this.read_buf;
                            let to_copy = available.len().min(buf.remaining());
                            buf.put_slice(&available[..to_copy]);
                            this.read_pos = to_copy;
                            return Poll::Ready(Ok(()));
                        }
                    }
                }
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

        // All bytes written -- clear flush state and flush the TCP socket.
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
// Bip324Transport -- implements the Transport trait
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
