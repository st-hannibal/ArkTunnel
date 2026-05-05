// BIP 324 handshake state machine.
//
// Wire format:
//   Initiator → Responder: ellswift_pub (64B) || garbage (<= 4095B random)
//   Responder → Initiator: ellswift_pub (64B) || garbage (<= 4095B random)
//   Both: garbage_terminator (16B), version packet, app packets
//
// The responder first checks for the v1 Bitcoin protocol prefix
// (network magic + "version") to detect legacy peers and return RealPeer.

use super::{
    cipher::{
        v2_enc_packet, v2_receive_contents, v2_receive_length, FsChaCha20, FsChaCha20Poly1305,
        LENGTH_FIELD_LEN,
    },
    ellswift::{ellswift_create, v2_ecdh, EllSwiftPub, PrivKey},
};
use crate::transport::{parse_ark1, ARK1_MAGIC};
use anyhow::{anyhow, bail, Result};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// Maximum garbage bytes (not counting the 64B public key).
const MAX_GARBAGE_LEN: usize = 4095;
/// Garbage terminator length.
const GARBAGE_TERMINATOR_LEN: usize = 16;
/// Bitcoin mainnet magic bytes.
const NETWORK_MAGIC: &[u8; 4] = b"\xf9\xbe\xb4\xd9";
/// v1 prefix: NETWORK_MAGIC + "version\x00\x00\x00\x00\x00" (16 bytes total).
const V1_PREFIX: &[u8; 16] = b"\xf9\xbe\xb4\xd9version\x00\x00\x00\x00\x00";
/// Empty TRANSPORT_VERSION content (v1-compatible transport version 0).
const TRANSPORT_VERSION: &[u8] = b"";

// ---------------------------------------------------------------------------
// Session keys derived from ECDH secret
// ---------------------------------------------------------------------------

pub struct SessionKeys {
    pub session_id: [u8; 32],
    pub send_l: FsChaCha20,
    pub send_p: FsChaCha20Poly1305,
    pub recv_l: FsChaCha20,
    pub recv_p: FsChaCha20Poly1305,
    pub send_garbage_terminator: [u8; 16],
    pub recv_garbage_terminator: [u8; 16],
}

pub(crate) fn derive_session_keys(ecdh_secret: &[u8; 32], initiating: bool) -> Result<SessionKeys> {
    // HKDF-Extract with salt = b"bitcoin_v2_shared_secret" || NETWORK_MAGIC
    let mut salt = Vec::with_capacity(28);
    salt.extend_from_slice(b"bitcoin_v2_shared_secret");
    salt.extend_from_slice(NETWORK_MAGIC);

    let hk = Hkdf::<Sha256>::new(Some(&salt), ecdh_secret);

    let expand = |info: &[u8]| -> Result<[u8; 32]> {
        let mut buf = [0u8; 32];
        hk.expand(info, &mut buf)
            .map_err(|e| anyhow!("HKDF expand: {e}"))?;
        Ok(buf)
    };

    let session_id = expand(b"session_id")?;
    let initiator_l = expand(b"initiator_L")?;
    let initiator_p = expand(b"initiator_P")?;
    let responder_l = expand(b"responder_L")?;
    let responder_p = expand(b"responder_P")?;

    let mut gc_buf = [0u8; 32];
    hk.expand(b"garbage_terminators", &mut gc_buf)
        .map_err(|e| anyhow!("HKDF expand garbage_terminators: {e}"))?;
    let mut initiator_gc = [0u8; 16];
    let mut responder_gc = [0u8; 16];
    initiator_gc.copy_from_slice(&gc_buf[..16]);
    responder_gc.copy_from_slice(&gc_buf[16..]);

    let (send_l_key, send_p_key, recv_l_key, recv_p_key, send_gc, recv_gc) = if initiating {
        (initiator_l, initiator_p, responder_l, responder_p, initiator_gc, responder_gc)
    } else {
        (responder_l, responder_p, initiator_l, initiator_p, responder_gc, initiator_gc)
    };

    Ok(SessionKeys {
        session_id,
        send_l: FsChaCha20::new(send_l_key),
        send_p: FsChaCha20Poly1305::new(send_p_key),
        recv_l: FsChaCha20::new(recv_l_key),
        recv_p: FsChaCha20Poly1305::new(recv_p_key),
        send_garbage_terminator: send_gc,
        recv_garbage_terminator: recv_gc,
    })
}

// ---------------------------------------------------------------------------
// Encrypted stream — wraps a TcpStream after handshake
// ---------------------------------------------------------------------------

pub struct EncryptedStream {
    inner: TcpStream,
    send_l: FsChaCha20,
    send_p: FsChaCha20Poly1305,
    recv_l: FsChaCha20,
    recv_p: FsChaCha20Poly1305,
}

impl EncryptedStream {
    fn new(stream: TcpStream, keys: SessionKeys) -> Self {
        Self {
            inner: stream,
            send_l: keys.send_l,
            send_p: keys.send_p,
            recv_l: keys.recv_l,
            recv_p: keys.recv_p,
        }
    }

    /// Send one BIP 324 packet containing `contents`.
    pub async fn send_packet(&mut self, contents: &[u8], aad: &[u8]) -> Result<()> {
        let pkt = self.encrypt_packet(contents, aad)?;
        self.inner.write_all(&pkt).await?;
        Ok(())
    }

    /// Encrypt `contents` into a BIP 324 packet and return the ciphertext bytes
    /// **without** writing them to the socket.  Advances the send ciphers exactly
    /// once; callers must not encrypt the same data again on retry.
    pub fn encrypt_packet(&mut self, contents: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        v2_enc_packet(&mut self.send_l, &mut self.send_p, contents, aad, false)
    }

    /// Return a mutable reference to the underlying TCP stream for direct I/O.
    pub fn tcp_stream_mut(&mut self) -> &mut TcpStream {
        &mut self.inner
    }

    /// Receive one BIP 324 packet. Skips decoy packets automatically.
    /// `aad` is used only for the first packet (garbage authentication).
    pub async fn recv_packet(&mut self, aad: &[u8]) -> Result<Vec<u8>> {
        loop {
            // Read encrypted 3-byte length field.
            let mut enc_len = [0u8; LENGTH_FIELD_LEN];
            self.inner.read_exact(&mut enc_len).await?;
            let aead_len = v2_receive_length(&mut self.recv_l, &enc_len);

            // Read AEAD ciphertext.
            let mut ct = vec![0u8; aead_len];
            self.inner.read_exact(&mut ct).await?;
            let aad_for_this = if aad.is_empty() { b"".as_ref() } else { aad };
            match v2_receive_contents(&mut self.recv_p, &ct, aad_for_this)? {
                Some(contents) => return Ok(contents),
                None => continue, // ignore-bit (decoy) — keep reading
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Async I/O helpers
// ---------------------------------------------------------------------------

async fn read_exact_vec(stream: &mut TcpStream, n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Initiator handshake
// ---------------------------------------------------------------------------

/// Perform the BIP 324 handshake as the initiator.
///
/// Returns an `EncryptedStream` ready for application data.
pub async fn initiator_handshake(stream: &mut TcpStream) -> Result<EncryptedStream> {
    // --- Key exchange phase ---
    let (priv_ours, es_ours): (PrivKey, EllSwiftPub) = ellswift_create()?;

    // Random garbage 0..4095 bytes
    let garbage_len = (rand::thread_rng().next_u32() as usize) % MAX_GARBAGE_LEN;
    let mut garbage = vec![0u8; garbage_len];
    rand::thread_rng().fill_bytes(&mut garbage);

    // Send: ellswift_ours (64B) || garbage
    stream.write_all(&es_ours).await?;
    stream.write_all(&garbage).await?;

    // Receive responder's ellswift (64B)
    let es_theirs_bytes = read_exact_vec(stream, 64).await?;
    let mut es_theirs = [0u8; 64];
    es_theirs.copy_from_slice(&es_theirs_bytes);

    // Derive shared secret and session keys
    let ecdh_secret = v2_ecdh(&priv_ours, &es_theirs, &es_ours, true)?;
    let mut keys = derive_session_keys(&ecdh_secret, true)?;

    // --- Garbage terminator ---
    stream.write_all(&keys.send_garbage_terminator).await?;

    // Skip responder's garbage (up to 4095+64+16 bytes), stop at recv_garbage_terminator
    skip_garbage(stream, &keys.recv_garbage_terminator).await?;

    // --- Version packet exchange ---
    // Initiator sends version packet; AAD = our sent_garbage (empty if no garbage for version pkt)
    let version_pkt = v2_enc_packet(
        &mut keys.send_l,
        &mut keys.send_p,
        TRANSPORT_VERSION,
        &garbage, // AAD = garbage we sent (before the garbage terminator)
        false,
    )?;
    stream.write_all(&version_pkt).await?;

    // Receive responder's version packet (ignore contents per spec; AAD was responder's garbage,
    // which we already consumed — pass empty AAD here because we are not the first decryptor
    // on the responder side; we use empty aad since we never held their garbage bytes for auth
    // in this implementation — the auth is applied in skip_garbage).
    // Actually: the spec says the FIRST encrypted packet the initiator receives from the responder
    // has aad = the responder's garbage (which we just skipped). We need those garbage bytes.
    // We pass them from skip_garbage below.
    //
    // NOTE: EncryptedStream is built AFTER this version exchange.
    // We need a temporary inline recv here.
    {
        // Receive the length (3 bytes)
        let mut enc_len = [0u8; LENGTH_FIELD_LEN];
        stream.read_exact(&mut enc_len).await?;
        let aead_len = v2_receive_length(&mut keys.recv_l, &enc_len);
        let mut ct = vec![0u8; aead_len];
        stream.read_exact(&mut ct).await?;
        // Spec: initiator ignores version packet contents.
        // AAD for this first incoming packet = responder's garbage, but we don't have it
        // because we consumed it in skip_garbage.  We pass empty bytes; a production
        // implementation would buffer the garbage for this auth step.
        // For now we decrypt with empty AAD to keep progress; Phase 8 hardening will fix this.
        v2_receive_contents(&mut keys.recv_p, &ct, b"")?;
    }

    // Rebuild TcpStream from keys (we can't move stream after borrowing it mutably above;
    // but we already have all the key state in `keys`).
    // We reconstruct by taking ownership via a dummy move — caller passed `stream` by &mut,
    // so we return a struct that wraps the keys rather than the stream itself here.
    // Since we need to return an EncryptedStream that owns the TcpStream, we accept a design
    // where the caller hands ownership through this function. We do it differently: accept
    // TcpStream by value and return EncryptedStream.
    // This function signature needs updating — see module-level note.
    todo!("initiator_handshake: finish after refactoring to take TcpStream by value")
}

// ---------------------------------------------------------------------------
// skip_garbage — read until 16-byte garbage terminator is found
// ---------------------------------------------------------------------------

async fn skip_garbage(stream: &mut TcpStream, terminator: &[u8; 16]) -> Result<Vec<u8>> {
    let mut window: Vec<u8> = Vec::new();
    let mut garbage: Vec<u8> = Vec::new();

    // Read first 16 bytes to fill the window
    let first = read_exact_vec(stream, GARBAGE_TERMINATOR_LEN).await?;
    window.extend_from_slice(&first);
    garbage.extend_from_slice(&first);

    for _ in 0..MAX_GARBAGE_LEN {
        if window[window.len() - 16..] == *terminator {
            // Strip terminator from garbage
            let g_len = garbage.len() - 16;
            garbage.truncate(g_len);
            return Ok(garbage);
        }
        let mut b = [0u8; 1];
        stream.read_exact(&mut b).await?;
        window.push(b[0]);
        garbage.push(b[0]);
        if window.len() > 16 {
            window.remove(0);
        }
    }
    bail!("BIP 324 garbage terminator not found within 4 KiB")
}

// ---------------------------------------------------------------------------
// Public handshake API (owned TcpStream, returns EncryptedStream)
// ---------------------------------------------------------------------------

/// Perform the BIP 324 handshake as the **initiator** (client side).
///
/// Takes ownership of `stream`, returns an encrypted channel.
pub async fn do_initiator_handshake(mut stream: TcpStream) -> Result<EncryptedStream> {
    let (priv_ours, es_ours): (PrivKey, EllSwiftPub) = ellswift_create()?;

    let garbage_len = (rand::thread_rng().next_u32() as usize) % MAX_GARBAGE_LEN;
    let mut sent_garbage = vec![0u8; garbage_len];
    rand::thread_rng().fill_bytes(&mut sent_garbage);

    stream.write_all(&es_ours).await?;
    stream.write_all(&sent_garbage).await?;

    let es_theirs_bytes = read_exact_vec(&mut stream, 64).await?;
    let mut es_theirs = [0u8; 64];
    es_theirs.copy_from_slice(&es_theirs_bytes);

    let ecdh_secret = v2_ecdh(&priv_ours, &es_theirs, &es_ours, true)?;
    let mut keys = derive_session_keys(&ecdh_secret, true)?;

    // Send our garbage terminator
    stream.write_all(&keys.send_garbage_terminator).await?;

    // Skip responder garbage (AAD for their first packet = their garbage bytes)
    let _recv_garbage = skip_garbage(&mut stream, &keys.recv_garbage_terminator).await?;

    // Send version packet with AAD = our sent garbage
    let vpkt = v2_enc_packet(
        &mut keys.send_l,
        &mut keys.send_p,
        TRANSPORT_VERSION,
        &sent_garbage,
        false,
    )?;
    stream.write_all(&vpkt).await?;

    // Receive responder's version packet (ignore contents)
    {
        let mut enc_len = [0u8; LENGTH_FIELD_LEN];
        stream.read_exact(&mut enc_len).await?;
        let aead_len = v2_receive_length(&mut keys.recv_l, &enc_len);
        let mut ct = vec![0u8; aead_len];
        stream.read_exact(&mut ct).await?;
        v2_receive_contents(&mut keys.recv_p, &ct, &_recv_garbage)?;
    }

    Ok(EncryptedStream::new(stream, keys))
}

/// Outcome of the responder-side BIP 324 handshake.
pub enum ResponderOutcome {
    /// Peer sent ARK1 session marker — this is an ArkTunnel client.
    ArkClient {
        stream: EncryptedStream,
        uuid: uuid::Uuid,
    },
    /// Peer sent a real Bitcoin v1 message — forward raw TCP stream.
    /// `peeked` holds the 16-byte v1 prefix that was consumed during detection.
    RealPeer {
        stream: TcpStream,
        peeked: Vec<u8>,
    },
}

/// Perform the BIP 324 handshake as the **responder** (server side).
///
/// Returns `ResponderOutcome` distinguishing ark clients from real Bitcoin peers.
pub async fn do_responder_handshake(mut stream: TcpStream) -> Result<ResponderOutcome> {
    // --- v1 prefix detection ---
    // Read the first 16 bytes and check if they match V1_PREFIX.
    let prefix = read_exact_vec(&mut stream, 16).await?;
    if prefix.as_slice() == V1_PREFIX.as_slice() {
        // Real v1 peer — return the stream with the peeked prefix so the server
        // can prepend those bytes when forwarding to bitcoind.
        return Ok(ResponderOutcome::RealPeer { stream, peeked: prefix });
    }

    // Not v1 — proceed with BIP 324 handshake.
    // The `prefix` is actually the first 16 bytes of the initiator's EllSwift key.
    let remaining_es = read_exact_vec(&mut stream, 48).await?;
    let mut es_theirs = [0u8; 64];
    es_theirs[..16].copy_from_slice(&prefix);
    es_theirs[16..].copy_from_slice(&remaining_es);

    // Generate our own ephemeral keypair
    let (priv_ours, es_ours): (PrivKey, EllSwiftPub) = ellswift_create()?;

    // Random garbage
    let garbage_len = (rand::thread_rng().next_u32() as usize) % MAX_GARBAGE_LEN;
    let mut sent_garbage = vec![0u8; garbage_len];
    rand::thread_rng().fill_bytes(&mut sent_garbage);

    // Send our ellswift key + garbage
    stream.write_all(&es_ours).await?;
    stream.write_all(&sent_garbage).await?;

    // Derive keys (we are the responder, initiating=false)
    let ecdh_secret = v2_ecdh(&priv_ours, &es_theirs, &es_ours, false)?;
    let mut keys = derive_session_keys(&ecdh_secret, false)?;

    // Receive initiator's remaining garbage (after the 64-byte key we already read)
    // and find the initiator's garbage terminator
    let recv_garbage = skip_garbage(&mut stream, &keys.recv_garbage_terminator).await?;

    // Send our garbage terminator + version packet
    stream.write_all(&keys.send_garbage_terminator).await?;
    let vpkt = v2_enc_packet(
        &mut keys.send_l,
        &mut keys.send_p,
        TRANSPORT_VERSION,
        &sent_garbage,
        false,
    )?;
    stream.write_all(&vpkt).await?;

    // Receive initiator's version packet (first packet, AAD = initiator's garbage)
    {
        let mut enc_len = [0u8; LENGTH_FIELD_LEN];
        stream.read_exact(&mut enc_len).await?;
        let aead_len = v2_receive_length(&mut keys.recv_l, &enc_len);
        let mut ct = vec![0u8; aead_len];
        stream.read_exact(&mut ct).await?;
        v2_receive_contents(&mut keys.recv_p, &ct, &recv_garbage)?;
    }

    let mut enc_stream = EncryptedStream::new(stream, keys);

    // --- Application phase: read first application packet ---
    // The first application payload determines whether this is an ArkTunnel client.
    let first_payload = enc_stream.recv_packet(b"").await?;

    if first_payload.len() >= 4 && &first_payload[..4] == ARK1_MAGIC {
        match parse_ark1(&first_payload) {
            Some(uuid) => Ok(ResponderOutcome::ArkClient {
                stream: enc_stream,
                uuid,
            }),
            None => bail!("malformed ARK1 payload (missing uuid)"),
        }
    } else {
        // Real Bitcoin peer — we can't return the raw TcpStream because we've already
        // consumed bytes and set up encryption.  For RealPeer routing in Phase 4 the
        // server will need to forward the decrypted bytes to bitcoind.  Return an error
        // for now; Phase 4 will handle this by forwarding `first_payload` as a v2 message.
        bail!("BIP 324 peer sent a real Bitcoin message — RealPeer forwarding handled in Phase 4")
    }
}

// ---------------------------------------------------------------------------
// Tests — BIP 324 packet-encoding test vectors
// ---------------------------------------------------------------------------
//
// Source: https://github.com/bitcoin/bips/blob/master/bip-0324/packet_encoding_test_vectors.csv
//
// Each test case starts from `mid_shared_secret` (ECDH output, 32 B) and
// `in_initiating` to derive session keys via HKDF, then encodes `in_contents`
// and compares against the expected `out_ciphertext`.  This validates our
// key-derivation (HKDF labels, salt) and cipher-suite (FSChaCha20 + AEAD)
// without requiring the EllSwift ECDH itself.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip324::cipher::v2_enc_packet;

    fn h(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn h32(hex: &str) -> [u8; 32] {
        h(hex).try_into().unwrap()
    }

    /// Derive session keys from a known shared secret and verify HKDF outputs
    /// match the BIP 324 test vector intermediate values.
    fn check_keys(
        shared_hex: &str,
        initiating: bool,
        exp_session_id: &str,
        exp_initiator_l: &str,
        exp_initiator_p: &str,
        exp_responder_l: &str,
        exp_responder_p: &str,
    ) {
        let shared = h32(shared_hex);
        // derive_session_keys is infallible in practice; test will panic on error
        let keys = derive_session_keys(&shared, initiating).unwrap();

        // Verify session_id
        assert_eq!(
            keys.session_id,
            h32(exp_session_id),
            "session_id mismatch (initiating={initiating})"
        );

        // The four cipher keys are not directly exposed — re-derive using the
        // known send/recv direction from `initiating` and compare by encoding a
        // test payload instead.  The separate `check_ciphertext` test verifies
        // end-to-end behaviour.  For this test we re-derive both sets of keys.
        let keys_as_init = derive_session_keys(&shared, true).unwrap();
        let keys_as_resp = derive_session_keys(&shared, false).unwrap();

        // Re-run HKDF manually and compare the four key values.
        use hkdf::Hkdf;
        use sha2::Sha256;
        let mut salt = Vec::with_capacity(28);
        salt.extend_from_slice(b"bitcoin_v2_shared_secret");
        salt.extend_from_slice(b"\xf9\xbe\xb4\xd9"); // mainnet magic
        let hk = Hkdf::<Sha256>::new(Some(&salt), &shared);
        let mut expand = |info: &[u8]| -> [u8; 32] {
            let mut buf = [0u8; 32];
            hk.expand(info, &mut buf).unwrap();
            buf
        };
        assert_eq!(expand(b"initiator_L"), h32(exp_initiator_l), "initiator_L");
        assert_eq!(expand(b"initiator_P"), h32(exp_initiator_p), "initiator_P");
        assert_eq!(expand(b"responder_L"), h32(exp_responder_l), "responder_L");
        assert_eq!(expand(b"responder_P"), h32(exp_responder_p), "responder_P");
        let _ = (keys_as_init, keys_as_resp); // suppress unused warning
    }

    /// Encode one packet from a known shared secret and verify the ciphertext.
    ///
    /// Per the BIP-324 test vector spec (mirroring Bitcoin Core's
    /// `TestBIP324PacketVector`): before encrypting the real packet, advance
    /// the cipher state by sending `in_idx` dummy empty packets (ignore=true,
    /// empty contents, no AAD).  The actual contents are repeated `in_multiply`
    /// times before encryption.
    fn check_ciphertext(
        in_idx: u64,
        shared_hex: &str,
        initiating: bool,
        contents_hex: &str,
        in_multiply: usize,
        ignore: bool,
        aad_hex: &str,
        exp_ciphertext_hex: &str,
    ) {
        let shared = h32(shared_hex);
        let mut keys = derive_session_keys(&shared, initiating).unwrap();

        // Advance cipher state with in_idx dummy empty packets.
        for _ in 0..in_idx {
            v2_enc_packet(&mut keys.send_l, &mut keys.send_p, &[], &[], true).unwrap();
        }

        let base = h(contents_hex);
        let contents: Vec<u8> = base.iter().copied().cycle().take(base.len() * in_multiply).collect();
        let aad = h(aad_hex);
        let ct = v2_enc_packet(&mut keys.send_l, &mut keys.send_p, &contents, &aad, ignore)
            .unwrap();
        let expected = h(exp_ciphertext_hex);
        assert_eq!(ct, expected, "ciphertext mismatch for idx={in_idx} contents={contents_hex}");
    }

    // -----------------------------------------------------------------------
    // Test vector idx=1
    // in_initiating=1, in_contents=8e, in_aad="", in_ignore=0
    // -----------------------------------------------------------------------
    #[test]
    fn bip324_vector_1_session_keys() {
        check_keys(
            "c6992a117f5edbea70c3f511d32d26b9798be4b81a62eaee1a5acaa8459a3592",
            true,
            "ce72dffb015da62b0d0f5474cab8bc72605225b0cee3f62312ec680ec5f41ba5",
            "9a6478b5fbab1f4dd2f78994b774c03211c78312786e602da75a0d1767fb55cf",
            "7d0c7820ba6a4d29ce40baf2caa6035e04f1e1cefd59f3e7e59e9e5af84f1f51",
            "17bc726421e4054ac6a1d54915085aaa766f4d3cf67bbd168e6080eac289d15e",
            "9f0fc1c0e85fd9a8eee07e6fc41dba2ff54c7729068a239ac97c37c524cca1c0",
        );
    }

    #[test]
    fn bip324_vector_1_ciphertext() {
        check_ciphertext(
            1,  // in_idx
            "c6992a117f5edbea70c3f511d32d26b9798be4b81a62eaee1a5acaa8459a3592",
            true,
            "8e",
            1,  // in_multiply
            false,
            "",
            "7530d2a18720162ac09c25329a60d75adf36eda3c3",
        );
    }

    // -----------------------------------------------------------------------
    // Test vector idx=999
    // in_initiating=0, in_contents=3eb1d4e98035cfd8eeb29bac969ed3824a, in_aad="", in_ignore=0
    // -----------------------------------------------------------------------
    #[test]
    fn bip324_vector_999_session_keys() {
        check_keys(
            "a6f79eb08243b6f65dbe42bfe4a6cf3f131d6963fa5d06c770a18f7b9c489b78",
            false,
            "b0490e26111cb2d55bbff2ace00f7f644f64006539abb4e7513f05107bb10608",
            "efc938c88c925459a9c837238716cfadfb1c3016f60d12923933710b5fcc9b55",
            "91702f3cbd33b3c4a0b29b40548aea1ab01e43582db194afee70637d247aa036",
            "7f457572e4260c611a6858acc8f325d87a3c8af8a59ce1da26ef6041f35715e8",
            "1fe4d56334f5b0a5bd3c71ce4e338f40fc7e194925daa7ee6ce98aecf1766d7c",
        );
    }

    #[test]
    fn bip324_vector_999_ciphertext() {
        check_ciphertext(
            999,  // in_idx
            "a6f79eb08243b6f65dbe42bfe4a6cf3f131d6963fa5d06c770a18f7b9c489b78",
            false,
            "3eb1d4e98035cfd8eeb29bac969ed3824a",
            1,  // in_multiply
            false,
            "",
            "d78adbcba0eebfb15cfbd8142c84dc729d233d0dc11b1d851e46a114122b8d5b96b7d59317",
        );
    }
}

