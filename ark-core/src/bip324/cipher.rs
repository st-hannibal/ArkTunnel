// BIP 324 packet cipher suite.
//
// Two primitives are used:
//
//   FSChaCha20          — forward-secret stream cipher for the 3-byte
//                         packet-length field. Rekeyed every 224 chunks.
//
//   FSChaCha20Poly1305  — forward-secret AEAD for packet content.
//                         Rekeyed every 224 messages.
//
// Both are defined in BIP 324 Section "Packet Encryption".
// The spec's Python pseudocode is translated directly; all variable
// names mirror the spec for easy auditing.

use anyhow::{anyhow, Result};
use chacha20::{
    cipher::{KeyIvInit, StreamCipher, StreamCipherSeek},
    ChaCha20,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};

// REKEY_INTERVAL = 224 (per BIP 324 specification)
const REKEY_INTERVAL: u64 = 224;

/// Packet-length field length (bytes).
pub const LENGTH_FIELD_LEN: usize = 3;
/// AEAD expansion (Poly1305 tag).
pub const CHACHA20POLY1305_EXPANSION: usize = 16;
/// Header length: 1 byte (ignore bit in highest bit).
pub const HEADER_LEN: usize = 1;
/// Bit position of the ignore flag.
pub const IGNORE_BIT_POS: u8 = 7;

// ---------------------------------------------------------------------------
// FSChaCha20 — stream cipher for length fields
// ---------------------------------------------------------------------------

/// Rekeying wrapper stream cipher around ChaCha20.
///
/// Encrypts/decrypts 3-byte length chunks; rekeyed every `REKEY_INTERVAL`
/// chunks by consuming the next 32 bytes of the key stream as the new key.
pub struct FsChaCha20 {
    key: [u8; 32],
    /// Count of individual `crypt()` invocations (chunks).
    chunk_counter: u64,
    /// How many block outputs have been produced for the current batch.
    block_counter: u32,
    /// Buffered key-stream bytes not yet consumed.
    keystream: Vec<u8>,
}

impl FsChaCha20 {
    pub fn new(initial_key: [u8; 32]) -> Self {
        Self {
            key: initial_key,
            chunk_counter: 0,
            block_counter: 0,
            keystream: Vec::new(),
        }
    }

    /// Fill internal keystream buffer until at least `nbytes` bytes are ready.
    fn fill_keystream(&mut self, nbytes: usize) {
        while self.keystream.len() < nbytes {
            // nonce = LE32(0) || LE64(rekeyings_done)
            let rekeyings = self.chunk_counter / REKEY_INTERVAL;
            let mut nonce = [0u8; 12];
            nonce[4..12].copy_from_slice(&rekeyings.to_le_bytes());

            // Produce one 64-byte block using the current block_counter.
            let mut block = [0u8; 64];
            let mut cipher = ChaCha20::new(
                (&self.key).into(),
                (&nonce).into(),
            );
            cipher.seek(self.block_counter as u64 * 64);
            cipher.apply_keystream(&mut block);
            self.block_counter += 1;
            self.keystream.extend_from_slice(&block);
        }
    }

    fn get_keystream_bytes(&mut self, nbytes: usize) -> Vec<u8> {
        self.fill_keystream(nbytes);
        self.keystream.drain(..nbytes).collect()
    }

    /// XOR `chunk` with key-stream bytes, advancing counter and rekeying if needed.
    pub fn crypt(&mut self, chunk: &[u8]) -> Vec<u8> {
        let ks = self.get_keystream_bytes(chunk.len());
        let ret: Vec<u8> = ks.iter().zip(chunk).map(|(k, c)| k ^ c).collect();

        // Rekey after every REKEY_INTERVAL chunks.
        if (self.chunk_counter + 1) % REKEY_INTERVAL == 0 {
            self.key = self.get_keystream_bytes(32).try_into().unwrap();
            self.block_counter = 0;
        }
        self.chunk_counter += 1;
        ret
    }
}

// ---------------------------------------------------------------------------
// FSChaCha20Poly1305 — AEAD for packet content
// ---------------------------------------------------------------------------

/// Rekeying wrapper AEAD around ChaCha20Poly1305.
///
/// One instance is used exclusively for encryption OR decryption (never both).
/// Rekeyed every `REKEY_INTERVAL` messages.
pub struct FsChaCha20Poly1305 {
    key: [u8; 32],
    packet_counter: u64,
}

impl FsChaCha20Poly1305 {
    pub fn new(initial_key: [u8; 32]) -> Self {
        Self {
            key: initial_key,
            packet_counter: 0,
        }
    }

    fn build_nonce(&self, counter_in_interval: u64, rekeyings: u64) -> [u8; 12] {
        // nonce = LE32(counter_in_interval) || LE64(rekeyings)
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&(counter_in_interval as u32).to_le_bytes());
        nonce[4..12].copy_from_slice(&rekeyings.to_le_bytes());
        nonce
    }

    /// Encrypt `plaintext` with associated data `aad`.
    /// Returns ciphertext (plaintext.len() + 16 bytes).
    pub fn encrypt(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let counter_in_interval = self.packet_counter % REKEY_INTERVAL;
        let rekeyings = self.packet_counter / REKEY_INTERVAL;
        let nonce_bytes = self.build_nonce(counter_in_interval, rekeyings);

        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|e| anyhow!("cipher init: {e}"))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, Payload { msg: plaintext, aad })
            .map_err(|e| anyhow!("encrypt: {e}"))?;

        self.maybe_rekey();
        Ok(ct)
    }

    /// Decrypt `ciphertext` with associated data `aad`.
    /// Returns plaintext or error if authentication fails.
    pub fn decrypt(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let counter_in_interval = self.packet_counter % REKEY_INTERVAL;
        let rekeyings = self.packet_counter / REKEY_INTERVAL;
        let nonce_bytes = self.build_nonce(counter_in_interval, rekeyings);

        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|e| anyhow!("cipher init: {e}"))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let pt = cipher
            .decrypt(nonce, Payload { msg: ciphertext, aad })
            .map_err(|_| anyhow!("AEAD authentication failure"))?;

        self.maybe_rekey();
        Ok(pt)
    }

    fn maybe_rekey(&mut self) {
        // At the end of each REKEY_INTERVAL, encrypt 32 zero bytes with the
        // special rekey nonce (0xFFFFFFFF || LE64(rekeyings)) and use the
        // first 32 bytes as the new key.
        if (self.packet_counter + 1) % REKEY_INTERVAL == 0 {
            let rekeyings = self.packet_counter / REKEY_INTERVAL;
            let mut rekey_nonce = [0u8; 12];
            rekey_nonce[0..4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
            rekey_nonce[4..12].copy_from_slice(&rekeyings.to_le_bytes());

            let cipher = ChaCha20Poly1305::new_from_slice(&self.key).expect("rekey");
            let nonce = Nonce::from_slice(&rekey_nonce);
            let zeros = [0u8; 32];
            let new_key_ct = cipher
                .encrypt(nonce, Payload { msg: &zeros, aad: b"" })
                .expect("rekey encrypt");
            self.key.copy_from_slice(&new_key_ct[..32]);
        }
        self.packet_counter += 1;
    }
}

// ---------------------------------------------------------------------------
// Packet encode / decode (stateless helpers used by the handshake)
// ---------------------------------------------------------------------------

/// Encode one BIP 324 packet using the given send ciphers.
///
/// Wire format: `enc_len (3B) || aead_ciphertext (1 + contents.len() + 16 B)`
pub fn v2_enc_packet(
    send_l: &mut FsChaCha20,
    send_p: &mut FsChaCha20Poly1305,
    contents: &[u8],
    aad: &[u8],
    ignore: bool,
) -> Result<Vec<u8>> {
    assert!(
        contents.len() <= (1 << 24) - 1,
        "contents too large for BIP 324 packet"
    );
    let header: u8 = if ignore { 1 << IGNORE_BIT_POS } else { 0 };
    let plaintext: Vec<u8> = std::iter::once(header).chain(contents.iter().copied()).collect();
    let aead_ct = send_p.encrypt(aad, &plaintext)?;

    let len_bytes = (contents.len() as u32).to_le_bytes();
    let enc_len = send_l.crypt(&len_bytes[..3]);

    let mut packet = Vec::with_capacity(3 + aead_ct.len());
    packet.extend_from_slice(&enc_len);
    packet.extend_from_slice(&aead_ct);
    Ok(packet)
}

/// Decode the *length* portion of a BIP 324 packet (first 3 bytes).
///
/// Returns the number of bytes in the AEAD ciphertext that follow
/// (`HEADER_LEN + contents_len + CHACHA20POLY1305_EXPANSION`).
pub fn v2_receive_length(recv_l: &mut FsChaCha20, enc_len: &[u8; 3]) -> usize {
    let dec = recv_l.crypt(enc_len);
    let mut buf = [0u8; 4];
    buf[..3].copy_from_slice(&dec);
    let contents_len = u32::from_le_bytes(buf) as usize;
    HEADER_LEN + contents_len + CHACHA20POLY1305_EXPANSION
}

/// Authenticate and unwrap the AEAD portion of a BIP 324 packet.
///
/// Returns `Ok(Some(contents))` for a normal packet, `Ok(None)` for an
/// ignore-bit (decoy) packet. Returns `Err` on authentication failure.
pub fn v2_receive_contents(
    recv_p: &mut FsChaCha20Poly1305,
    aead_ct: &[u8],
    aad: &[u8],
) -> Result<Option<Vec<u8>>> {
    let plaintext = recv_p.decrypt(aad, aead_ct)?;
    let header = plaintext[0];
    if header & (1 << IGNORE_BIT_POS) != 0 {
        return Ok(None); // decoy packet — skip
    }
    Ok(Some(plaintext[HEADER_LEN..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_key() -> [u8; 32] {
        [0u8; 32]
    }

    #[test]
    fn fschacha20_encrypt_decrypt_roundtrip() {
        let mut enc = FsChaCha20::new(zero_key());
        let mut dec = FsChaCha20::new(zero_key());
        let msg = b"hello BIP 324 length field";
        let ct = enc.crypt(msg);
        let pt = dec.crypt(&ct);
        assert_eq!(pt, msg);
    }

    #[test]
    fn fschacha20poly1305_roundtrip() {
        let mut enc = FsChaCha20Poly1305::new(zero_key());
        let mut dec = FsChaCha20Poly1305::new(zero_key());
        let msg = b"application payload";
        let aad = b"garbage_here";
        let ct = enc.encrypt(aad, msg).unwrap();
        let pt = dec.decrypt(aad, &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn fschacha20poly1305_wrong_aad_fails() {
        let mut enc = FsChaCha20Poly1305::new(zero_key());
        let mut dec = FsChaCha20Poly1305::new(zero_key());
        let ct = enc.encrypt(b"aad", b"data").unwrap();
        assert!(dec.decrypt(b"wrong_aad", &ct).is_err());
    }

    #[test]
    fn packet_encode_decode_roundtrip() {
        let key = zero_key();
        let mut sl = FsChaCha20::new(key);
        let mut sp = FsChaCha20Poly1305::new(key);
        let mut rl = FsChaCha20::new(key);
        let mut rp = FsChaCha20Poly1305::new(key);

        let contents = b"test packet contents";
        let pkt = v2_enc_packet(&mut sl, &mut sp, contents, b"aad", false).unwrap();

        let enc_len: [u8; 3] = pkt[..3].try_into().unwrap();
        let aead_len = v2_receive_length(&mut rl, &enc_len);
        assert_eq!(aead_len, pkt.len() - 3);

        let result = v2_receive_contents(&mut rp, &pkt[3..], b"aad").unwrap();
        assert_eq!(result.as_deref(), Some(contents.as_ref()));
    }

    #[test]
    fn ignore_bit_packet_returns_none() {
        let key = zero_key();
        let mut sl = FsChaCha20::new(key);
        let mut sp = FsChaCha20Poly1305::new(key);
        let mut rl = FsChaCha20::new(key);
        let mut rp = FsChaCha20Poly1305::new(key);

        let pkt = v2_enc_packet(&mut sl, &mut sp, b"decoy", b"", true).unwrap();
        let enc_len: [u8; 3] = pkt[..3].try_into().unwrap();
        let _ = v2_receive_length(&mut rl, &enc_len);
        let result = v2_receive_contents(&mut rp, &pkt[3..], b"").unwrap();
        assert!(result.is_none(), "ignore-bit packet must return None");
    }
}
