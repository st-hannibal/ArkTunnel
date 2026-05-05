// RLPx frame encoding / decryption.
//
// Frame layout (per devp2p spec):
//   header-ciphertext (16B) || header-mac (16B)
//   frame-ciphertext  (N bytes, padded to 16B multiple) || frame-mac (16B)
//
// AES-256-CTR (stateful across frames, IV = 0x00*16) for payload.
// Keccak256-based running MAC (separate for each direction) for authentication.
//
// Header format (plaintext, before encryption):
//   frame-size (3B BE) || capability-id (1B=0) || context-id (1B=0) || zeros[11]

use aes::{
    Aes256,
    cipher::{BlockEncrypt, KeyInit, KeyIvInit, StreamCipher},
};
use ctr::Ctr128BE;
use sha3::{Digest, Keccak256};
use anyhow::{bail, Result};

type Aes256Ctr = Ctr128BE<Aes256>;
// Block<Aes256> = GenericArray<u8, U16>; use AES block size directly.
type AesBlock = aes::cipher::Block<Aes256>;

/// Running MAC + AES-CTR state for one direction of an RLPx connection.
pub struct FrameState {
    pub(crate) aes_ctr: Aes256Ctr,
    pub(crate) mac_aes: Aes256,
    pub(crate) mac_state: Keccak256,
}

impl FrameState {
    /// Create a new FrameState.
    ///
    /// `mac_init` is the data used to initialize the running MAC state:
    ///   for egress-mac: `xor32(mac-secret, remote-nonce) || sent-ciphertext`
    ///   for ingress-mac: `xor32(mac-secret, local-nonce) || received-ciphertext`
    pub fn new(
        aes_secret: &[u8; 32],
        mac_secret: &[u8; 32],
        mac_init: &[u8],
    ) -> Result<Self> {
        let iv = [0u8; 16];
        let aes_ctr = Aes256Ctr::new_from_slices(aes_secret, &iv)
            .map_err(|e| anyhow::anyhow!("FrameState AES-CTR: {e}"))?;
        let mac_aes = Aes256::new_from_slice(mac_secret)
            .map_err(|e| anyhow::anyhow!("FrameState MAC AES: {e}"))?;
        let mut mac_state = Keccak256::new();
        mac_state.update(mac_init);
        Ok(Self { aes_ctr, mac_aes, mac_state })
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Encode `data` as one RLPx frame. Returns complete wire bytes.
pub fn encode_frame(data: &[u8], st: &mut FrameState) -> Vec<u8> {
    // Build 16-byte header: frame-size (3B BE) || zeros
    let frame_size = data.len();
    let mut header = [0u8; 16];
    header[0] = (frame_size >> 16) as u8;
    header[1] = (frame_size >> 8) as u8;
    header[2] = frame_size as u8;

    // Encrypt header (AES-256-CTR, advances the keystream by 16 bytes)
    st.aes_ctr.apply_keystream(&mut header);

    // Compute header-mac and update egress MAC state
    let h_mac = header_mac(&mut st.mac_state, &st.mac_aes, &header);

    // Pad frame data to 16-byte multiple
    let padded_len = (frame_size + 15) & !15;
    let mut frame = vec![0u8; padded_len];
    frame[..frame_size].copy_from_slice(data);

    // Encrypt frame (continues the same AES-256-CTR keystream)
    st.aes_ctr.apply_keystream(&mut frame);

    // Compute frame-mac: first update MAC with the encrypted frame, then finalize seed
    st.mac_state.update(&frame);
    let f_mac = frame_mac(&mut st.mac_state, &st.mac_aes);

    // Assemble: header-ct(16) | header-mac(16) | frame-ct(N) | frame-mac(16)
    let mut out = Vec::with_capacity(32 + padded_len + 16);
    out.extend_from_slice(&header);
    out.extend_from_slice(&h_mac);
    out.extend_from_slice(&frame);
    out.extend_from_slice(&f_mac);
    out
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Decode and authenticate a frame header.
///
/// `wire` must be exactly 32 bytes: `header-ciphertext (16B) || header-mac (16B)`.
/// Returns the plaintext frame-data length on success.
pub fn decode_frame_header(wire: &[u8; 32], st: &mut FrameState) -> Result<usize> {
    let header_ct: &[u8; 16] = wire[..16].try_into().unwrap();
    let expected_mac: [u8; 16] = wire[16..].try_into().unwrap();

    // Verify header MAC (updates ingress MAC state)
    let computed = header_mac(&mut st.mac_state, &st.mac_aes, header_ct);
    if computed != expected_mac {
        bail!("RLPx: header MAC mismatch");
    }

    // Decrypt header
    let mut header = *header_ct;
    st.aes_ctr.apply_keystream(&mut header);

    let frame_size = ((header[0] as usize) << 16)
        | ((header[1] as usize) << 8)
        | (header[2] as usize);
    Ok(frame_size)
}

/// Decode and authenticate frame body.
///
/// `wire` is `frame-ciphertext (padded to 16B multiple) || frame-mac (16B)`.
/// Returns plaintext truncated to `frame_size`.
pub fn decode_frame_data(
    wire: &[u8],
    frame_size: usize,
    st: &mut FrameState,
) -> Result<Vec<u8>> {
    if wire.len() < 16 {
        bail!("RLPx: frame data too short");
    }
    let padded_len = wire.len() - 16;
    let frame_ct = &wire[..padded_len];
    let expected_mac: [u8; 16] = wire[padded_len..].try_into().unwrap();

    // Update MAC with frame ciphertext, then compute frame-mac
    st.mac_state.update(frame_ct);
    let computed = frame_mac(&mut st.mac_state, &st.mac_aes);
    if computed != expected_mac {
        bail!("RLPx: frame MAC mismatch");
    }

    // Decrypt
    let mut pt = frame_ct.to_vec();
    st.aes_ctr.apply_keystream(&mut pt);
    pt.truncate(frame_size);
    Ok(pt)
}

// ---------------------------------------------------------------------------
// MAC helpers (devp2p spec)
// ---------------------------------------------------------------------------

/// Header-MAC:
///   seed = AES256-ECB(mac-secret, mac-state.digest[:16]) XOR header-ct[:16]
///   mac-state.update(seed)
///   return mac-state.digest[:16]
fn header_mac(
    mac_state: &mut Keccak256,
    mac_aes: &Aes256,
    header_ct: &[u8; 16],
) -> [u8; 16] {
    let digest = keccak_digest16(mac_state);
    let aes_out = aes_ecb16(mac_aes, &digest);
    let mut seed = [0u8; 16];
    for i in 0..16 {
        seed[i] = aes_out[i] ^ header_ct[i];
    }
    mac_state.update(seed);
    keccak_digest16(mac_state)
}

/// Frame-MAC (call AFTER mac-state.update(frame-ct)):
///   seed = mac-state.digest[:16] XOR AES256-ECB(mac-secret, mac-state.digest[:16])
///   mac-state.update(seed)
///   return mac-state.digest[:16]
fn frame_mac(mac_state: &mut Keccak256, mac_aes: &Aes256) -> [u8; 16] {
    let digest = keccak_digest16(mac_state);
    let aes_out = aes_ecb16(mac_aes, &digest);
    let mut seed = [0u8; 16];
    for i in 0..16 {
        seed[i] = digest[i] ^ aes_out[i];
    }
    mac_state.update(seed);
    keccak_digest16(mac_state)
}

/// Get first 16 bytes of the current Keccak256 digest (non-destructive clone).
fn keccak_digest16(state: &Keccak256) -> [u8; 16] {
    let d = state.clone().finalize();
    d[..16].try_into().unwrap()
}

/// AES-256-ECB encrypt a single 16-byte block (no chaining, pure block cipher).
fn aes_ecb16(aes: &Aes256, block_in: &[u8; 16]) -> [u8; 16] {
    let mut block = AesBlock::default();
    block.copy_from_slice(block_in);
    aes.encrypt_block(&mut block);
    block[..16].try_into().unwrap()
}
