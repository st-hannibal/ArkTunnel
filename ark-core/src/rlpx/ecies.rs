// RLPx ECIES encryption/decryption (devp2p variant).
//
// KDF   : NIST SP 800-56A ConcatKDF, SHA-256, counter = 1, no OtherInfo.
//          Output 32 bytes → kE (first 16B) + kM (last 16B).
// Enc   : AES-128-CTR(kE, IV, message).
// MAC   : HMAC-SHA256(SHA256(kM), IV || ciphertext).
// Wire  : 04||R.x||R.y (65B) || IV (16B) || ciphertext || HMAC (32B).
//
// Note on ECDH: uses raw x-coordinate of the shared point, NOT a hashed form.
// secp256k1::ecdh::shared_secret_point() returns 64B: x || y (no 04 prefix).

use aes::{Aes128, cipher::{KeyIvInit, StreamCipher}};
use ctr::Ctr128BE;
use hmac::{Hmac, Mac};
use rand::RngCore;
use secp256k1::{ecdh::shared_secret_point, PublicKey, SecretKey, SECP256K1};
use sha2::{Digest, Sha256};
use anyhow::{anyhow, bail, Result};

type Aes128Ctr = Ctr128BE<Aes128>;
type HmacSha256 = Hmac<Sha256>;

/// ECIES wire overhead: 65 (ephemeral pubkey) + 16 (IV) + 32 (HMAC) = 113 bytes.
pub const ECIES_OVERHEAD: usize = 113;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Encrypt `message` to `recipient_pub` using devp2p ECIES.
///
/// `aad` is optional additional authenticated data included in the HMAC but
/// NOT transmitted — used by EIP-8 which includes the 2-byte size prefix.
pub fn ecies_encrypt(recipient_pub: &PublicKey, message: &[u8]) -> Result<Vec<u8>> {
    ecies_encrypt_with_aad(recipient_pub, message, b"")
}

/// EIP-8 variant: includes `aad` bytes in the HMAC alongside IV||ciphertext.
pub fn ecies_encrypt_with_aad(
    recipient_pub: &PublicKey,
    message: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    // Ephemeral key pair
    let ek = SecretKey::new(&mut rand::thread_rng());
    let ek_pub = PublicKey::from_secret_key(SECP256K1, &ek);

    // ECDH: z = x-coordinate of ek * recipient_pub
    let xy = shared_secret_point(recipient_pub, &ek); // 64B: x || y
    let z: [u8; 32] = xy[..32].try_into().unwrap();

    let (ke, km) = concat_kdf(&z);

    // Random IV
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    // AES-128-CTR encryption
    let mut ct = message.to_vec();
    Aes128Ctr::new_from_slices(&ke, &iv)
        .map_err(|e| anyhow!("ECIES AES init: {e}"))?
        .apply_keystream(&mut ct);

    // HMAC-SHA256(SHA256(kM), aad || IV || ciphertext)
    // For the standard (no-AAD) case aad is empty, so this is backward-compatible.
    let km_hash: [u8; 32] = Sha256::digest(km).as_slice().try_into().unwrap();
    let mut mac = HmacSha256::new_from_slice(&km_hash)
        .map_err(|e| anyhow!("ECIES HMAC init: {e}"))?;
    if !aad.is_empty() {
        mac.update(aad);
    }
    mac.update(&iv);
    mac.update(&ct);
    let tag = mac.finalize().into_bytes();

    // Wire: 04||R.x||R.y || IV || ciphertext || HMAC
    let mut out = Vec::with_capacity(65 + 16 + ct.len() + 32);
    out.extend_from_slice(&ek_pub.serialize_uncompressed()); // 65B
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Decrypt devp2p ECIES ciphertext with `our_priv`.
pub fn ecies_decrypt(our_priv: &SecretKey, data: &[u8]) -> Result<Vec<u8>> {
    ecies_decrypt_with_aad(our_priv, data, b"")
}

/// EIP-8 variant: `aad` bytes are included in HMAC verification (not transmitted).
pub fn ecies_decrypt_with_aad(
    our_priv: &SecretKey,
    data: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    if data.len() < ECIES_OVERHEAD {
        bail!(
            "ECIES: ciphertext too short ({} < {})",
            data.len(),
            ECIES_OVERHEAD
        );
    }

    let r_pub = PublicKey::from_slice(&data[..65])
        .map_err(|e| anyhow!("ECIES: bad ephemeral pubkey: {e}"))?;
    let iv = &data[65..81];
    let ct = &data[81..data.len() - 32];
    let tag = &data[data.len() - 32..];

    // ECDH
    let xy = shared_secret_point(&r_pub, our_priv);
    let z: [u8; 32] = xy[..32].try_into().unwrap();
    let (ke, km) = concat_kdf(&z);

    // Verify HMAC
    let km_hash: [u8; 32] = Sha256::digest(km).as_slice().try_into().unwrap();
    let mut mac = HmacSha256::new_from_slice(&km_hash)
        .map_err(|e| anyhow!("ECIES HMAC init: {e}"))?;
    if !aad.is_empty() {
        mac.update(aad);
    }
    mac.update(iv);
    mac.update(ct);
    mac.verify_slice(tag)
        .map_err(|_| anyhow!("ECIES: MAC verification failed"))?;

    // Decrypt
    let mut pt = ct.to_vec();
    Aes128Ctr::new_from_slices(&ke, iv)
        .map_err(|e| anyhow!("ECIES AES init: {e}"))?
        .apply_keystream(&mut pt);
    Ok(pt)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// NIST SP 800-56A ConcatKDF: SHA256(0x00000001 || z) → (kE: 16B, kM: 16B).
fn concat_kdf(z: &[u8; 32]) -> ([u8; 16], [u8; 16]) {
    let mut h = Sha256::new();
    h.update([0x00, 0x00, 0x00, 0x01]);
    h.update(z);
    let result: [u8; 32] = h.finalize().as_slice().try_into().unwrap();
    let mut ke = [0u8; 16];
    let mut km = [0u8; 16];
    ke.copy_from_slice(&result[..16]);
    km.copy_from_slice(&result[16..]);
    (ke, km)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecies_roundtrip() {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let pk = PublicKey::from_secret_key(SECP256K1, &sk);
        let msg = b"hello rlpx ecies test message";
        let ct = ecies_encrypt(&pk, msg).unwrap();
        let pt = ecies_decrypt(&sk, &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn ecies_wrong_key_fails() {
        let sk1 = SecretKey::new(&mut rand::thread_rng());
        let sk2 = SecretKey::new(&mut rand::thread_rng());
        let pk1 = PublicKey::from_secret_key(SECP256K1, &sk1);
        let ct = ecies_encrypt(&pk1, b"secret data").unwrap();
        assert!(ecies_decrypt(&sk2, &ct).is_err());
    }
}
