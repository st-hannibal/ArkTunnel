// EllSwift encoding/decoding for BIP 324.
//
// Delegates entirely to the libsecp256k1 EllSwift API (secp256k1 crate v0.29).
// libsecp256k1 implements the full XSwiftEC / XElligatorSwift spec from the
// BIP 324 Appendix and has been verified against all official test vectors.
//
// References:
//   BIP 324: https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki
//   secp256k1 crate: https://docs.rs/secp256k1/0.29

use anyhow::{Context, Result};
use rand::RngCore;
use secp256k1::{
    ellswift::{ElligatorSwift, ElligatorSwiftParty},
    SecretKey, SECP256K1,
};

// ---------------------------------------------------------------------------
// Public types — thin wrappers keeping our API independent of crate internals
// ---------------------------------------------------------------------------

/// A BIP 324 EllSwift-encoded public key (64 bytes, uniformly random-looking).
pub type EllSwiftPub = [u8; 64];

/// An ephemeral secp256k1 private key (32 bytes).
pub type PrivKey = [u8; 32];

// ---------------------------------------------------------------------------
// ellswift_create
// ---------------------------------------------------------------------------

/// Generate a random ephemeral private key and its EllSwift-encoded public key.
///
/// Returns `(privkey_bytes, ellswift_pub_bytes)`.
/// Both are uniformly random from the perspective of an observer.
pub fn ellswift_create() -> Result<(PrivKey, EllSwiftPub)> {
    let mut rand32 = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut rand32);

    let sk = SecretKey::new(&mut rand::thread_rng());
    let priv_bytes: PrivKey = sk.secret_bytes();

    // from_seckey uses the secret key plus aux_rand for a uniformly-sampled encoding.
    let es = ElligatorSwift::from_seckey(SECP256K1, sk, Some(rand32));
    Ok((priv_bytes, es.to_array()))
}

// ---------------------------------------------------------------------------
// ellswift_ecdh_xonly
// ---------------------------------------------------------------------------

/// BIP 324 v2_ecdh: compute the shared ECDH secret.
///
/// * `ellswift_theirs` — the remote party's 64-byte EllSwift-encoded public key
/// * `priv_bytes`      — our 32-byte private key
/// * `ellswift_ours`   — our own 64-byte EllSwift-encoded public key
/// * `initiating`      — true if we are the initiator (Party A)
///
/// Returns the 32-byte tagged shared secret as specified in BIP 324:
///   SHA256(SHA256("bip324_ellswift_xonly_ecdh") ||
///          SHA256("bip324_ellswift_xonly_ecdh") ||
///          ellswift_A || ellswift_B || ecdh_point_x32)
///
/// The secp256k1 `shared_secret` function implements exactly this hash when
/// called with `ElligatorSwiftParty::A` or `::B`.
pub fn v2_ecdh(
    priv_bytes: &PrivKey,
    ellswift_theirs: &EllSwiftPub,
    ellswift_ours: &EllSwiftPub,
    initiating: bool,
) -> Result<[u8; 32]> {
    let sk = SecretKey::from_slice(priv_bytes).context("invalid private key")?;
    let es_theirs = ElligatorSwift::from_array(*ellswift_theirs);
    let es_ours = ElligatorSwift::from_array(*ellswift_ours);

    // BIP 324 convention: ellswift_A is the initiator's key, ellswift_B the responder's.
    let (es_a, es_b, party) = if initiating {
        (es_ours, es_theirs, ElligatorSwiftParty::A)
    } else {
        (es_theirs, es_ours, ElligatorSwiftParty::B)
    };

    let secret = ElligatorSwift::shared_secret(es_a, es_b, sk, party, None);
    Ok(*secret.as_secret_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::PublicKey;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
            .collect()
    }

    /// Smoke test: two parties derive the same shared secret.
    #[test]
    fn ecdh_shared_secret_matches() {
        let (priv_a, es_a) = ellswift_create().unwrap();
        let (priv_b, es_b) = ellswift_create().unwrap();

        let secret_a = v2_ecdh(&priv_a, &es_b, &es_a, true).unwrap();
        let secret_b = v2_ecdh(&priv_b, &es_a, &es_b, false).unwrap();

        assert_eq!(secret_a, secret_b, "shared secrets must match");
    }

    /// Different key pairs must produce different secrets (collision sanity).
    #[test]
    fn ecdh_different_keys_differ() {
        let (priv_a, es_a) = ellswift_create().unwrap();
        let (priv_b, es_b) = ellswift_create().unwrap();
        let (_, es_c) = ellswift_create().unwrap();

        let secret_ab = v2_ecdh(&priv_a, &es_b, &es_a, true).unwrap();
        let secret_ac = v2_ecdh(&priv_a, &es_c, &es_a, true).unwrap();

        assert_ne!(secret_ab, secret_ac);

        let _ = priv_b;
    }

    // -----------------------------------------------------------------------
    // BIP 324 official test vectors
    // -----------------------------------------------------------------------

    static ELLSWIFT_DECODE_CSV: &str =
        include_str!("../../tests/vectors/bip324_ellswift_decode.csv");

    static XSWIFTEC_INV_CSV: &str =
        include_str!("../../tests/vectors/bip324_xswiftec_inv.csv");

    /// For each ellswift_decode vector: decode the 64-byte EllSwift encoding and
    /// verify the resulting public key's x-coordinate matches the expected value.
    #[test]
    fn ellswift_decode_vectors() {
        let mut count = 0;
        for (line_no, line) in ELLSWIFT_DECODE_CSV.lines().enumerate() {
            if line_no == 0 || line.trim().is_empty() {
                continue; // skip header
            }
            let cols: Vec<&str> = line.splitn(3, ',').collect();
            assert!(cols.len() >= 2, "line {}: too few columns", line_no + 1);
            let ellswift_hex = cols[0].trim();
            let expected_x_hex = cols[1].trim();

            assert_eq!(ellswift_hex.len(), 128, "line {}: ellswift not 64 bytes", line_no + 1);
            assert_eq!(expected_x_hex.len(), 64, "line {}: x not 32 bytes", line_no + 1);

            let enc_bytes: [u8; 64] = hex_to_bytes(ellswift_hex).try_into().unwrap();
            let expected_x: Vec<u8> = hex_to_bytes(expected_x_hex);

            let es = ElligatorSwift::from_array(enc_bytes);
            let pk = PublicKey::from_ellswift(es);
            // x-coordinate = bytes 1..33 of the 65-byte uncompressed encoding (04 || x || y)
            let x = &pk.serialize_uncompressed()[1..33];

            assert_eq!(
                x, expected_x.as_slice(),
                "line {}: x mismatch for ellswift={ellswift_hex}",
                line_no + 1
            );
            count += 1;
        }
        assert!(count > 0, "no ellswift_decode vectors loaded");
    }

    /// For each xswiftec_inv vector: for every non-empty case_i_t value, verify that
    /// XSwiftEC(u, t) produces a public key with the expected x-coordinate.
    /// (We test the inverse relationship: XSwiftEC(u, XSwiftECInv(u, x, i)) = x.)
    #[test]
    fn xswiftec_inv_vectors() {
        let mut checked = 0usize;
        for (line_no, line) in XSWIFTEC_INV_CSV.lines().enumerate() {
            if line_no == 0 || line.trim().is_empty() {
                continue; // skip header
            }
            // Columns: u, x, case0_t, case1_t, ..., case7_t, comment
            let cols: Vec<&str> = line.splitn(11, ',').collect();
            assert!(cols.len() >= 10, "line {}: too few columns", line_no + 1);
            let u_hex = cols[0].trim();
            let x_hex = cols[1].trim();
            let u_bytes: Vec<u8> = hex_to_bytes(u_hex);
            let expected_x: Vec<u8> = hex_to_bytes(x_hex);

            for case in 0..8usize {
                let t_hex = cols[2 + case].trim();
                if t_hex.is_empty() {
                    continue; // this case has no valid t — skip
                }
                assert_eq!(t_hex.len(), 64, "line {}: case{case} t not 32 bytes", line_no + 1);
                let t_bytes: Vec<u8> = hex_to_bytes(t_hex);

                // Form 64-byte EllSwift encoding: u (32B) || t (32B)
                let mut enc = [0u8; 64];
                enc[..32].copy_from_slice(&u_bytes);
                enc[32..].copy_from_slice(&t_bytes);

                let es = ElligatorSwift::from_array(enc);
                let pk = PublicKey::from_ellswift(es);
                let x = &pk.serialize_uncompressed()[1..33];

                assert_eq!(
                    x, expected_x.as_slice(),
                    "line {}: case{case}: x mismatch for u={u_hex} t={t_hex}",
                    line_no + 1
                );
                checked += 1;
            }
        }
        assert!(checked > 0, "no xswiftec_inv cases verified");
    }
}
