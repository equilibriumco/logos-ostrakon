//! BIP-340 Schnorr verification on the secp256k1 EC circuits.
//!
//! Verification computes `R = s·G − e·P`, where `P` is the x-only public key
//! lifted to its even-`y` point and `e` is the BIP-340 challenge. The signature
//! holds when `R` is finite, `R.y` is even, and `R.x` equals the signature's
//! `r`.
//!
//! That sum is two scalar multiples, one against the generator and one against
//! a point the signature supplies. GLV decomposition splits each scalar into
//! two half-length ones, windowed NAF thins the additions, and the generator's
//! odd multiples are compile-time constants, so only the public key's table is
//! built per verification.
//!
//! # Where the ECDSA rules do not carry over
//!
//! Three ways to be subtly wrong by copying a recovery path:
//!
//! - `s = 0` and `r = 0` are not refused. ECDSA rejects both because its
//!   arithmetic divides by `r`. BIP-340 does not divide, and bounds `r < p`
//!   and `s < n` and nothing else.
//! - There is no low-`s` rule. ECDSA recovers `R` scaled by `1/s`, so negating
//!   `s` negates `R` and leaves `R.x` unchanged, and both signatures verify.
//!   `R = s·G − e·P` is affine in `s`, so `(r, n − s)` lands on a different
//!   `x` and fails.
//! - `r` is a field element and `s` is a scalar, so they are range-checked
//!   against different moduli: `p` for `r`, `n` for `s`.
//!
//! # zkVM only
//!
//! The circuits exist only inside a guest.

use risc0_crypto::curves::secp256k1::{Fq, Fr};
use risc0_crypto::{BigInt, UnverifiedFp};

use sha2::{Digest, Sha256};

use crate::params::{CHALLENGE_TAG_HASH, FIELD_ORDER};
use crate::curve::{
    decompress, lt, split_lambda, wnaf, Pt, Stream, G_TABLE, LAMBDA_G_TABLE, MAX_DIGITS, ORDER,
    R_TABLE_LEN, WINDOW_G, WINDOW_R,
};

/// Why a verification did not succeed. Coarse on purpose: a precise reason
/// tells an attacker more than it tells an operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bip340Error {
    /// The public key was not a field element, or no point has it as an
    /// x-coordinate.
    InvalidPublicKey,
    /// `r` was not below `p`, or `s` was not below `n`.
    InvalidSignature,
    /// The signature was well formed and did not verify.
    VerificationFailed,
}

/// The BIP-340 challenge `e = int(tagged_hash(r ‖ P ‖ m)) mod n`.
fn challenge(r_bytes: &[u8], public_key: &[u8; 32], message: &[u8; 32]) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(CHALLENGE_TAG_HASH);
    hasher.update(CHALLENGE_TAG_HASH);
    hasher.update(r_bytes);
    hasher.update(public_key);
    hasher.update(message);

    let digest: [u8; 32] = hasher.finalize().into();
    Fr::from_be_bytes_mod_order(&digest)
}

/// Verifies a BIP-340 signature over `message` under the x-only `public_key`,
/// answering [`Bip340Error`] when either is malformed or the signature does not
/// verify.
pub fn verify(
    public_key: &[u8; 32],
    message: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), Bip340Error> {
    // Range-check the wire values. `r` is a field element and `s` a scalar, so
    // they are bounded by different moduli.
    let (r_bytes, s_bytes) = signature.split_at(32);
    if !lt(r_bytes, &FIELD_ORDER) || !lt(s_bytes, &ORDER) {
        return Err(Bip340Error::InvalidSignature);
    }
    if !lt(public_key, &FIELD_ORDER) {
        return Err(Bip340Error::InvalidPublicKey);
    }

    // lift_x: the key names an x-coordinate and BIP-340 fixes the point as the
    // one with even y. About half of all x have no point at all.
    let key_x = UnverifiedFp::from_bigint(BigInt::from_be_bytes(public_key));
    let point = decompress(&key_x, false).ok_or(Bip340Error::InvalidPublicKey)?;

    // The two scalars of `R = s·G + (−e)·P`, each split into GLV halves.
    // The range check above already established `s < n`, so this cannot be
    // `None`. Kept as an error rather than an unwrap: this function must not
    // panic on any input.
    let s_scalar =
        Fr::from_bigint(BigInt::from_be_bytes(s_bytes)).ok_or(Bip340Error::InvalidSignature)?;
    let negated_challenge = -&challenge(r_bytes, public_key, message);
    let (p_1, p_2) = split_lambda(&negated_challenge);
    let (g_1, g_2) = split_lambda(&s_scalar);

    // Odd multiples of P and their endomorphism images. The generator's
    // equivalents are compile-time constants, so only these are built here.
    let mut twice = Pt::IDENTITY;
    twice.double_from(&point);
    let mut p_table = [point; R_TABLE_LEN];
    for i in 1..R_TABLE_LEN {
        let previous = p_table[i - 1];
        p_table[i].add_from(&previous, &twice);
    }
    let mut lambda_p_table = [Pt::IDENTITY; R_TABLE_LEN];
    for (phi, source) in lambda_p_table.iter_mut().zip(p_table.iter()) {
        *phi = source.endomorphism();
    }

    // One signed-digit stream per half-scalar, each paired with its table.
    let mut d_p1 = [0i8; MAX_DIGITS];
    let mut d_p2 = [0i8; MAX_DIGITS];
    let mut d_g1 = [0i8; MAX_DIGITS];
    let mut d_g2 = [0i8; MAX_DIGITS];
    let len_p1 = wnaf(&p_1.magnitude, WINDOW_R, &mut d_p1);
    let len_p2 = wnaf(&p_2.magnitude, WINDOW_R, &mut d_p2);
    let len_g1 = wnaf(&g_1.magnitude, WINDOW_G, &mut d_g1);
    let len_g2 = wnaf(&g_2.magnitude, WINDOW_G, &mut d_g2);

    let streams = [
        Stream {
            digits: &d_p1,
            len: len_p1,
            negative: p_1.negative,
            table: &p_table,
        },
        Stream {
            digits: &d_p2,
            len: len_p2,
            negative: p_2.negative,
            table: &lambda_p_table,
        },
        Stream {
            digits: &d_g1,
            len: len_g1,
            negative: g_1.negative,
            table: &G_TABLE,
        },
        Stream {
            digits: &d_g2,
            len: len_g2,
            negative: g_2.negative,
            table: &LAMBDA_G_TABLE,
        },
    ];

    // The interleaved double-and-add: one shared doubling per position, one
    // addition per nonzero digit across all four streams. Two buffers and a
    // swap: the circuit must not write over its own input, and a by-value
    // result is a copy per operation.
    let mut position = streams.iter().map(|s| s.len).max().unwrap_or(0);
    let mut buffer_a = Pt::IDENTITY;
    let mut buffer_b = Pt::IDENTITY;
    let (mut acc, mut spare) = (&mut buffer_a, &mut buffer_b);
    while position > 0 {
        position -= 1;
        spare.double_from(acc);
        core::mem::swap(&mut acc, &mut spare);
        for stream in &streams {
            if let Some(table_point) = stream.point_at(position) {
                spare.add_from(acc, &table_point);
                core::mem::swap(&mut acc, &mut spare);
            }
        }
    }

    // The signature holds when R is finite, has even y, and sits at x = r. The
    // circuits may answer with coordinates not yet reduced below p, and both
    // coordinate checks read the canonical value.
    let r_point = *acc;
    if r_point.infinity {
        return Err(Bip340Error::VerificationFailed);
    }

    let y = Fq::reduce_from_bigint(r_point.xy[1].to_bigint());
    if y.as_bigint().is_odd() {
        return Err(Bip340Error::VerificationFailed);
    }

    let x = Fq::reduce_from_bigint(r_point.xy[0].to_bigint());
    let mut x_bytes = [0u8; 32];
    x.as_bigint().write_be_bytes(&mut x_bytes);
    if x_bytes != r_bytes {
        return Err(Bip340Error::VerificationFailed);
    }

    Ok(())
}
