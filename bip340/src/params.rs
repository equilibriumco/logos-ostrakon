//! The constants BIP-340 verification needs that are not curve arithmetic: a
//! range bound and a hash prefix.
//!
//! Not gated to the zkVM, so the tests below can run on the host. They derive
//! the field characteristic from its definition and the tag hash from the tag,
//! rather than restating either.

/// The secp256k1 field characteristic `p = 2²⁵⁶ − 2³² − 977`, big-endian.
pub const FIELD_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
];

/// `SHA256("BIP0340/challenge")`, the tag hash every challenge is prefixed with
/// twice.
pub const CHALLENGE_TAG_HASH: [u8; 32] = [
    0x7b, 0xb5, 0x2d, 0x7a, 0x9f, 0xef, 0x58, 0x32, 0x3e, 0xb1, 0xbf, 0x7a, 0x40, 0x7d, 0xb3, 0x82,
    0xd2, 0xf3, 0xf2, 0xd8, 0x1b, 0xb1, 0x22, 0x4f, 0x49, 0xfe, 0x51, 0x8f, 0x6d, 0x48, 0xd3, 0x7c,
];

/// The BIP-340 tag the challenge hash is derived from.
pub const CHALLENGE_TAG: &[u8] = b"BIP0340/challenge";

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// Derives `p` from its definition rather than restating the constant.
    #[test]
    fn the_field_order_is_two_to_the_256_minus_two_to_the_32_minus_977() {
        // Starting from 2²⁵⁶ − 1, subtract 2³² + 976. Every byte of that
        // subtrahend is below 0xFF, so no borrow leaves a byte and the
        // subtraction is per-byte.
        let mut derived = [0xFFu8; 32];
        let subtrahend: u64 = (1u64 << 32) + 976;
        for (offset, byte) in derived.iter_mut().rev().enumerate().take(8) {
            *byte -= ((subtrahend >> (offset * 8)) & 0xFF) as u8;
        }

        assert_eq!(derived, FIELD_ORDER);
    }

    #[test]
    fn the_challenge_tag_hash_is_what_sha256_says() {
        let digest: [u8; 32] = Sha256::digest(CHALLENGE_TAG).into();
        assert_eq!(digest, CHALLENGE_TAG_HASH);
    }
}
