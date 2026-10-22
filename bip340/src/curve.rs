//! secp256k1 point arithmetic over the zkVM's EC circuits: GLV decomposition,
//! windowed NAF, and a compile-time table of the generator's odd multiples.
//!
//! Extracted unchanged from our own secp256k1 backend, with the ECDSA
//! recovery path and its keccak256 left behind. What remains is curve
//! arithmetic and nothing else.
//!
use risc0_crypto::curves::secp256k1::{Config, Fq, FqConfig, Fr};
use risc0_crypto::{fp, BigInt, Coords, CurveOps, R0VMCurveOps, UnverifiedFp};


use crate::tables::{FIXED_BASE_TABLE_LEN, G_ODD, LAMBDA_G_ODD};

/// The secp256k1 group order `n`, big-endian bytes, for the wire-level range
/// checks. Identical to [`super::r0crypto`]'s, duplicated on the same
/// argument: the backends must be able to diverge without dragging each other.
pub const ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// `n / 2`, big-endian. A signature is canonical when `s <= n/2`.
const HALF_ORDER: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];

/// `n` as limbs, for the sign normalisation after the GLV split.
const ORDER_BIGINT: BigInt<8> =
    BigInt::from_hex("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

/// `n / 2` as limbs: above it a scalar is cheaper as `-(n - k)`.
const HALF_ORDER_BIGINT: BigInt<8> =
    BigInt::from_hex("0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");

// --- The GLV constants, verbatim from libsecp256k1's `secp256k1_scalar_split_lambda` ---
//
// λ is a cube root of unity in the scalar field and β its base-field
// counterpart: `λ·(x, y) = (β·x, y)`. (-b1, -b2, g1, g2) encode the
// precomputed lattice basis and the 384-bit-scaled rounding multipliers of the
// split `k = k₁ + k₂·λ`, exactly as libsecp256k1 publishes them. `g1`, `g2`
// carry libsecp256k1's built-in rounding adjustment, which is why the shift
// below adds only the half bit.

/// λ: the endomorphism scalar (`secp256k1_const_lambda`).
const LAMBDA: Fr = fp!("0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72");

/// β: the endomorphism's base-field multiplier (`secp256k1_const_beta`).
const BETA: Fq = fp!("0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee");

/// The curve equation's constant term: `y² = x³ + 7`.
const COEFF_B: Fq = fp!("0x7");

/// `-b1` of the lattice basis, mod n.
const MINUS_B1: Fr = fp!("0xe4437ed6010e88286f547fa90abfe4c3");

/// `-b2` of the lattice basis, mod n.
const MINUS_B2: Fr = fp!("0xfffffffffffffffffffffffffffffffe8a280ac50774346dd765cda83db1562c");

/// `g1 = round(2³⁸⁴ · b2 / n)`, for `c1 = round(k·g1 / 2³⁸⁴)`.
const G1: BigInt<8> =
    BigInt::from_hex("0x3086d221a7d46bcde86c90e49284eb153daa8a1471e8ca7fe893209a45dbb031");

/// `g2 = round(2³⁸⁴ · (-b1) / n)`, for `c2 = round(k·g2 / 2³⁸⁴)`.
const G2: BigInt<8> =
    BigInt::from_hex("0xe4437ed6010e88286f547fa90abfe4c4221208ac9df506c61571b4ae8ac47f71");

/// wNAF window for the recovered point `R`: digits are odd with
/// `|digit| <= 2^w - 1`, nonzero once per `w + 2` bits on average, and the
/// table holds `2^(w-1)` odd multiples. `R`'s table is built at runtime, so a
/// wider window would cost in table additions what it saves in the loop;
/// at ~130-bit half-scalars, 4 is where the two balance.
pub const WINDOW_R: u32 = 4;

/// wNAF window for the generator: its tables are compile-time constants, so
/// the window is as wide as [`FIXED_BASE_TABLE_LEN`] allows.
pub const WINDOW_G: u32 = 5;

/// Odd multiples of `R` a window-4 wNAF needs: `1, 3, 5, …, 15`.
pub const R_TABLE_LEN: usize = 1 << (WINDOW_R - 1);

/// The most wNAF digits a GLV half-scalar can produce: the halves are below
/// `2¹²⁹` in magnitude — a property of the fixed lattice basis, which bounds
/// Babai rounding for *every* input scalar, adversarial ones included — and a
/// wNAF of a b-bit value spans at most b + 1 positions. A few extra for
/// margin; [`wnaf`] is total either way.
pub const MAX_DIGITS: usize = 136;

pub fn lt(a: &[u8], b: &[u8; 32]) -> bool {
    for (x, y) in a.iter().zip(b.iter()) {
        if x != y {
            return x < y;
        }
    }
    false
}

/// Whether every byte is zero.
fn is_zero(a: &[u8]) -> bool {
    a.iter().all(|b| *b == 0)
}

/// An affine point with an explicit identity flag, over the circuit's own
/// coordinate type.
///
/// Not `risc0-crypto`'s `AffinePoint`, because this crate forbids `unsafe`
/// and that type's only const constructor is `unsafe` — while the circuit ops
/// themselves ([`R0VMCurveOps`]) take bare coordinate pairs, which
/// [`UnverifiedFp::from_bigint`] builds in const context without any of that.
/// The identity/same-x triage below mirrors `AffinePoint::add` line for line.
#[derive(Clone, Copy)]
pub struct Pt {
    pub xy: Coords<Config, 8>,
    pub infinity: bool,
}

impl Pt {
    pub const IDENTITY: Self = Self {
        xy: [
            UnverifiedFp::from_bigint(BigInt::ZERO),
            UnverifiedFp::from_bigint(BigInt::ZERO),
        ],
        infinity: true,
    };

    /// Writes `[2]src` into `self`, in place: the by-value circuit wrappers
    /// cost a measurable copy per call, and the main loop runs hundreds.
    ///
    /// A `y = 0` doubling would divide by zero in the circuit, but no on-curve
    /// secp256k1 point has one: the group order is odd, so there is no
    /// 2-torsion, and everything this backend doubles is on the curve.
    pub fn double_from(&mut self, src: &Self) {
        if src.infinity {
            self.infinity = true;
            return;
        }
        <R0VMCurveOps as CurveOps<Config, 8>>::double_into(&src.xy, &mut self.xy);
        self.infinity = false;
    }

    /// Writes `a + b` into `self`, with the same-x triage the chord rule
    /// cannot do itself.
    pub fn add_from(&mut self, a: &Self, b: &Self) {
        if b.infinity {
            *self = *a;
            return;
        }
        if a.infinity {
            *self = *b;
            return;
        }
        if a.xy[0].check_is_eq(&b.xy[0]) {
            if a.xy[1].check_is_eq(&b.xy[1]) {
                self.double_from(a);
            } else {
                self.infinity = true;
            }
            return;
        }
        <R0VMCurveOps as CurveOps<Config, 8>>::add_into(&a.xy, &b.xy, &mut self.xy);
        self.infinity = false;
    }

    /// `-self`: the reflection `(x, -y)`.
    pub fn neg(&self) -> Self {
        Self {
            xy: [self.xy[0], -&self.xy[1]],
            infinity: self.infinity,
        }
    }

    /// The endomorphism `φ(x, y) = (β·x, y) = λ·self`.
    pub fn endomorphism(&self) -> Self {
        Self {
            xy: [&self.xy[0] * &BETA, self.xy[1]],
            infinity: self.infinity,
        }
    }
}

/// The square root of `value` mod p, computed as `value^((p+1)/4)` through
/// libsecp256k1's addition chain, or `None` when no root exists.
///
/// The chain is the point: the binary of `(p+1)/4` has blocks of ones with
/// lengths {2, 22, 223}, so building `x^(2^n - 1)` for n in
/// 1, 2, 3, 6, 9, 11, 22, 44, 88, 176, 220, 223 and assembling takes about
/// 266 modular multiplies, where the generic bit-at-a-time `pow` spends about
/// 400 — and at the measured 86 cycles a multiply, that difference is ~12,000
/// cycles on every recovery. Chain structure from `secp256k1_fe_sqrt`,
/// reproduced over this crate's field type.
fn sqrt_chain(value: &UnverifiedFp<FqConfig, 8>) -> Option<UnverifiedFp<FqConfig, 8>> {
    /// `base^(2^squarings) * mul`, the chain's repeated step.
    fn step(
        base: &UnverifiedFp<FqConfig, 8>,
        squarings: u32,
        mul: &UnverifiedFp<FqConfig, 8>,
    ) -> UnverifiedFp<FqConfig, 8> {
        let mut acc = *base;
        for _ in 0..squarings {
            acc.square_in_place();
        }
        &acc * mul
    }

    let x1 = *value;
    let x2 = step(&x1, 1, &x1); // 2^2 - 1 ones
    let x3 = step(&x2, 1, &x1); // 3 ones
    let x6 = step(&x3, 3, &x3);
    let x9 = step(&x6, 3, &x3);
    let x11 = step(&x9, 2, &x2);
    let x22 = step(&x11, 11, &x11);
    let x44 = step(&x22, 22, &x22);
    let x88 = step(&x44, 44, &x44);
    let x176 = step(&x88, 88, &x88);
    let x220 = step(&x176, 44, &x44);
    let x223 = step(&x220, 3, &x3);

    // (p+1)/4 = ones(223) . 0 . ones(22) . 0000 . ones(2) . 00 . 1100
    let t1 = step(&x223, 23, &x22);
    let mut root = step(&t1, 6, &x2);
    root.square_in_place();
    root.square_in_place();

    // A root exists for exactly half of all values; squaring back is the test.
    let mut square = root;
    square.square_in_place();
    if square.check_is_eq(value) {
        Some(root)
    } else {
        None
    }
}

/// The point at `x` with the asked-for y-parity, or `None` when no point has
/// that x-coordinate. What `AffinePoint::decompress` does, minus its generic
/// square root — [`sqrt_chain`] is most of a recovery's fixed cost.
pub fn decompress(x: &UnverifiedFp<FqConfig, 8>, want_odd: bool) -> Option<Pt> {
    // y² = x³ + 7.
    let mut rhs = x * x;
    rhs = &rhs * x;
    rhs = &rhs + COEFF_B.as_unverified();

    let y = sqrt_chain(&rhs)?;

    // The parity of a field value is only meaningful reduced; the chain's
    // output is a circuit product and arrives canonical, but reducing is two
    // compares when it already is, so it is not worth assuming.
    let y = Fq::reduce_from_bigint(y.to_bigint());
    let y = if y.as_bigint().is_odd() == want_odd {
        *y.as_unverified()
    } else {
        -y.as_unverified()
    };
    Some(Pt {
        xy: [*x, y],
        infinity: false,
    })
}

/// A fixed-base table row, parsed from [`super::fast_tables`]' hex at compile
/// time. The values are checked against `k256` by that module's tests; the
/// parse itself is `BigInt::from_hex`, which panics at *compile* time on a
/// malformed constant and so cannot panic in the guest.
const fn fixed_table(rows: &[(&str, &str); FIXED_BASE_TABLE_LEN]) -> [Pt; FIXED_BASE_TABLE_LEN] {
    let mut out = [Pt::IDENTITY; FIXED_BASE_TABLE_LEN];
    let mut i = 0;
    while i < FIXED_BASE_TABLE_LEN {
        out[i] = Pt {
            xy: [
                UnverifiedFp::from_bigint(BigInt::from_hex(rows[i].0)),
                UnverifiedFp::from_bigint(BigInt::from_hex(rows[i].1)),
            ],
            infinity: false,
        };
        i += 1;
    }
    out
}

/// `(2i+1)·G`.
pub static G_TABLE: [Pt; FIXED_BASE_TABLE_LEN] = fixed_table(&G_ODD);

/// `(λ·(2i+1))·G`.
pub static LAMBDA_G_TABLE: [Pt; FIXED_BASE_TABLE_LEN] = fixed_table(&LAMBDA_G_ODD);

/// The limbs of a [`BigInt<8>`], little-endian.
fn limbs(value: &BigInt<8>) -> [u32; 8] {
    let bytes = value.as_le_bytes();
    let mut out = [0u32; 8];
    for (i, limb) in out.iter_mut().enumerate() {
        let mut word = [0u8; 4];
        word.copy_from_slice(&bytes[i * 4..i * 4 + 4]);
        *limb = u32::from_le_bytes(word);
    }
    out
}

/// `round(a·b / 2³⁸⁴)`: the 512-bit schoolbook product, shifted down with the
/// half bit added — libsecp256k1's `secp256k1_scalar_mul_shift_var` at a fixed
/// shift of 384. Software arithmetic, no circuit: 64 `u32` products.
fn mul_shift_384(a: &BigInt<8>, b: &BigInt<8>) -> BigInt<8> {
    let (x, y) = (limbs(a), limbs(b));
    let mut product = [0u32; 16];
    for i in 0..8 {
        let mut carry = 0u64;
        for j in 0..8 {
            let t = u64::from(product[i + j]) + u64::from(x[i]) * u64::from(y[j]) + carry;
            product[i + j] = t as u32;
            carry = t >> 32;
        }
        product[i + 8] = carry as u32;
    }

    let mut out = [0u32; 8];
    out[..4].copy_from_slice(&product[12..16]);
    // The rounding half-bit: bit 383 of the product.
    if product[11] >> 31 == 1 {
        for limb in &mut out {
            let (sum, overflowed) = limb.overflowing_add(1);
            *limb = sum;
            if !overflowed {
                break;
            }
        }
    }
    BigInt::new(out)
}

/// A GLV half-scalar: a sign and a magnitude below `2¹²⁹`.
pub struct Half {
    pub negative: bool,
    pub magnitude: BigInt<8>,
}

/// Normalises a scalar mod n into sign–magnitude form: values above `n/2`
/// are shorter as `-(n - k)`.
fn sign_magnitude(value: &Fr) -> Half {
    let bigint = *value.as_bigint();
    if HALF_ORDER_BIGINT.const_lt(&bigint) {
        Half {
            negative: true,
            magnitude: &ORDER_BIGINT - &bigint,
        }
    } else {
        Half {
            negative: false,
            magnitude: bigint,
        }
    }
}

/// Splits `k ≡ k₁ + k₂·λ (mod n)` with both halves below `2¹²⁹` in
/// magnitude: libsecp256k1's `secp256k1_scalar_split_lambda`, on this crate's
/// types. The two 384-bit-shifted products are software; the four reductions
/// mod n ride the modular-multiply circuit through `Fr`'s operators.
pub fn split_lambda(k: &Fr) -> (Half, Half) {
    let c1 = mul_shift_384(k.as_bigint(), &G1);
    let c2 = mul_shift_384(k.as_bigint(), &G2);

    // c1, c2 < 2^129 < n, so the conversions cannot fail; `unwrap_or` keeps
    // the guest path panic-free regardless.
    let c1 = Fr::from_bigint(c1).unwrap_or(Fr::ZERO);
    let c2 = Fr::from_bigint(c2).unwrap_or(Fr::ZERO);

    let k2 = &(&c1 * &MINUS_B1) + &(&c2 * &MINUS_B2);
    let k1 = k - &(&k2 * &LAMBDA);

    (sign_magnitude(&k1), sign_magnitude(&k2))
}

/// The window-`w` wNAF digits of `magnitude`, least significant first,
/// written into `digits`; returns how many positions they cover. Every digit
/// is zero or odd with `|digit| < 2^w`, so `(|digit| - 1) / 2` indexes a
/// table of odd multiples.
///
/// The magnitude is a GLV half below `2¹²⁹` ([`MAX_DIGITS`] has the bound's
/// provenance), so it is walked as 160 bits — a `u128` and a limb — rather
/// than as eight limbs: this loop runs once per bit, four times per recovery,
/// and the eight-limb version was measurably most of the backend's software
/// overhead.
pub fn wnaf(magnitude: &BigInt<8>, w: u32, digits: &mut [i8; MAX_DIGITS]) -> usize {
    let k = limbs(magnitude);
    let mut lo =
        u128::from(k[0]) | u128::from(k[1]) << 32 | u128::from(k[2]) << 64 | u128::from(k[3]) << 96;
    let mut hi = k[4];
    let mut len = 0usize;

    let mask = (1u32 << (w + 1)) - 1;
    let sign_bound = 1u32 << w;

    while (lo != 0 || hi != 0) && len < MAX_DIGITS {
        if lo & 1 == 1 {
            let low = (lo as u32) & mask;
            let digit = if low >= sign_bound {
                // The negative form: subtracting it *adds* the complement.
                let complement = u128::from((1u32 << (w + 1)) - low);
                let (sum, overflow) = lo.overflowing_add(complement);
                lo = sum;
                hi += u32::from(overflow);
                // low - 2^(w+1): the digit itself, which is negative.
                low as i32 - mask as i32 - 1
            } else {
                // The low bits equal `low`, so no borrow can propagate.
                lo -= u128::from(low);
                low as i32
            };
            // `w <= 6`, so the digit fits an i8 with room to spare.
            digits[len] = digit as i8;
        } else {
            digits[len] = 0;
        }
        lo = (lo >> 1) | (u128::from(hi & 1) << 127);
        hi >>= 1;
        len += 1;
    }
    len
}

/// One of the four digit streams the interleaved loop walks. Digits by
/// reference: the arrays live on the caller's stack and are read once per
/// position, so moving them into the stream would be a copy for nothing.
pub struct Stream<'a> {
    pub digits: &'a [i8; MAX_DIGITS],
    pub len: usize,
    pub negative: bool,
    pub table: &'a [Pt],
}

impl Stream<'_> {
    /// The table point this position asks for, already sign-adjusted, or
    /// `None` when the digit is zero or the position is past this stream.
    pub fn point_at(&self, i: usize) -> Option<Pt> {
        if i >= self.len {
            return None;
        }
        let digit = self.digits[i];
        if digit == 0 {
            return None;
        }
        let index = (usize::from(digit.unsigned_abs()) - 1) / 2;
        // The wNAF window is what sizes the table, so the index is always in
        // range; `get` keeps the guest panic-free rather than trusting that.
        let point = self.table.get(index)?;
        if (digit < 0) != self.negative {
            Some(point.neg())
        } else {
            Some(*point)
        }
    }
}