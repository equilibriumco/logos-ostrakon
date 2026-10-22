//! BIP-340 Schnorr verification on the zkVM's secp256k1 EC circuits.
//!
//! Verification computes `R = s·G − e·P`. That is a sum of two scalar
//! multiples, one against the generator and one against the public key, so
//! three classical techniques apply: GLV decomposition halves the scalars,
//! windowed NAF thins the additions, and the generator's odd multiples are
//! compile-time constants. The result costs about a third of what the
//! accelerated `k256` loop costs for the same check.
//!
//! The circuits exist only inside a guest, so this crate is zkVM-only.
//!
//! Extracted from our own secp256k1 backend. Only the curve arithmetic came
//! across: no ECDSA recovery, no keccak256, no dependency on anything that is
//! not secp256k1.

#![no_std]

// The circuits are a guest intrinsic, so on any other target this crate is
// empty rather than broken: the host builds the same workspace.
#[cfg(all(target_os = "zkvm", target_vendor = "risc0"))]
mod curve;
#[cfg(all(target_os = "zkvm", target_vendor = "risc0"))]
mod params;
#[cfg(all(target_os = "zkvm", target_vendor = "risc0"))]
mod tables;
#[cfg(all(target_os = "zkvm", target_vendor = "risc0"))]
mod verify;

#[cfg(all(target_os = "zkvm", target_vendor = "risc0"))]
pub use verify::{verify, Bip340Error};
