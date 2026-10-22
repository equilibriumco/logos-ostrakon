use std::borrow::Cow;

use lee::program::Program;

mod guests {
    include!(concat!(env!("OUT_DIR"), "/methods.rs"));
}

/// The multisig guest, as the state machine loads it.
#[must_use]
pub fn ostrakon() -> Program {
    Program::new_unchecked(guests::OSTRAKON_ID, Cow::Borrowed(guests::OSTRAKON_ELF))
}

/// The guest's ImageID, which is also its program account id.
#[must_use]
pub fn ostrakon_id() -> lee::AccountId {
    lee::AccountId::from_builtin_program(guests::OSTRAKON_ID)
}

/// The same guest built against the stock `k256`: the control for what the
/// RISC Zero accelerated fork is worth.
#[must_use]
pub fn ostrakon_stock() -> Program {
    Program::new_unchecked(guests::OSTRAKON_STOCK_ID, Cow::Borrowed(guests::OSTRAKON_STOCK_ELF))
}

#[must_use]
pub fn ostrakon_stock_id() -> lee::AccountId {
    lee::AccountId::from_builtin_program(guests::OSTRAKON_STOCK_ID)
}

/// The same guest with approval verification on our own GLV + wNAF loop over
/// the secp256k1 EC circuits.
#[must_use]
pub fn ostrakon_fast() -> Program {
    Program::new_unchecked(guests::OSTRAKON_FAST_ID, Cow::Borrowed(guests::OSTRAKON_FAST_ELF))
}

#[must_use]
pub fn ostrakon_fast_id() -> lee::AccountId {
    lee::AccountId::from_builtin_program(guests::OSTRAKON_FAST_ID)
}

/// Measurement only: the same program with every signature accepted
/// unchecked. Subtracting it from a verifying guest leaves the cryptography.
#[must_use]
pub fn ostrakon_plumbing() -> Program {
    Program::new_unchecked(guests::OSTRAKON_PLUMBING_ID, Cow::Borrowed(guests::OSTRAKON_PLUMBING_ELF))
}

#[must_use]
pub fn ostrakon_plumbing_id() -> lee::AccountId {
    lee::AccountId::from_builtin_program(guests::OSTRAKON_PLUMBING_ID)
}
