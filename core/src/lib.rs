//! An M-of-N multisig as a LEZ actor.
//!
//! One handler. `ReceiveInput` carries the actor's own prior state, so the
//! quorum is checked against stored configuration in the same step that
//! spends — there is no plan/apply split to bridge, and no effect to hand
//! across it.
//!
//! A member is a single-purpose BIP-340 key. No member's LEZ account is ever
//! named in a multisig transaction; the only account that signs one is
//! whoever pays the fee.
//!
//! Three things make the quorum mean something:
//!
//! - **The funds live in a PDA.** The group secret authorises an *account*;
//!   this program authorises an *action*. While the money sat in the balance
//!   of the account this actor lives on, any member could move it alone
//!   (`host/src/bin/bypass.rs`). A private PDA has no authorisation key: the
//!   only way to spend it is a call this program attaches the seed to.
//! - **Executed digests are recorded**, so an approved package runs once.
//!   Entries retire at their own expiry, which bounds the list.
//! - **The expiry bounds the transaction itself**, so an approval is not good
//!   forever. It is a window on the transaction rather than a question put to
//!   the clock: asking the clock means sending it a message, and a message
//!   from a private actor to a public one publishes the sender — account and
//!   program both — which is the one thing the private posture may not do
//!   (`host/src/bin/leak.rs`).

use borsh::{BorshDeserialize, BorshSerialize};
use k256::schnorr::{signature::hazmat::PrehashVerifier as _, Signature, VerifyingKey};
use lee_core::{
    account::{AccountId, Actor},
    native_token,
    program::{PdaSeed, ReceiveInput, Response, SyncMessage},
    Timestamp,
};
use risc0_zkvm::sha::{Impl, Sha256 as _};

/// At most this many members in one configuration.
pub const MAX_MEMBERS: usize = 32;

const TAG_APPROVE: &[u8] = b"/OSTRAKON/v1/Approve";
const TAG_VAULT: &[u8] = b"/OSTRAKON/v1/Vault";

/// The stored configuration: the actor's whole state.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Msig {
    /// Single-purpose BIP-340 x-only approval keys, strictly ascending.
    ///
    /// The order is a stored invariant, not a convention: it is what lets a
    /// quorum be checked by walking the two lists once instead of scanning
    /// the configuration for every approval.
    pub members: Vec<[u8; 32]>,
    /// How many distinct members an action needs.
    pub threshold: u32,
    /// Bumped by every configuration change; part of the digest, so approvals
    /// gathered under an older configuration stop verifying.
    pub epoch: u32,
    /// Digests already executed, each with the expiry that retires it. An
    /// entry can be dropped once the chain is past its expiry, because the
    /// package it names can never land again.
    pub executed: Vec<([u8; 32], Timestamp)>,
}

/// One member's signature over an action digest.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Sig {
    pub key: [u8; 32],
    pub sig: [u8; 64],
}

/// What the multisig does once a quorum approves it.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Action {
    /// Pay out of the vault.
    ///
    /// The vault's account id travels in the action because a private PDA's id
    /// depends on the group's keys, which the program does not hold. Naming
    /// the wrong one does not help an attacker: authority comes from the seed
    /// this program attaches, not from the id in the message, so a vault the
    /// seed does not bind refuses the debit.
    Transfer {
        vault: AccountId,
        to: AccountId,
        amount: u128,
    },
    /// Replace the configuration. Executing this bumps the epoch, which is the
    /// cutoff: every approval gathered under the old one dies with it.
    Reconfigure {
        members: Vec<[u8; 32]>,
        threshold: u32,
    },
}

/// The messages this actor accepts.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Msg {
    /// Write the first configuration. Refused once one exists.
    Create {
        members: Vec<[u8; 32]>,
        threshold: u32,
    },
    /// Run `action`, if `approvals` carries a quorum over its digest.
    ///
    /// `nonce` is the proposal's identifier, chosen by whoever proposes it and
    /// signed with everything else. Without it two legitimately identical
    /// payments — same vault, recipient, amount, epoch and expiry — would
    /// share a digest, and the executed record would refuse the second.
    ///
    /// `at` is the client's claim about the time. It is not taken on trust:
    /// the transaction is bounded to `[at, expires_at)`, so the sequencer
    /// refuses it outside those times. That both stops a late execution and
    /// makes `at` a sound lower bound on the chain's clock for retiring
    /// executed digests.
    Execute {
        nonce: [u8; 32],
        at: Timestamp,
        expires_at: Timestamp,
        action: Action,
        approvals: Vec<Sig>,
    },
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut buf = Vec::new();
    for p in parts {
        buf.extend_from_slice(&(p.len() as u32).to_le_bytes());
        buf.extend_from_slice(p);
    }
    *Impl::hash_bytes(&buf)
        .as_bytes()
        .first_chunk::<32>()
        .expect("sha-256 is 32 bytes")
}

/// The seed binding a multisig's vault to this program.
///
/// It is derived from the account the configuration lives on, so one
/// multisig's seed cannot reach another's vault.
#[must_use]
pub fn vault_seed(config: &AccountId) -> PdaSeed {
    PdaSeed::new(sha256(&[TAG_VAULT, config.as_ref()]))
}

/// The digest every approval signs.
///
/// It binds the actor (account *and* program, so an approval cannot cross
/// multisigs or deployments), the epoch (so it cannot cross a configuration
/// change), the nonce (so one proposal is not another), the expiry, and the
/// action itself.
#[must_use]
pub fn digest(
    me: &Actor,
    epoch: u32,
    nonce: &[u8; 32],
    expires_at: Timestamp,
    action: &Action,
) -> [u8; 32] {
    sha256(&[
        TAG_APPROVE,
        me.account_id.as_ref(),
        me.program_account_id.as_ref(),
        &epoch.to_le_bytes(),
        nonce,
        &expires_at.to_le_bytes(),
        &borsh::to_vec(action).expect("borsh is infallible"),
    ])
}

/// Measurement only: accepts every signature unchecked, so that subtracting
/// this program from a verifying one leaves the cryptography alone. The two
/// terms must come out of one dependency graph for the subtraction to hold,
/// which is why this is a feature of the same crate rather than a separate
/// program.
#[cfg(feature = "plumbing")]
#[must_use]
fn verify(_key: &[u8; 32], _message: &[u8; 32], _sig: &[u8; 64]) -> bool {
    true
}

/// One BIP-340 verification.
///
/// The `fast` feature swaps the patched `k256` for our own GLV + wNAF loop
/// over the secp256k1 EC circuits. The two are held to agree on BIP-340's
/// published vectors; only the cost differs.
#[cfg(all(target_os = "zkvm", target_vendor = "risc0", feature = "fast", not(feature = "plumbing")))]
#[must_use]
fn verify(key: &[u8; 32], message: &[u8; 32], sig: &[u8; 64]) -> bool {
    ostrakon_bip340::verify(key, message, sig).is_ok()
}

#[cfg(all(not(all(target_os = "zkvm", target_vendor = "risc0", feature = "fast")), not(feature = "plumbing")))]
#[must_use]
fn verify(key: &[u8; 32], message: &[u8; 32], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(key) else {
        return false;
    };
    let Ok(sig) = Signature::try_from(&sig[..]) else {
        return false;
    };
    vk.verify_prehash(message, &sig).is_ok()
}

/// Counts distinct current members whose signature over `message` verifies.
/// Panics — which fails the whole transaction — on a repeat, a non-member or a
/// bad signature, rather than silently not counting it.
///
/// Both lists are strictly ascending, so one walk over the pair settles
/// distinctness and membership together: a repeated key cannot ascend, and a
/// member once passed cannot be claimed again. The cost is linear in M + N
/// rather than quadratic.
fn quorum(cfg: &Msig, message: &[u8; 32], approvals: &[Sig]) -> u32 {
    let mut count = 0;
    let mut member = 0usize;
    let mut previous: Option<[u8; 32]> = None;

    for a in approvals {
        if let Some(p) = previous {
            assert!(p != a.key, "a key signed twice");
            assert!(p < a.key, "the approvals are not in ascending key order");
        }
        previous = Some(a.key);

        // The configuration ascends too, so the match can only lie at or
        // after the last one found.
        while member < cfg.members.len() && cfg.members[member] < a.key {
            member += 1;
        }
        assert!(
            member < cfg.members.len() && cfg.members[member] == a.key,
            "a signing key is not a current member"
        );
        member += 1;

        assert!(verify(&a.key, message, &a.sig), "a signature does not verify");
        count += 1;
    }
    count
}

fn check_config(members: &[[u8; 32]], threshold: u32) {
    assert!(
        !members.is_empty() && members.len() <= MAX_MEMBERS,
        "member count out of range"
    );
    assert!(
        threshold >= 1 && threshold as usize <= members.len(),
        "the threshold is between 1 and the member count"
    );
    for (i, k) in members.iter().enumerate() {
        // Ascending order carries uniqueness with it, and checking it costs
        // one comparison per member instead of a scan of the ones before.
        if i > 0 {
            assert!(members[i - 1] != *k, "a member is listed twice");
            assert!(
                members[i - 1] < *k,
                "the members are not in ascending key order"
            );
        }
        assert!(
            VerifyingKey::from_bytes(k).is_ok(),
            "a member key is not a valid BIP-340 key"
        );
    }
}

/// Bounds the transaction to `[at, expires_at)`.
///
/// The program reads no clock and sends no message: the window travels with
/// the transaction and the sequencer refuses it outside those times. The upper
/// bound is exclusive, so an action never lands at or after its expiry.
fn window(response: Response, at: Timestamp, expires_at: Timestamp) -> Response {
    response
        .try_timestamp_window(at..expires_at)
        .expect("at is before expires_at, checked above")
}

/// The whole program.
#[must_use]
pub fn handle(input: &ReceiveInput, msg: Msg) -> Response {
    let pre: &[u8] = &input.pre_state;

    match msg {
        Msg::Create { members, threshold } => {
            assert!(pre.is_empty(), "this multisig exists");
            check_config(&members, threshold);
            Response::set_state(
                borsh::to_vec(&Msig {
                    members,
                    threshold,
                    epoch: 0,
                    executed: Vec::new(),
                })
                .expect("borsh is infallible"),
            )
        }

        Msg::Execute {
            nonce,
            at,
            expires_at,
            action,
            approvals,
        } => {
            let mut cfg = Msig::try_from_slice(pre).expect("the configuration decodes");
            assert!(at < expires_at, "the window is empty: at is at or past the expiry");

            let d = digest(&input.receiver, cfg.epoch, &nonce, expires_at, &action);
            assert!(
                quorum(&cfg, &d, &approvals) >= cfg.threshold,
                "approvals are below the threshold"
            );

            // Once, and only once. `at` is a lower bound on the chain's clock
            // (the assertion below makes it one), so an entry whose expiry has
            // passed names a package that can never land again.
            assert!(
                !cfg.executed.iter().any(|(seen, _)| *seen == d),
                "this action has already executed"
            );
            cfg.executed.retain(|(_, retires_at)| *retires_at > at);
            cfg.executed.push((d, expires_at));

            match action {
                Action::Transfer { vault, to, amount } => window(
                    Response::set_state(borsh::to_vec(&cfg).expect("borsh is infallible")),
                    at,
                    expires_at,
                )
                .send(
                    // The seed is what authorises the debit. A vault this
                    // program did not derive is not reachable with it.
                    SyncMessage::new(
                        Actor::native_balance(vault),
                        &native_token::Message::Transfer { to, amount },
                    )
                    .with_pda_seeds(vec![vault_seed(&input.receiver.account_id)]),
                ),

                Action::Reconfigure { members, threshold } => {
                    check_config(&members, threshold);
                    cfg.members = members;
                    cfg.threshold = threshold;
                    cfg.epoch = cfg.epoch.checked_add(1).expect("epoch overflow");
                    window(
                        Response::set_state(borsh::to_vec(&cfg).expect("borsh is infallible")),
                        at,
                        expires_at,
                    )
                }
            }
        }
    }
}
