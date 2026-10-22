//! Can a key holder move the money without the quorum?
//!
//! Under the private posture every member derives the multisig's account keys
//! from the group secret, which is what lets any of them build a transaction
//! on it. Two attacks, with the same material the honest path uses, each
//! sending `native_token::Transfer` straight at a balance actor, naming no
//! multisig and carrying no approvals:
//!
//! 1. **against a regular private account** — the shape the funds used to sit
//!    in. Expected to drain: the group secret authorises the account.
//! 2. **against the vault PDA** — where they sit now. Expected to be refused:
//!    a private PDA has no authorisation key, and the only authority over it
//!    is the seed this program attaches to a call it makes.
//!
//! `RISC0_DEV_MODE=1 cargo run --release -p ostrakon-host --features prove --bin bypass`

use std::collections::{BTreeSet, HashSet};

use lee::{
    error::LeeError, execute_and_prove, privacy_preserving_transaction::circuit::ProgramCatalog,
    ProvingInput, PublicExecutionContext, SenderPresentation, Simulation,
};
use lee_core::{
    account::{Account, AccountId, Actor},
    encryption::ViewingPublicKey,
    execution_state::TransactionEntry,
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::MessageBody,
    AuthorizationSecretKey, NullifierPublicKey, NullifierSecretKey, NullifierWitness,
    PrivateWitness, RecipientEncryption, RegularKey, RootCall, WitnessKind,
};
use ostrakon_core::{vault_seed, Msig};

const THIEF: AccountId = AccountId::new([0xBA; 32]);
const BALANCE: u128 = 100_000;

fn no_seal(body: &MessageBody) -> Result<RecipientEncryption, LeeError> {
    Err(LeeError::InvalidInput(format!("no seal for {:?}", body.to)))
}

/// A 3-of-3 configuration: the money should need three signatures.
fn config() -> Msig {
    Msig {
        members: vec![[1; 32], [2; 32], [3; 32]],
        threshold: 3,
        epoch: 0,
        executed: Vec::new(),
    }
}

/// Sends every token out of `from`'s balance to the thief, with `witness` as
/// the only credential and the multisig program never invoked.
fn steal(from: AccountId, witness: PrivateWitness) -> Result<(), LeeError> {
    let program_id = ostrakon_methods::ostrakon_id();
    execute_and_prove(
        ProvingInput {
            root: TransactionEntry::Sync(RootCall {
                to: Actor::native_balance(from),
                message: borsh::to_vec(&native_token::Message::Transfer {
                    to: THIEF,
                    amount: BALANCE,
                })
                .expect("borsh"),
            }),
            public_context: PublicExecutionContext::new(
                vec![Actor::native_balance(THIEF)],
                HashSet::new(),
            ),
            private_witnesses: vec![witness],
            dummy_inputs: Vec::new(),
            ciphertext_padding: None,
            recoveries: Vec::new(),
            private_promotions: BTreeSet::new(),
        },
        &Simulation::default(),
        &ProgramCatalog::from([(program_id, ostrakon_methods::ostrakon())]),
        |_| SenderPresentation::Canonical,
        |_, _| false,
        no_seal,
    )
    .map(|_| ())
}

/// What a group-secret holder has for the multisig's own account.
fn group_keys() -> (AuthorizationSecretKey, NullifierSecretKey, ViewingPublicKey) {
    let ask = AuthorizationSecretKey([3; 32]);
    let nsk = NullifierSecretKey::from(&ask);
    let vpk = ViewingPublicKey::from_seed(&[3; 32], &[4; 32]);
    (ask, nsk, vpk)
}

fn funded(program_id: AccountId, with_config: bool) -> Account {
    let account = Account::default().with_actor_state(
        NATIVE_TOKEN_PROGRAM_ID,
        native_token::encode_balance(BALANCE),
    );
    if with_config {
        account.with_actor_state(
            program_id,
            borsh::to_vec(&config()).expect("borsh").into(),
        )
    } else {
        account
    }
}

fn main() {
    let program_id = ostrakon_methods::ostrakon_id();
    let (ask, nsk, vpk) = group_keys();

    // 1. The old shape: funds in the balance of the account the actor lives on.
    let account_id = AccountId::for_regular_private_account(
        &NullifierPublicKey::from(&nsk),
        &vpk,
    );
    let result = steal(
        account_id,
        PrivateWitness {
            vpk: vpk.clone(),
            random_seed: [0; 32],
            kind: WitnessKind::Regular(RegularKey::Authorized(ask)),
            nullifier: NullifierWitness::Update {
                account: funded(program_id, true),
                membership_proof: (0, Vec::new()),
            },
            address_openings: BTreeSet::new(),
        },
    );
    match result {
        Ok(()) => println!("1. funds on the multisig's own account: DRAINED, no approvals"),
        Err(e) => println!("1. funds on the multisig's own account: refused: {e}"),
    }

    // 2. Where the funds live now: a PDA bound to this program by a seed only
    //    this program can attach.
    let seed = vault_seed(&account_id);
    let vault = AccountId::for_private_pda(
        &program_id,
        &seed,
        &NullifierPublicKey::from(&nsk),
        &vpk,
    );
    let vpk_for_pda = vpk;
    let result = steal(
        vault,
        PrivateWitness {
            vpk: vpk_for_pda,
            random_seed: [0; 32],
            // The strongest thing a member can hold for a PDA. There is no
            // authorisation secret key: the binding is the authority.
            kind: WitnessKind::Pda {
                nsk,
                binding: (program_id, seed),
            },
            nullifier: NullifierWitness::Update {
                account: funded(program_id, false),
                membership_proof: (0, Vec::new()),
            },
            address_openings: BTreeSet::new(),
        },
    );
    match result {
        Ok(()) => println!("2. the vault PDA: DRAINED, no approvals — the fix does not hold"),
        Err(e) => println!("2. the vault PDA: refused: {e}"),
    }
}
