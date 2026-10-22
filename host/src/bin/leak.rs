//! What a private execution publishes.
//!
//! The private posture rests on the chain learning that *some* deployed
//! program ran, not which one. Every message a private actor sends to a public
//! one crosses the boundary, and the circuit records that crossing as a
//! `BoundaryStep` carrying the delivery's envelope — whose `from` is an
//! `Actor`, which is an account id *and* a program account id.
//!
//! So: run the real private execution and print every boundary crossing, then
//! search the whole public output for the multisig's program id and for the
//! private account the configuration lives on.
//!
//! `RISC0_DEV_MODE=1 cargo run --release -p ostrakon-host --features prove --bin leak`

use std::collections::{BTreeSet, HashSet};

use lee::{
    error::LeeError,
    execute_and_prove,
    privacy_preserving_transaction::circuit::ProgramCatalog,
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
use ostrakon_core::{digest, vault_seed, Action, Msg, Msig};
use ostrakon_host::Key;

const DEST: AccountId = AccountId::new([0xD1; 32]);
const BALANCE: u128 = 100_000;
const NONCE: [u8; 32] = [0x01; 32];
const NOW: u64 = 1_700_000_000_000;
const EXPIRES_AT: u64 = 1_700_000_600_000;

fn no_seal(body: &MessageBody) -> Result<RecipientEncryption, LeeError> {
    Err(LeeError::InvalidInput(format!(
        "no seal for a durable async message to {:?}",
        body.to
    )))
}

fn run(m: usize) -> anyhow::Result<()> {
    // `OSTRAKON_BACKEND=fast` proves the same transaction with approval
    // verification on our own GLV + wNAF loop.
    let (program, program_id) = if std::env::var("OSTRAKON_BACKEND").as_deref() == Ok("fast") {
        (
            ostrakon_methods::ostrakon_fast(),
            ostrakon_methods::ostrakon_fast_id(),
        )
    } else {
        (ostrakon_methods::ostrakon(), ostrakon_methods::ostrakon_id())
    };

    let mut keys: Vec<Key> = (0..m).map(|i| Key::new(40 + i as u8)).collect();
    // The configuration ascends by key, and approvals are presented in the
    // same order, which is what makes the quorum check a single walk.
    keys.sort_by_key(Key::public);
    let config = Msig {
        members: keys.iter().map(Key::public).collect(),
        threshold: m as u32,
        epoch: 0,
        executed: Vec::new(),
    };

    // The configuration lives on a private account every member derives from
    // the group secret. It holds no money.
    let ask = AuthorizationSecretKey([3; 32]);
    let nsk = NullifierSecretKey::from(&ask);
    let npk = NullifierPublicKey::from(&nsk);
    let vpk = ViewingPublicKey::from_seed(&[3; 32], &[4; 32]);
    let account_id = AccountId::for_regular_private_account(&npk, &vpk);
    let config_witness = PrivateWitness {
        vpk: vpk.clone(),
        random_seed: [0; 32],
        kind: WitnessKind::Regular(RegularKey::Authorized(ask)),
        nullifier: NullifierWitness::Update {
            account: Account::default()
                .with_actor_state(program_id, borsh::to_vec(&config)?.into()),
            membership_proof: (0, Vec::new()),
        },
        address_openings: BTreeSet::new(),
    };

    // The money lives in a PDA bound to this program by a seed only this
    // program can attach. No key authorises it.
    let seed = vault_seed(&account_id);
    let vault = AccountId::for_private_pda(&program_id, &seed, &npk, &vpk);
    let vault_witness = PrivateWitness {
        vpk,
        random_seed: [1; 32],
        kind: WitnessKind::Pda {
            nsk,
            binding: (program_id, seed),
        },
        nullifier: NullifierWitness::Update {
            account: Account::default().with_actor_state(
                NATIVE_TOKEN_PROGRAM_ID,
                native_token::encode_balance(BALANCE),
            ),
            membership_proof: (0, Vec::new()),
        },
        address_openings: BTreeSet::new(),
    };

    let me = Actor::new(account_id, program_id);
    let action = Action::Transfer {
        vault,
        to: DEST,
        amount: 1,
    };
    let d = digest(&me, config.epoch, &NONCE, EXPIRES_AT, &action);
    let message = borsh::to_vec(&Msg::Execute {
        nonce: NONCE,
        at: NOW,
        expires_at: EXPIRES_AT,
        action,
        approvals: keys.iter().map(|k| k.sign(&d)).collect(),
    })?;


    let (output, _proof) = execute_and_prove(
        ProvingInput {
            root: TransactionEntry::Sync(RootCall { to: me, message }),
            // Only the recipient's balance and the clock are public. The
            // multisig's account, its configuration, its vault and its
            // approvals are not.
            public_context: PublicExecutionContext::new(
                vec![Actor::native_balance(DEST)],
                HashSet::new(),
            ),
            private_witnesses: vec![config_witness, vault_witness],
            dummy_inputs: Vec::new(),
            ciphertext_padding: None,
            recoveries: Vec::new(),
            private_promotions: BTreeSet::new(),
        },
        &Simulation::default(),
        &ProgramCatalog::from([(program_id, program)]),
        |_| SenderPresentation::Canonical,
        |_, _| false,
        no_seal,
    )?;

    println!("multisig private account: {account_id}");
    println!("multisig program account: {program_id}");
    println!("vault (private PDA):      {vault}");
    println!();

    println!("boundary crossings the circuit publishes:");
    for step in &output.execution.boundary {
        match step {
            lee_core::execution_state::BoundaryStep::PrivateToPublic(d) => println!(
                "  private -> public   from {} under program {}\n                      to   {} under program {}",
                d.envelope.from.account_id,
                d.envelope.from.program_account_id,
                d.envelope.to.account_id,
                d.envelope.to.program_account_id,
            ),
            lee_core::execution_state::BoundaryStep::PublicToPrivate(d) => println!(
                "  public  -> private  from {} under program {}",
                d.envelope.from.account_id, d.envelope.from.program_account_id,
            ),
            other => println!("  {other:?}"),
        }
    }
    println!();

    let published = borsh::to_vec(&output)?;
    let find = |needle: &[u8]| {
        published
            .windows(needle.len())
            .any(|w| w == needle)
    };
    println!("in the published output:");
    println!("  the multisig's program id appears: {}", find(program_id.as_ref()));
    println!("  the multisig's account id appears: {}", find(account_id.as_ref()));
    println!("  the vault's account id appears:    {}", find(vault.as_ref()));
    for claim in &output.execution.program_image_claims {
        match claim {
            lee_core::ProgramImageClaim::Disclosed { account_id, .. } => println!(
                "  image claim: DISCLOSED, naming program {account_id}"
            ),
            lee_core::ProgramImageClaim::Undisclosed { .. } => {
                println!("  image claim: undisclosed (a set membership, naming nothing)");
            }
        }
    }
    Ok(())
}

fn run_private_recipient(m: usize) -> anyhow::Result<()> {
    // `OSTRAKON_BACKEND=fast` proves the same transaction with approval
    // verification on our own GLV + wNAF loop.
    let (program, program_id) = if std::env::var("OSTRAKON_BACKEND").as_deref() == Ok("fast") {
        (
            ostrakon_methods::ostrakon_fast(),
            ostrakon_methods::ostrakon_fast_id(),
        )
    } else {
        (ostrakon_methods::ostrakon(), ostrakon_methods::ostrakon_id())
    };

    let mut keys: Vec<Key> = (0..m).map(|i| Key::new(40 + i as u8)).collect();
    // The configuration ascends by key, and approvals are presented in the
    // same order, which is what makes the quorum check a single walk.
    keys.sort_by_key(Key::public);
    let config = Msig {
        members: keys.iter().map(Key::public).collect(),
        threshold: m as u32,
        epoch: 0,
        executed: Vec::new(),
    };

    // The configuration lives on a private account every member derives from
    // the group secret. It holds no money.
    let ask = AuthorizationSecretKey([3; 32]);
    let nsk = NullifierSecretKey::from(&ask);
    let npk = NullifierPublicKey::from(&nsk);
    let vpk = ViewingPublicKey::from_seed(&[3; 32], &[4; 32]);
    let account_id = AccountId::for_regular_private_account(&npk, &vpk);
    let config_witness = PrivateWitness {
        vpk: vpk.clone(),
        random_seed: [0; 32],
        kind: WitnessKind::Regular(RegularKey::Authorized(ask)),
        nullifier: NullifierWitness::Update {
            account: Account::default()
                .with_actor_state(program_id, borsh::to_vec(&config)?.into()),
            membership_proof: (0, Vec::new()),
        },
        address_openings: BTreeSet::new(),
    };

    // The money lives in a PDA bound to this program by a seed only this
    // program can attach. No key authorises it.
    let seed = vault_seed(&account_id);
    let vault = AccountId::for_private_pda(&program_id, &seed, &npk, &vpk);
    let vault_witness = PrivateWitness {
        vpk,
        random_seed: [1; 32],
        kind: WitnessKind::Pda {
            nsk,
            binding: (program_id, seed),
        },
        nullifier: NullifierWitness::Update {
            account: Account::default().with_actor_state(
                NATIVE_TOKEN_PROGRAM_ID,
                native_token::encode_balance(BALANCE),
            ),
            membership_proof: (0, Vec::new()),
        },
        address_openings: BTreeSet::new(),
    };

    let me = Actor::new(account_id, program_id);
    // The recipient is a private account too, so nothing in this transaction
    // has a public counterparty.
    let (recipient, recipient_witness) = {
        let ask = AuthorizationSecretKey([9; 32]);
        let nsk = NullifierSecretKey::from(&ask);
        let npk = NullifierPublicKey::from(&nsk);
        let vpk = ViewingPublicKey::from_seed(&[9; 32], &[10; 32]);
        let id = AccountId::for_regular_private_account(&npk, &vpk);
        let w = PrivateWitness {
            vpk,
            random_seed: [2; 32],
            kind: WitnessKind::Regular(RegularKey::Authorized(ask)),
            nullifier: NullifierWitness::Init {
                commitment_root: lee_core::DUMMY_COMMITMENT_HASH,
            },
            address_openings: BTreeSet::new(),
        };
        (id, w)
    };
    let action = Action::Transfer {
        vault,
        to: recipient,
        amount: 1,
    };
    let d = digest(&me, config.epoch, &NONCE, EXPIRES_AT, &action);
    let message = borsh::to_vec(&Msg::Execute {
        nonce: NONCE,
        at: NOW,
        expires_at: EXPIRES_AT,
        action,
        approvals: keys.iter().map(|k| k.sign(&d)).collect(),
    })?;


    let (output, _proof) = execute_and_prove(
        ProvingInput {
            root: TransactionEntry::Sync(RootCall { to: me, message }),
            // Only the recipient's balance and the clock are public. The
            // multisig's account, its configuration, its vault and its
            // approvals are not.
            public_context: PublicExecutionContext::new(
                Vec::new(),
                HashSet::new(),
            ),
            private_witnesses: vec![config_witness, vault_witness, recipient_witness],
            dummy_inputs: Vec::new(),
            ciphertext_padding: None,
            recoveries: Vec::new(),
            private_promotions: BTreeSet::new(),
        },
        &Simulation::default(),
        &ProgramCatalog::from([(program_id, program)]),
        |_| SenderPresentation::Canonical,
        |_, body| body.to.account_id == recipient,
        no_seal,
    )?;

    println!("multisig private account: {account_id}");
    println!("multisig program account: {program_id}");
    println!("vault (private PDA):      {vault}");
    println!();

    println!("boundary crossings the circuit publishes:");
    for step in &output.execution.boundary {
        match step {
            lee_core::execution_state::BoundaryStep::PrivateToPublic(d) => println!(
                "  private -> public   from {} under program {}\n                      to   {} under program {}",
                d.envelope.from.account_id,
                d.envelope.from.program_account_id,
                d.envelope.to.account_id,
                d.envelope.to.program_account_id,
            ),
            lee_core::execution_state::BoundaryStep::PublicToPrivate(d) => println!(
                "  public  -> private  from {} under program {}",
                d.envelope.from.account_id, d.envelope.from.program_account_id,
            ),
            other => println!("  {other:?}"),
        }
    }
    println!();

    let published = borsh::to_vec(&output)?;
    let find = |needle: &[u8]| {
        published
            .windows(needle.len())
            .any(|w| w == needle)
    };
    println!("in the published output:");
    println!("  the multisig's program id appears: {}", find(program_id.as_ref()));
    println!("  the multisig's account id appears: {}", find(account_id.as_ref()));
    println!("  the vault's account id appears:    {}", find(vault.as_ref()));
    for claim in &output.execution.program_image_claims {
        match claim {
            lee_core::ProgramImageClaim::Disclosed { account_id, .. } => println!(
                "  image claim: DISCLOSED, naming program {account_id}"
            ),
            lee_core::ProgramImageClaim::Undisclosed { .. } => {
                println!("  image claim: undisclosed (a set membership, naming nothing)");
            }
        }
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    println!("=== paying a PUBLIC recipient ===");
    run(3)?;
    println!();
    println!("=== paying a PRIVATE recipient ===");
    run_private_recipient(3)
}
