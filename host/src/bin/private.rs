//! The multisig on a **private account**, through the privacy circuit.
//!
//! The configuration lives in the actor state of a private account, so the
//! chain stores a commitment and a validity proof and publishes neither the
//! members, nor the threshold, nor the approvals. The quorum is still checked
//! by the program, inside the proof, and the approved transfer spends the
//! private account's own balance.
//!
//! `cargo run --release -p ostrakon-host --features prove --bin private -- [M...]`
//!
//! `RISC0_DEV_MODE=1` exercises the composition without real proving, which is
//! the fast way to answer "does this compose at all". Timings are only
//! meaningful with it off.

use std::collections::{BTreeSet, HashSet};
use std::time::Instant;

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

fn run(m: usize) -> anyhow::Result<(f64, usize)> {
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


    let started = Instant::now();
    let (_output, proof) = execute_and_prove(
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
    Ok((started.elapsed().as_secs_f64(), proof.into_inner().len()))
}

fn main() {
    let dev = std::env::var("RISC0_DEV_MODE").is_ok_and(|v| v != "0" && !v.is_empty());
    if dev {
        eprintln!("RISC0_DEV_MODE is on: composition is exercised, timings are meaningless");
    }
    let ms: Vec<usize> = std::env::args()
        .skip(1)
        .map(|a| a.parse().expect("an M"))
        .collect();
    let ms = if ms.is_empty() { vec![1, 3, 5] } else { ms };

    println!("| M | prove (s) | proof bytes |");
    println!("|---:|---:|---:|");
    for m in ms {
        match run(m) {
            Ok((secs, bytes)) => println!("| {m} | {secs:.1} | {bytes} |"),
            Err(e) => println!("| {m} | failed | {e} |"),
        }
    }
}
