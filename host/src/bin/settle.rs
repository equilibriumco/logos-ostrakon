//! The whole private lifecycle, settled.
//!
//! `private.rs` proves a transaction and stops. This one goes the rest of the
//! way, three times. Each step builds a real `PrivacyPreservingTransaction`,
//! has the state machine **validate** it — the privacy circuit's proof
//! verified against its image id, nullifiers checked against the spent set,
//! commitments checked for membership — and then **applies** it to chain
//! state. That pair of calls is what a sequencer makes when it puts a
//! transaction in a block.
//!
//! 1. **Create** — the configuration is written into a private account.
//! 2. **Fund** — a public account pays the vault, a private PDA of this
//!    program that no key authorises.
//! 3. **Execute** — a 5-of-5 quorum spends the vault, and the payout lands.
//!
//! Nothing is seeded. Each transaction proves against the state the previous
//! one settled, so the membership proofs are real paths into a commitment
//! tree that earlier settled transactions built. After each step the
//! plaintext we believe the chain now commits to is checked against the
//! commitment it actually recorded — and a private account's successor takes
//! the nonce its predecessor's transition hands on, which is why that check
//! is worth making rather than assuming.
//!
//! Finally the execute is submitted again and is refused with `Commitment
//! already seen`: validation rejects it before application, so the nullifier
//! check never runs, though it would refuse it too. Either way the refusal is
//! the chain's, independent of the program's executed-digest record.
//!
//! ```sh
//! RISC0_DEV_MODE=1 cargo run --release -p ostrakon-host --features prove --bin settle
//! RISC0_DEV_MODE=0 cargo run --release -p ostrakon-host --features prove --bin settle
//! ```

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::time::Instant;

use lee::{
    error::LeeError,
    execute_and_prove,
    privacy_preserving_transaction::{circuit::ProgramCatalog, Message, WitnessSet},
    PrivacyPreservingTransaction, PrivateKey, ProvingInput, PublicExecutionContext, PublicKey,
    SenderPresentation, Simulation, V03State,
};
use lee_core::{
    account::{Account, AccountId, Actor, Nonce},
    encryption::ViewingPublicKey,
    execution_state::TransactionEntry,
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::MessageBody,
    AuthorizationSecretKey, Commitment, NullifierPublicKey, NullifierSecretKey, NullifierWitness,
    PrivateWitness, RecipientEncryption, RegularKey, RootCall, WitnessKind, DUMMY_COMMITMENT_HASH,
};
use ostrakon_core::{digest, vault_seed, Action, Msg, Msig};
use ostrakon_host::Key;

const DEST: AccountId = AccountId::new([0xD1; 32]);
const FUNDING: u128 = 100_000;
const PAYOUT: u128 = 7_000;
const NONCE: [u8; 32] = [0x01; 32];
const NOW: u64 = 1_700_000_000_000;
const EXPIRES_AT: u64 = 1_700_000_600_000;
const M: usize = 5;

fn no_seal(body: &MessageBody) -> Result<RecipientEncryption, LeeError> {
    Err(LeeError::InvalidInput(format!("no seal for {:?}", body.to)))
}

/// The private-account key material every member derives from the group
/// secret. It lets a member read these accounts and build transactions on
/// them; it does not let one spend the vault, which is why the vault is a PDA.
struct Group {
    ask: AuthorizationSecretKey,
    vpk: ViewingPublicKey,
}

impl Group {
    fn new(tag: u8) -> Self {
        Self {
            ask: AuthorizationSecretKey([tag; 32]),
            vpk: ViewingPublicKey::from_seed(&[tag; 32], &[tag.wrapping_add(1); 32]),
        }
    }
    fn nsk(&self) -> NullifierSecretKey {
        NullifierSecretKey::from(&self.ask)
    }
    fn npk(&self) -> NullifierPublicKey {
        NullifierPublicKey::from(&self.nsk())
    }
    fn ask(&self) -> AuthorizationSecretKey {
        AuthorizationSecretKey(self.ask.0)
    }
    /// The account the configuration lives on.
    fn config_account(&self) -> AccountId {
        AccountId::for_regular_private_account(&self.npk(), &self.vpk)
    }
}

/// One transaction to settle.
struct Step<'a> {
    label: &'a str,
    input: ProvingInput,
    simulation: Simulation,
    /// The private account a payment is going to, if any. The circuit needs
    /// to know which outgoing message stays inside it.
    private_recipient: Option<AccountId>,
    nonces: BTreeMap<AccountId, Nonce>,
    signers: Vec<&'a PrivateKey>,
}

/// Prove, build, validate, apply — and report what it cost.
fn settle(
    state: &mut V03State,
    catalog: &ProgramCatalog,
    block: u64,
    step: Step<'_>,
) -> anyhow::Result<(Vec<Commitment>, PrivacyPreservingTransaction)> {
    let recipient = step.private_recipient;
    let started = Instant::now();
    let (output, proof) = execute_and_prove(
        step.input,
        &step.simulation,
        catalog,
        |_| SenderPresentation::Canonical,
        |_, body: &MessageBody| recipient.is_some_and(|r| body.to.account_id == r),
        no_seal,
    )?;
    let proved = started.elapsed().as_secs_f64();
    let commitments = output.execution.commitments();

    let message = Message::from_circuit_output(step.nonces, output);
    let witness_set = WitnessSet::for_message(&message, proof, &step.signers);
    let tx = PrivacyPreservingTransaction::new(message, witness_set);
    let bytes = borsh::to_vec(&tx)?.len();

    let at = Instant::now();
    state.transition_from_privacy_preserving_transaction(&tx, block, NOW)?;
    println!(
        "  {:<8} proved {proved:>7.1} s   {bytes:>7} bytes   validated and applied in {:.3} s",
        step.label,
        at.elapsed().as_secs_f64()
    );
    Ok((commitments, tx))
}

fn main() -> anyhow::Result<()> {
    if std::env::var("RISC0_DEV_MODE").is_ok_and(|v| v != "0" && !v.is_empty()) {
        println!("RISC0_DEV_MODE is on: the proofs are fake, the settlement path is real.\n");
    }

    let program = ostrakon_methods::ostrakon();
    let program_id = ostrakon_methods::ostrakon_id();
    let catalog = ProgramCatalog::from([(program_id, program.clone())]);
    let group = Group::new(3);

    let config_account = group.config_account();
    let seed = vault_seed(&config_account);
    let vault = AccountId::for_private_pda(&program_id, &seed, &group.npk(), &group.vpk);
    let me = Actor::new(config_account, program_id);

    // Whoever funds the vault: a public account, and the only account in the
    // whole lifecycle that signs a transaction.
    let payer_key = PrivateKey::try_new([7; 32]).expect("a valid key");
    let payer = AccountId::from(&PublicKey::new_from_private_key(&payer_key));

    let mut keys: Vec<Key> = (0..M).map(|i| Key::new(40 + i as u8)).collect();
    keys.sort_by_key(Key::public);
    let config = Msig {
        members: keys.iter().map(Key::public).collect(),
        threshold: M as u32,
        epoch: 0,
        executed: Vec::new(),
    };

    let mut state = V03State::new()
        .with_public_account_balances([(payer, FUNDING * 2), (DEST, 0)])
        .with_programs([program]);

    println!("configuration (private): {config_account}");
    println!("vault (private PDA):     {vault}");
    println!("payer (public):          {payer}");
    println!("recipient (public):      {DEST}");
    println!("threshold:               {M}-of-{M}\n");

    // ---------------------------------------------------------------- create
    let create_witness = PrivateWitness {
        vpk: group.vpk.clone(),
        random_seed: [0; 32],
        kind: WitnessKind::Regular(RegularKey::Authorized(group.ask())),
        nullifier: NullifierWitness::Init {
            commitment_root: DUMMY_COMMITMENT_HASH,
        },
        address_openings: BTreeSet::new(),
    };
    let (created, _) = settle(
        &mut state,
        &catalog,
        1,
        Step {
            label: "create",
            input: ProvingInput {
                root: TransactionEntry::Sync(RootCall {
                    to: me,
                    message: borsh::to_vec(&Msg::Create {
                        members: config.members.clone(),
                        threshold: config.threshold,
                    })?,
                }),
                public_context: PublicExecutionContext::new(Vec::new(), HashSet::new()),
                private_witnesses: vec![create_witness.clone()],
                dummy_inputs: Vec::new(),
                ciphertext_padding: None,
                recoveries: Vec::new(),
                private_promotions: BTreeSet::new(),
            },
            simulation: Simulation::default(),
            private_recipient: None,
            nonces: BTreeMap::new(),
            signers: Vec::new(),
        },
    )?;

    // What we believe the chain now commits to, checked against what it
    // recorded. If our model of the post-state were wrong, the execute's
    // membership proof would be for a leaf that is not there.
    // A private account's commitment is over a *blinded* account id, so it
    // cannot be derived from the plaintext alone. Take the one the settled
    // transaction recorded; the plaintext is what we know it wrote.
    let config_pre =
        Account::default().with_actor_state(program_id, borsh::to_vec(&config)?.into());
    anyhow::ensure!(created.len() == 1, "create records exactly one commitment");
    // A private account's successor takes the nonce its predecessor's
    // transition hands on, so the plaintext alone is not the commitment: the
    // nonce comes from the witness that wrote it.
    let mut config_pre = config_pre;
    config_pre.nonce = create_witness.transition()?.2;
    let config_commitment = Commitment::new(&config_account, &config_pre);
    anyhow::ensure!(
        created.contains(&config_commitment),
        "the configuration the create settled is not the one we modelled"
    );

    // ------------------------------------------------------------------ fund
    let fund_witness = PrivateWitness {
        vpk: group.vpk.clone(),
        random_seed: [1; 32],
        kind: WitnessKind::Pda {
            nsk: group.nsk(),
            binding: (program_id, seed),
        },
        nullifier: NullifierWitness::Init {
            commitment_root: DUMMY_COMMITMENT_HASH,
        },
        address_openings: BTreeSet::new(),
    };
    let payer_account = state.get_account_by_id(payer);
    let payer_actor = Actor::native_balance(payer);
    let (funded, _) = settle(
        &mut state,
        &catalog,
        2,
        Step {
            label: "fund",
            input: ProvingInput {
                root: TransactionEntry::Sync(RootCall {
                    to: payer_actor,
                    message: borsh::to_vec(&native_token::Message::Transfer {
                        to: vault,
                        amount: FUNDING,
                    })?,
                }),
                public_context: PublicExecutionContext::new(vec![payer_actor], [payer]),
                private_witnesses: vec![fund_witness.clone()],
                dummy_inputs: Vec::new(),
                ciphertext_padding: None,
                recoveries: Vec::new(),
                private_promotions: BTreeSet::new(),
            },
            simulation: Simulation {
                public_actor_states: [(
                    payer_actor,
                    payer_account
                        .data
                        .actor_state(NATIVE_TOKEN_PROGRAM_ID)
                        .clone(),
                )]
                .into(),
                admitted_accounts: None,
            },
            private_recipient: Some(vault),
            nonces: BTreeMap::from([(payer, payer_account.nonce)]),
            signers: vec![&payer_key],
        },
    )?;

    let vault_pre = Account::default().with_actor_state(
        NATIVE_TOKEN_PROGRAM_ID,
        native_token::encode_balance(FUNDING),
    );
    anyhow::ensure!(funded.len() == 1, "funding records exactly one commitment");
    let mut vault_pre = vault_pre;
    vault_pre.nonce = fund_witness.transition()?.2;
    let vault_commitment = Commitment::new(&vault, &vault_pre);
    anyhow::ensure!(
        funded.contains(&vault_commitment),
        "the vault the funding settled is not the one we modelled"
    );

    // --------------------------------------------------------------- execute
    let action = Action::Transfer {
        vault,
        to: DEST,
        amount: PAYOUT,
    };
    let d = digest(&me, config.epoch, &NONCE, EXPIRES_AT, &action);
    let before = state
        .get_account_by_id(DEST)
        .data
        .native_balance()
        .unwrap_or(0);
    let config_proof = state
        .get_proof_for_commitment(&config_commitment)
        .expect("the configuration the create settled");
    let vault_proof = state
        .get_proof_for_commitment(&vault_commitment)
        .expect("the vault the funding settled");

    let (_, executed) = settle(
        &mut state,
        &catalog,
        3,
        Step {
            label: "execute",
            input: ProvingInput {
                root: TransactionEntry::Sync(RootCall {
                    to: me,
                    message: borsh::to_vec(&Msg::Execute {
                        nonce: NONCE,
                        at: NOW,
                        expires_at: EXPIRES_AT,
                        action,
                        approvals: keys.iter().map(|k| k.sign(&d)).collect(),
                    })?,
                }),
                public_context: PublicExecutionContext::new(
                    vec![Actor::native_balance(DEST)],
                    HashSet::new(),
                ),
                private_witnesses: vec![
                    PrivateWitness {
                        vpk: group.vpk.clone(),
                        random_seed: [0; 32],
                        kind: WitnessKind::Regular(RegularKey::Authorized(group.ask())),
                        nullifier: NullifierWitness::Update {
                            account: config_pre,
                            membership_proof: config_proof,
                        },
                        address_openings: BTreeSet::new(),
                    },
                    PrivateWitness {
                        vpk: group.vpk.clone(),
                        random_seed: [1; 32],
                        kind: WitnessKind::Pda {
                            nsk: group.nsk(),
                            binding: (program_id, seed),
                        },
                        nullifier: NullifierWitness::Update {
                            account: vault_pre,
                            membership_proof: vault_proof,
                        },
                        address_openings: BTreeSet::new(),
                    },
                ],
                dummy_inputs: Vec::new(),
                ciphertext_padding: None,
                recoveries: Vec::new(),
                private_promotions: BTreeSet::new(),
            },
            simulation: Simulation::default(),
            private_recipient: None,
            nonces: BTreeMap::new(),
            signers: Vec::new(),
        },
    )?;

    let after = state
        .get_account_by_id(DEST)
        .data
        .native_balance()
        .unwrap_or(0);
    println!();
    println!("recipient balance  {before} -> {after}");
    anyhow::ensure!(after - before == PAYOUT, "the payout must land");
    println!(
        "payer balance      {}",
        state
            .get_account_by_id(payer)
            .data
            .native_balance()
            .unwrap_or(0)
    );

    // The execute, a second time. Its nullifiers are spent, so the chain
    // refuses it on its own rules — not on the program's executed record.
    let replay = state.transition_from_privacy_preserving_transaction(&executed, 4, NOW);
    let refused = replay.is_err();
    match replay {
        Ok(()) => println!("REPLAY ACCEPTED — the settled chain did not refuse it"),
        Err(e) => println!("replay refused     {e}"),
    }
    anyhow::ensure!(refused, "a settled transaction must not settle twice");
    Ok(())
}
