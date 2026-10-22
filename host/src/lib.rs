//! Driving the multisig actor the way the sequencer does.
//!
//! `WholeExecution` is the state machine's own orchestration: a root delivery
//! and every send it triggers, each a guest run that sees only its receiver's
//! actor state. [`Meter`] implements the environment it runs against, counting
//! RISC Zero user cycles for every transition — which is what the public gas
//! cap meters, one for one.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use k256::schnorr::{signature::hazmat::PrehashSigner as _, SigningKey};
use lee::program::Program;
use lee_core::{
    account::{AccountId, Actor, ActorState},
    execution_state::{
        ExecutionEnvironment, PublicExecutionContext, TransactionEntry, TransitionView,
        WholeExecution,
    },
    from_frame, native_token,
    native_token::NATIVE_TOKEN_PROGRAM_ID,
    program::{ReceiveInput, Transition},
    RootCall,
};
use ostrakon_core::Sig;
use risc0_zkvm::{default_executor, ExecutorEnv};

/// The 10,000,000-gas cap of one public transaction
/// (`fee_core::market::MAX_GAS_EXEC`, 2 × `TARGET_GAS_EXEC`). Gas is cycles
/// one for one.
pub const GAS_CAP: u64 = 10_000_000;

/// A member's approval key: single-purpose, never a LEZ account key.
pub struct Key(SigningKey);

impl Key {
    #[must_use]
    pub fn new(tag: u8) -> Self {
        Self(SigningKey::from_bytes(&[tag.max(1); 32]).expect("a valid scalar"))
    }

    #[must_use]
    pub fn public(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes().into()
    }

    #[must_use]
    pub fn sign(&self, digest: &[u8; 32]) -> Sig {
        let sig: k256::schnorr::Signature = self.0.sign_prehash(digest).expect("signing");
        Sig {
            key: self.public(),
            sig: sig.to_bytes(),
        }
    }
}

/// Counts user cycles across every transition of one transaction.
pub struct Meter {
    programs: Vec<(AccountId, Program)>,
    actor_states: HashMap<Actor, ActorState>,
    budget: u64,
    pub cycles: u64,
    pub transitions: u32,
    /// The validity windows the program asked for. Enforcing them is the
    /// sequencer's job, not this harness's, so what a test can check here is
    /// that the program sets the window it promised.
    pub windows: Vec<lee_core::program::ValidityWindows>,
}

impl Meter {
    #[must_use]
    pub fn new(
        programs: impl IntoIterator<Item = (AccountId, Program)>,
        actor_states: impl IntoIterator<Item = (Actor, ActorState)>,
        budget: u64,
    ) -> Self {
        Self {
            programs: programs.into_iter().collect(),
            actor_states: actor_states.into_iter().collect(),
            budget,
            cycles: 0,
            transitions: 0,
            windows: Vec::new(),
        }
    }

    /// Delivers `message` to `root` and every send it triggers.
    pub fn run(&mut self, root: Actor, message: Vec<u8>, public_actors: Vec<Actor>) -> Result<()> {
        // Every actor a delivery can name has to be declared public (or be
        // private, which nothing here is); the root included.
        let mut actors = public_actors;
        actors.push(root);
        let context = PublicExecutionContext::new(actors, [root.account_id]);
        WholeExecution::new(
            context,
            TransactionEntry::Sync(RootCall { to: root, message }),
            &[],
        )?
        .execute(self)?;
        Ok(())
    }
}

impl ExecutionEnvironment for Meter {
    type Error = anyhow::Error;

    fn handle_message(
        &mut self,
        input: &ReceiveInput,
        _: &TransitionView<'_>,
    ) -> Result<Transition> {
        if input.receiver.program_account_id == NATIVE_TOKEN_PROGRAM_ID {
            return Ok(native_token::handle_message(input)?);
        }
        let program = self
            .programs
            .iter()
            .find(|(id, _)| *id == input.receiver.program_account_id)
            .map(|(_, p)| p.clone())
            .ok_or_else(|| {
                anyhow!("no guest registered at {}", input.receiver.program_account_id)
            })?;
        let mut builder = ExecutorEnv::builder();
        Program::write_receive_input(input, &mut builder)?;
        // The budget is shared across every transition of the transaction, as
        // the state machine shares it: each transition gets what is left, so
        // the transaction cannot exceed the cap in aggregate. Overrunning it
        // is an error here, not a number in a table.
        builder.session_limit(Some(self.budget.saturating_sub(self.cycles)));
        let env = builder.build()?;
        let info = default_executor().execute(env, program.elf())?;
        self.cycles = self.cycles.saturating_add(info.cycles());
        self.transitions = self.transitions.saturating_add(1);
        let journal = info.journal.bytes;
        let payload = from_frame(&journal).ok_or_else(|| anyhow!("malformed journal frame"))?;
        let transition: Transition = borsh::from_slice(payload)?;
        self.windows.push(transition.response.validity);
        Ok(transition)
    }

    fn public_actor_state(&mut self, actor: Actor) -> Result<ActorState> {
        Ok(self.actor_states.get(&actor).cloned().unwrap_or_default())
    }

    fn admits(&mut self, _account_id: AccountId) -> Result<bool> {
        Ok(true)
    }
}
