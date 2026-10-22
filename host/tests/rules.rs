//! One test per rule, against the committed guest binary, through the state
//! machine's own execution, under the 10,000,000-cycle cap.
//!
//! Every refusal here fails the whole transaction, chained calls included.

use lee_core::{
    account::{AccountId, Actor},
    native_token,
};
use ostrakon_core::{digest, vault_seed, Action, Msg, Msig, Sig};
use ostrakon_host::{Key, Meter, GAS_CAP};

const MULTISIG_ACCOUNT: AccountId = AccountId::new([0x31; 32]);
const OTHER_MULTISIG: AccountId = AccountId::new([0x32; 32]);
const DEST: AccountId = AccountId::new([0xD1; 32]);
const NONCE: [u8; 32] = [0x01; 32];
const OTHER_NONCE: [u8; 32] = [0x02; 32];
const NOW: u64 = 1_700_000_000_000;
const EXPIRES_AT: u64 = 1_700_000_600_000;

struct Fixture {
    /// The timestamp window the last run's program asked for.
    window: std::cell::Cell<Option<(Option<u64>, Option<u64>)>>,
    me: Actor,
    vault: AccountId,
    keys: Vec<Key>,
    config: Msig,
}

/// Which guest the suite runs against. `OSTRAKON_BACKEND=fast` runs every rule
/// through the GLV + wNAF verifier instead of the patched `k256`, which is how
/// the two backends are held to the same behaviour and not merely to the same
/// published test vectors.
fn guest() -> (lee::program::Program, AccountId) {
    if std::env::var("OSTRAKON_BACKEND").as_deref() == Ok("fast") {
        (
            ostrakon_methods::ostrakon_fast(),
            ostrakon_methods::ostrakon_fast_id(),
        )
    } else {
        (ostrakon_methods::ostrakon(), ostrakon_methods::ostrakon_id())
    }
}

fn fixture(n: usize, threshold: u32) -> Fixture {
    let program_id = guest().1;
    let mut keys: Vec<Key> = (0..n).map(|i| Key::new(40 + i as u8)).collect();
    keys.sort_by_key(Key::public);
    Fixture {
        window: std::cell::Cell::new(None),
        me: Actor::new(MULTISIG_ACCOUNT, program_id),
        vault: AccountId::for_public_pda(&program_id, &vault_seed(&MULTISIG_ACCOUNT)),
        config: Msig {
            members: keys.iter().map(Key::public).collect(),
            threshold,
            epoch: 0,
            executed: Vec::new(),
        },
        keys,
    }
}

impl Fixture {
    fn transfer(&self) -> Action {
        Action::Transfer {
            vault: self.vault,
            to: DEST,
            amount: 1,
        }
    }

    /// Runs one `Execute` with `approvals`.
    fn execute(&self, approvals: Vec<Sig>) -> Result<u64, String> {
        self.execute_with(NONCE, approvals)
    }

    fn execute_with(&self, nonce: [u8; 32], approvals: Vec<Sig>) -> Result<u64, String> {
        let message = borsh::to_vec(&Msg::Execute {
            nonce,
            at: NOW,
            expires_at: EXPIRES_AT,
            action: self.transfer(),
            approvals,
        })
        .expect("borsh");
        self.run_message(message)
    }

    fn run_message(&self, message: Vec<u8>) -> Result<u64, String> {
        let mut meter = Meter::new(
            [
                (self.me.program_account_id, guest().0),
                ],
            [
                (self.me, borsh::to_vec(&self.config).expect("borsh").into()),
                (
                    Actor::native_balance(self.vault),
                    native_token::encode_balance(1_000_000),
                ),
                ],
            GAS_CAP,
        );
        meter
            .run(
                self.me,
                message,
                vec![
                    Actor::native_balance(self.vault),
                    Actor::native_balance(DEST),
                ],
            )
            .map_err(|e| e.to_string())?;
        self.window.set(
            meter
                .windows
                .first()
                .map(|w| (w.timestamps.start(), w.timestamps.end())),
        );
        Ok(meter.cycles)
    }

    /// A valid quorum's signatures over the transfer, under `epoch`.
    fn approvals(&self, count: usize, epoch: u32) -> Vec<Sig> {
        self.approvals_for(&NONCE, count, epoch)
    }

    fn approvals_for(&self, nonce: &[u8; 32], count: usize, epoch: u32) -> Vec<Sig> {
        let d = digest(&self.me, epoch, nonce, EXPIRES_AT, &self.transfer());
        self.keys.iter().take(count).map(|k| k.sign(&d)).collect()
    }
}

#[test]
fn a_quorum_executes() {
    let f = fixture(5, 3);
    f.execute(f.approvals(3, 0)).expect("a quorum executes");
}

#[test]
fn an_action_cannot_execute_below_threshold() {
    let f = fixture(5, 3);
    let err = f.execute(f.approvals(2, 0)).unwrap_err();
    assert!(err.contains("below the threshold"), "{err}");
}

#[test]
fn a_non_member_cannot_approve() {
    let f = fixture(5, 3);
    let mut approvals = f.approvals(2, 0);
    let stranger = Key::new(200);
    let d = digest(&f.me, 0, &NONCE, EXPIRES_AT, &f.transfer());
    approvals.push(stranger.sign(&d));
    approvals.sort_by_key(|a| a.key);
    let err = f.execute(approvals).unwrap_err();
    assert!(err.contains("not a current member"), "{err}");
}

#[test]
fn a_key_cannot_sign_twice() {
    let f = fixture(5, 3);
    let mut approvals = f.approvals(2, 0);
    approvals.push(approvals[0].clone());
    approvals.sort_by_key(|a| a.key);
    let err = f.execute(approvals).unwrap_err();
    assert!(err.contains("signed twice"), "{err}");
}

#[test]
fn approvals_out_of_order_are_refused() {
    let f = fixture(5, 3);
    let mut approvals = f.approvals(3, 0);
    approvals.reverse();
    let err = f.execute(approvals).unwrap_err();
    assert!(err.contains("ascending"), "{err}");
}

#[test]
fn a_configuration_out_of_order_is_refused() {
    let mut f = fixture(5, 3);
    f.config.members.reverse();
    let err = f.execute(f.approvals(3, 0)).unwrap_err();
    assert!(err.contains("ascending") || err.contains("not a current member"), "{err}");
}

#[test]
fn an_approval_does_not_survive_a_configuration_change() {
    // Signed under epoch 1; the stored configuration is at epoch 0, so the
    // digest the program recomputes is not the one that was signed.
    let f = fixture(5, 3);
    let err = f.execute(f.approvals(3, 1)).unwrap_err();
    assert!(err.contains("does not verify"), "{err}");
}

#[test]
fn an_approval_for_another_multisig_is_refused() {
    let f = fixture(5, 3);
    let elsewhere = Actor::new(OTHER_MULTISIG, f.me.program_account_id);
    let d = digest(&elsewhere, 0, &NONCE, EXPIRES_AT, &f.transfer());
    let approvals = f.keys.iter().take(3).map(|k| k.sign(&d)).collect();
    let err = f.execute(approvals).unwrap_err();
    assert!(err.contains("does not verify"), "{err}");
}

#[test]
fn an_executed_action_cannot_execute_again() {
    let mut f = fixture(5, 3);
    let d = digest(&f.me, 0, &NONCE, EXPIRES_AT, &f.transfer());
    f.config.executed.push((d, EXPIRES_AT));
    let err = f.execute(f.approvals(3, 0)).unwrap_err();
    assert!(err.contains("already executed"), "{err}");
}

#[test]
fn the_transaction_is_bounded_by_the_expiry() {
    // The program names no clock and sends no message: it bounds the
    // transaction, and the sequencer refuses it outside those times. The
    // upper bound is exclusive, so an action never lands at or after its
    // expiry. (LEZ tests the enforcement; what belongs here is that the
    // program asks for the right window.)
    let f = fixture(5, 3);
    f.execute(f.approvals(3, 0)).expect("a quorum executes");
    assert_eq!(f.window.get(), Some((Some(NOW), Some(EXPIRES_AT))));
}

#[test]
fn an_execute_whose_window_has_already_closed_is_refused() {
    let f = fixture(5, 3);
    let message = borsh::to_vec(&Msg::Execute {
        nonce: NONCE,
        at: EXPIRES_AT,
        expires_at: EXPIRES_AT,
        action: f.transfer(),
        approvals: f.approvals(3, 0),
    })
    .expect("borsh");
    let err = f.run_message(message).unwrap_err();
    assert!(err.contains("window is empty"), "{err}");
}

#[test]
fn two_identical_payments_need_only_a_different_nonce() {
    // Same vault, recipient, amount, epoch and expiry. The first has executed,
    // so its digest is on the record; the second differs only by its nonce and
    // must still go through.
    let mut f = fixture(5, 3);
    let first = digest(&f.me, 0, &NONCE, EXPIRES_AT, &f.transfer());
    f.config.executed.push((first, EXPIRES_AT));

    let err = f
        .execute_with(NONCE, f.approvals_for(&NONCE, 3, 0))
        .unwrap_err();
    assert!(err.contains("already executed"), "{err}");

    f.execute_with(OTHER_NONCE, f.approvals_for(&OTHER_NONCE, 3, 0))
        .expect("a second identical payment under a fresh nonce executes");
}

#[test]
fn an_approval_does_not_move_to_another_nonce() {
    let f = fixture(5, 3);
    let err = f
        .execute_with(OTHER_NONCE, f.approvals_for(&NONCE, 3, 0))
        .unwrap_err();
    assert!(err.contains("does not verify"), "{err}");
}
