//! Approval-verification cost against M, on LEZ v0.4 (actors).
//!
//! One `Execute` carrying M approvals over a transfer out of the vault PDA.
//! The transaction is the whole thing the chain would run: the quorum check,
//! the clock's expiry assertion, and the debit. Cycles are what the public gas
//! cap meters; gas is cycles one for one, and `MAX_GAS_EXEC` is 10,000,000.
//!
//! `cargo run --release -p ostrakon-host --bin measure`

use lee_core::{
    account::{AccountId, Actor},
    native_token,
};
use ostrakon_core::{digest, vault_seed, Action, Msg, Msig, MAX_MEMBERS};
use ostrakon_host::{Key, Meter, GAS_CAP};

const MULTISIG_ACCOUNT: AccountId = AccountId::new([0x31; 32]);
const DEST: AccountId = AccountId::new([0xD1; 32]);
const NONCE: [u8; 32] = [0x01; 32];
const NOW: u64 = 1_700_000_000_000;
const EXPIRES_AT: u64 = 1_700_000_600_000;

/// Cycles of one `Execute` paying out of the vault, approved by M distinct
/// members of an M-member multisig.
fn execute_at(m: usize, backend: &str) -> Result<u64, String> {
    let (program, program_id) = match backend {
        "stock" => (
            ostrakon_methods::ostrakon_stock(),
            ostrakon_methods::ostrakon_stock_id(),
        ),
        "fast" => (
            ostrakon_methods::ostrakon_fast(),
            ostrakon_methods::ostrakon_fast_id(),
        ),
        "plumbing" => (
            ostrakon_methods::ostrakon_plumbing(),
            ostrakon_methods::ostrakon_plumbing_id(),
        ),
        _ => (ostrakon_methods::ostrakon(), ostrakon_methods::ostrakon_id()),
    };
    let me = Actor::new(MULTISIG_ACCOUNT, program_id);
    let vault = AccountId::for_public_pda(&program_id, &vault_seed(&MULTISIG_ACCOUNT));

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
    })
    .expect("borsh");

    let mut meter = Meter::new(
        [
            (program_id, program),
        ],
        [
            (me, borsh::to_vec(&config).expect("borsh").into()),
            (
                Actor::native_balance(vault),
                native_token::encode_balance(1_000_000),
            ),
        ],
        GAS_CAP,
    );
    meter
        .run(
            me,
            message,
            vec![
                Actor::native_balance(vault),
                Actor::native_balance(DEST),
            ],
        )
        .map_err(|e| e.to_string())?;
    Ok(meter.cycles)
}

fn pct(c: u64) -> String {
    format!("{:.1}%", c as f64 * 100.0 / GAS_CAP as f64)
}

fn main() {
    let backend = if std::env::args().any(|a| a == "--stock") {
        "stock"
    } else if std::env::args().any(|a| a == "--fast") {
        "fast"
    } else if std::env::args().any(|a| a == "--plumbing") {
        "plumbing"
    } else {
        "k256"
    };
    match backend {
        "stock" => println!("the same guest, built against the stock `k256` (no accelerator)"),
        "fast" => println!("the same guest, verifying on our own GLV + wNAF loop"),
        _ => {}
    }
    println!("| M | execute cycles | share of the 10M gas cap | marginal per approval |");
    println!("|---:|---:|---:|---:|");
    let mut prev: Option<(usize, u64)> = None;
    let mut largest = 0;
    for m in [1usize, 2, 3, 5, 10, 16, 24, MAX_MEMBERS] {
        match execute_at(m, backend) {
            Ok(c) => {
                let marginal = match prev {
                    Some((pm, pc)) if m > pm => {
                        format!("{}", (c.saturating_sub(pc)) / (m - pm) as u64)
                    }
                    _ => "-".to_string(),
                };
                println!("| {m} | {c} | {} | {marginal} |", pct(c));
                prev = Some((m, c));
                if c <= GAS_CAP {
                    largest = m;
                }
            }
            Err(e) => {
                println!("| {m} | refused | | {} |", e.lines().next().unwrap_or(""));
                break;
            }
        }
    }
    println!();
    println!("largest M measured within one transaction: {largest}");
}
