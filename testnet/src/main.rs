//! The multisig against a real LEZ sequencer.
//!
//! Everything else in this repository runs the program through the state
//! machine in process. This runs it against the stack a chain actually is:
//! Bedrock producing blocks underneath, a sequencer, an indexer and a wallet.
//!
//! Run it with `./run.sh`, which resolves the pieces LEZ's own fixtures need.

use anyhow::Result;

/// LEZ's stack prints whole transactions to stdout, so our own output goes to
/// stderr with a marker and `run.sh` shows that alone.
macro_rules! report {
    ($($arg:tt)*) => { eprintln!("ostrakon| {}", format!($($arg)*)) };
}

use integration_tests::{new_account, TestContext};
use program_loader_core::MAX_SEGMENT_DATA_LEN;
use wallet::program_facades::program_loader::ProgramLoader;

#[tokio::main]
async fn main() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    println!("sequencer up, {} zone(s)", ctx.zones_iter().count());

    // A genesis-funded account pays: every account a deploy touches is
    // freshly claimed and therefore unfunded.
    let payer = ctx.existing_public_accounts()[0];
    report!("payer                {payer}");

    // Deploy the multisig guest. `true` is the immutable flag — a header that
    // can never be updated again, which is what an undisclosed image claim
    // requires.
    let guest = ostrakon_methods::ostrakon();
    let elf = guest.elf().to_vec();
    let header = new_account(&mut ctx, false, None).await?;
    let mut segments = Vec::new();
    for _ in guest
        .user_elf()
        .expect("the guest is a valid program binary")
        .chunks(MAX_SEGMENT_DATA_LEN)
    {
        segments.push(new_account(&mut ctx, false, None).await?);
    }
    report!("deploying            {} segment(s)", segments.len());

    let program = ProgramLoader(ctx.wallet())
        .deploy(header, &segments, elf, true, Some(payer))
        .await?;
    report!("program deployed     {program}  (immutable)");

    Ok(())
}
