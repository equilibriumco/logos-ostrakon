# logos-ostrakon

An M-of-N multisig as a **LEZ v0.4 actor**, with its configuration and its
funds in a private account: the chain learns that a valid quorum acted, and
nothing about who, or on what.

A member is a single-purpose BIP-340 approval key. No member's LEZ account is
ever named in a multisig transaction — the only account that signs one is
whoever pays the fee.

Pinned to LEZ `9f004c6b` on branch `dev`. There is no v0.4 tag yet; the actor
model that replaced v0.3's plan/apply merged on 2026-10-14.

## Run it

```sh
# approval-verification cost against M, under the enforced 10M gas cap
cargo run --release -p ostrakon-host --bin measure

# the same guest without the RISC Zero accelerated k256 fork: the control
cargo run --release -p ostrakon-host --bin measure -- --stock

# every rule, one test each, against the committed guest binary
cargo test --release -p ostrakon-host --test rules

# the multisig on private accounts, through the privacy circuit
RISC0_DEV_MODE=1 cargo run --release -p ostrakon-host --features prove --bin private -- 1 3 5

# the quorum is enforceable: two drain attempts, one refused
RISC0_DEV_MODE=1 cargo run --release -p ostrakon-host --features prove --bin bypass

# create, fund, execute — each validated and applied to chain state
RISC0_DEV_MODE=1 cargo run --release -p ostrakon-host --features prove --bin settle

# ... with real proving, which takes minutes per M
RISC0_DEV_MODE=0 cargo run --release -p ostrakon-host --features prove --bin private -- 1
```

Measured results are in [FINDINGS.md](FINDINGS.md): about 272,000 cycles per
approval, M = 5 at 13.8% of a transaction, M = 32 still fitting one, and a
factor of 20 between the accelerated and stock builds.

## Against a real sequencer

Everything above runs the program through the state machine in process.
`testnet/` runs it against the stack a chain actually is — Bedrock producing
blocks underneath, a sequencer, an indexer and a wallet — and deploys the
multisig there, immutably, which is what an undisclosed image claim needs.

```sh
cd testnet && ./run.sh
```

Nothing in LEZ is modified: its test fixtures come in as a pinned git
dependency, and its own resolver builds the Bedrock node. The script works out
the rest, because four things sit between a clean clone and a running stack
and none of them are ours — the wallet links PC/SC for Keycard, Nix's
pkg-config wrapper reads a target-suffixed variable, that libpcsclite wants a
newer glibc than the toolchain links against, and a fresh resolve picks a
`zip` that `utoipa-swagger-ui` cannot build against. `run.sh` documents each
one where it handles it.

The first run compiles the Bedrock L1 from source in Docker, because no
published release matches the revision LEZ pins. That takes minutes, once.

`testnet/` is its own workspace on purpose: it reaches for LEZ's test-support
crates, which are not a published API, and nothing in the main workspace
should depend on them.

## Layout

```
core/                the whole program: state, digest, BIP-340 quorum, handler
methods/guest/       the actor entrypoint, one line, accelerated k256
methods/guest-stock/ the same guest without the accelerator, as a control
host/                the harness: rule tests, cycles against M, the private
                     path, the drain attempts, and the settled lifecycle
testnet/             the same program against a real sequencer (own workspace)
```

`core` depends on no runtime beyond `lee_core`'s types and is tested on the
host without a zkVM. The guest shell is one line, so the runtime it targets is
the smallest replaceable part.

## Scope

Built: create; a quorum of distinct current members over a digest binding the
actor, the program, the epoch, the proposal's nonce, the expiry and the action; a payment out of a
vault PDA no key authorises; an executed-digest record that retires at expiry;
an expiry that bounds the transaction's validity window, so the program reads
no clock and sends no message to one; and reconfiguration, whose epoch
bump invalidates approvals gathered under the old configuration.

Not built: roles, weights, time locks, cancel, spending limits, a registry,
selective disclosure, group-key renewal, vault deposit handling, any client,
any deployment.

Copyright Equilibrium. All rights reserved; no licence is granted for now.

This repository is published so the figures in our RFP-005 bid can be checked,
not as a release. The work the bid funds is open source: every component
delivered under it is committed to MIT or Apache-2.0, and this code is
relicensed to match on award.
