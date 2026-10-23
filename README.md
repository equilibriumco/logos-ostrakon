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

# every boundary crossing a private execution publishes
RISC0_DEV_MODE=1 cargo run --release -p ostrakon-host --features prove --bin leak

# create, fund, execute — each validated and applied to chain state
RISC0_DEV_MODE=1 cargo run --release -p ostrakon-host --features prove --bin settle

# the same two with real proving, which takes minutes each. Every timing in
# FINDINGS.md comes from these, not from the dev-mode runs above.
RISC0_DEV_MODE=0 cargo run --release -p ostrakon-host --features prove --bin private -- 1 5
RISC0_DEV_MODE=0 cargo run --release -p ostrakon-host --features prove --bin settle
```

Measured results are in [FINDINGS.md](FINDINGS.md): about 272,000 cycles per
approval, M = 5 at 13.8% of a transaction, M = 32 still fitting one, and a
factor of 20 between the accelerated and stock builds.

## Against a real sequencer

Everything above runs the program through the state machine in process.
`testnet/` runs it against the stack a chain actually is: Bedrock producing
blocks underneath, a sequencer, an indexer and a wallet. It deploys the
multisig there, immutably, which is what an undisclosed image claim needs.
None of the figures above come from it, and nothing else here depends on it.

```sh
cd testnet && ./run.sh
```

Needs `cargo`, Docker and, on Linux, `nix`. Podman is not enough: LEZ's
fixtures publish Bedrock's port as host port 0, meaning "pick a free one",
which Podman rejects as out of range.

Nothing in LEZ is modified: its test fixtures come in as a pinned git
dependency, and its own resolver builds the Bedrock node. `run.sh` supplies
what differs by platform and documents each piece where it handles it. On
macOS there is nothing to supply, since PC/SC is a system framework and the
binary runs as built. On Linux the wallet's libpcsclite comes out of nixpkgs,
which brings a target-suffixed `PKG_CONFIG_PATH` variable that Nix's
pkg-config wrapper reads, and a glibc newer than the toolchain links against,
so the binary runs under that loader.

The first run compiles the Bedrock L1 from source in a container, because no
published release matches the revision LEZ pins. That takes minutes, once. The
node it produces belongs to the LEZ revision this workspace pins, so a LEZ
clone at another revision has a different one and the fixtures reject it.

`testnet/` is its own workspace on purpose: it reaches for LEZ's test-support
crates, which are not a published API, and nothing in the main workspace
should depend on them.

## Layout

```
core/                the whole program: state, digest, BIP-340 quorum, handler
bip340/              BIP-340 over the zkVM's secp256k1 circuits, guest-only
methods/guest/       the actor entrypoint, one line, accelerated k256
methods/guest-stock/ the same guest without the accelerator, as a control
methods/guest-fast/  the same guest on the bip340 backend
methods/guest-plumbing/
                     the fast guest with signatures accepted unchecked, so
                     the difference is what the cryptography costs
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
