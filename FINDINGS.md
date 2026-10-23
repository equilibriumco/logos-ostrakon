# Ostrakon on LEZ v0.4: what is built, and what it was measured at

Every figure here is produced by code in this repository and reproducible with
one command.

- LEZ pinned at `9f004c6b90142b3de450c64e655cf699724b3e6f` (branch `dev`,
  2026-10-21). There is no v0.4 tag: the latest release is v0.3.1, and the
  actor model that replaced v0.3's plan/apply merged to `dev` on 2026-10-14.
- Machine: 20 cores, 93 GiB, Linux. CPU proving throughout.

## What the program does

An M-of-N multisig whose configuration and funds live in private accounts. The
chain learns that a valid quorum acted and nothing about who, or on what.

A member is a single-purpose BIP-340 approval key. No member's LEZ account is
ever named in a multisig transaction; the only account that signs one is
whoever pays the fee.

One `Execute` carries the action and a quorum's signatures over a digest that
binds the actor, the program, the epoch, the proposal's nonce, the expiry and
the action itself. The handler verifies them against the stored configuration,
records the digest, bounds the transaction to the window the approvals signed,
and makes the call.

Three properties make the quorum mean something, each with a test:

- **The funds live in a PDA.** The group secret authorises an *account*; the
  program authorises an *action*. A private PDA has no authorisation key, so
  the only way to spend it is a call this program attaches the seed to. The
  seed derives from the configuration's account, so one multisig's seed cannot
  reach another's vault.
- **Executed digests are recorded**, so an approved package runs once. Entries
  retire at their own expiry, which bounds the list. The digest carries the
  proposal's nonce, so two legitimately identical payments stay distinct.
- **The expiry bounds the transaction**, whose window the sequencer enforces.
  The program reads no clock and sends no message: asking the clock would mean
  messaging a public actor, and that publishes the sender (§6).

Not built, deliberately: roles, weights, time locks, cancel, spending limits, a
registry, selective disclosure, group-key renewal, any client, any deployment.

## 1. The actor model carries a multisig in 250 lines

v0.3 splits a program into `plan`, which cannot read state, and `apply`, which
can, so a multisig has to hand an *effect* across the split and check it there.
v0.4 deletes the split: one handler receives `ReceiveInput`, which carries
`pre_state` directly.

```rust
lee_core::actor_entrypoint!(ostrakon_core::handle);
```

The whole program is `core/src/lib.rs`. The guest binary is one line.

## 2. Approval verification cost

One `Execute` carrying M approvals over a transfer out of the vault: the quorum
check, the executed record and the debit, with the expiry bounding the
transaction's validity window, driven through `WholeExecution`
with the 10,000,000-cycle budget shared across every transition, as the
sequencer shares it. Gas is cycles one for one.

```sh
cargo run --release -p ostrakon-host --bin measure
```

| M | execute cycles | share of the 10M gas cap | marginal per approval |
|---:|---:|---:|---:|
| 1 | 287,050 | 2.9% | - |
| 2 | 560,435 | 5.6% | 273,385 |
| 3 | 834,894 | 8.3% | 274,459 |
| 5 | **1,376,784** | **13.8%** | 270,945 |
| 10 | 2,734,236 | 27.3% | 271,490 |
| 16 | 4,363,922 | 43.6% | 271,614 |
| 24 | 6,543,884 | 65.4% | 272,495 |
| 32 | 8,726,335 | 87.3% | 272,806 |

**About 272,000 cycles per approval, linear in M.** M = 5 uses 13.8% of a
transaction; M = 32, the member cap, still fits one. The budget is enforced
rather than reported: a transition that overruns it fails with `Session limit
exceeded`, as it would on chain.

Every row is bit-exact and reproduces across runs: the signatures are
deterministic and cycle counts do not depend on proving. Rebuilding a guest
under a different name or crate layout changes its ELF and does move the rows
slightly, so figures are only comparable within one build.

### Where the cycles go

Gas is what a transaction is bounded by, but it is not all cryptography. A
third guest accepts every signature unchecked (`--plumbing`), and both terms
come out of one dependency graph, so the subtraction holds.

| M | plumbing | total (fast) | cryptography | per approval |
|---:|---:|---:|---:|---:|
| 1 | 18,386 | 126,423 | 108,037 | 108,037 |
| 5 | 29,368 | 565,037 | 535,669 | **107,133** |
| 10 | 42,994 | 1,114,316 | 1,071,322 | 107,132 |
| 32 | 104,374 | 3,534,711 | 3,430,337 | 107,198 |

**The cryptography is flat in M at about 107,100 cycles a verification**, and
so is the program around it: the plumbing's marginal holds at about 2,750
cycles an approval from M = 2 to M = 32.

It did not start that way. Checking distinctness by scanning the approvals
already seen, and membership by scanning the configuration, made the plumbing
O(M²): on the build where it was found, its marginal climbed from 2,559 cycles
an approval to 3,548. Keeping both lists in ascending key order settles
distinctness and membership in one walk over the pair — a repeated key cannot
ascend, and a member once passed cannot be claimed again — and the marginal
has been flat since. The order is a stored invariant of the configuration,
enforced where it is written.

The same subtraction puts the patched `k256` path at about 269,500 cycles a
verification, so the ratio between the two backends is **2.5×**. Our v0.3
measurements published 267,647 cycles for the same check, on a different
runtime and a different program: within 0.7%.

What the whole `Execute` costs on the fast backend, against the same cap:

| M | execute cycles | share of the 10M gas cap |
|---:|---:|---:|
| 1 | 126,423 | 1.3% |
| 5 | 565,037 | 5.7% |
| 32 | 3,534,711 | 35.3% |

M = 5 falls from 13.8% of a transaction to 5.7%, and M = 32 from 87.3% to
35.3%. Every rule test passes on this backend too, refusals included:
`OSTRAKON_BACKEND=fast cargo test --release -p ostrakon-host --test rules`.

## 3. What the accelerated `k256` fork is worth

The same guest built without it, as a control:

```sh
cargo run --release -p ostrakon-host --bin measure -- --stock
```

| M | execute cycles | share of the cap |
|---:|---:|---:|
| 1 | 5,426,554 | 54.3% |
| 2 | refused — `Session limit exceeded: 10000000 >= 10000000` | |

About 5,408,000 cycles per verification against 269,500: **a factor of 20**.
Without the fork a single-signer multisig fits at half a transaction and a
2-of-N does not fit at all. The accelerator is not an optimisation; it is what
makes in-program approval verification possible.

## 4. It runs on private accounts

`host/src/bin/private.rs` runs the whole thing privately: the configuration in
the actor state of a private account every member derives from the group
secret, the funds in a private PDA bound to the program, the quorum checked
inside the privacy circuit, and only the recipient's balance public.

```sh
RISC0_DEV_MODE=1 cargo run --release -p ostrakon-host --features prove --bin private -- 1 3 5
```

Composition holds at M = 1, 3 and 5. Dev mode makes the receipt fake; the
circuit, the witnesses and the composition are real.

With real proving (`RISC0_DEV_MODE=0`), on this machine's 20 CPU cores, one
run per M on the committed binary:

| M | prove (s) | inner receipt (bytes) |
|---:|---:|---:|
| 1 | 220.7 | 226,215 |
| 5 | 298.5 | 226,343 |

The receipt grows by exactly 32 bytes per approval. The time grows by about
19 seconds per approval — one run per point, so a trend to re-measure on a
quiet machine rather than a settled slope, but it has held across every build
measured here: the signature work adds to the composed transaction rather
than vanishing inside the privacy circuit.

The same binary and the same inputs, on an Apple M5 Max with GPU proving:

| M | prove (s) | inner receipt (bytes) |
|---:|---:|---:|
| 1 | 197.3 | 226,215 |
| 5 | 228.9 | 226,343 |

The receipts match the CPU run byte for byte, so both machines prove the same
thing. The GPU takes the marginal cost from about 19 seconds an approval to
about 8, and the fixed cost from 220 seconds to 197. It helps the part that
grows with M, and barely touches the rest.

Both witnesses carry an empty membership proof. The circuit reads the
commitment-set digest out of that proof and never checks it against chain
state, so a synthetic proof costs what a real one of the same depth costs —
but depth zero is not a real depth. On a chain holding commitments the path
is tens of levels, the circuit hashes once per level, and there are two
private accounts here. These times do not include any of that.

## 5. The quorum is enforceable

```sh
RISC0_DEV_MODE=1 cargo run --release -p ostrakon-host --features prove --bin bypass
```

Two attacks, each holding the group-secret material the honest path uses, each
sending a native transfer straight at a balance actor with no approvals and the
program never invoked:

```
1. funds on the multisig's own account: DRAINED, no approvals
2. the vault PDA: refused: Program violated execution rules
```

The first is why the funds are not kept on the multisig's own account. The
second is the property the design rests on.

## 6. What a private execution publishes

```sh
RISC0_DEV_MODE=1 cargo run --release -p ostrakon-host --features prove --bin leak
```

The private posture rests on the chain learning that *some* program ran. Every
message a private actor sends to a public one is recorded as a boundary
crossing carrying the sender — an account id **and** a program account id — in
the clear. So the probe runs the real execution and prints every crossing, then
searches the published output for the program and the accounts.

This caught a design error of ours. Expiry was first enforced by asking the
clock actor to assert the time, which is a message to a public actor, and it
published both the multisig's program and the private account its
configuration lives on. The second is the worse of the two: a private account's
id is supposed to exist on chain only as a commitment, and publishing it links
every execution of one multisig together. Bounding the transaction instead —
the window travels with it and names nobody — removes both.

| | clock assertion | timestamp window |
|---|---|---|
| boundary crossings | 2 | 1 |
| multisig's account id published | yes | **no** |
| gas at M = 1 | 294,563 | 287,050 |

What remains, with the window:

- **Paying a public recipient names the vault**, under the token program, not
  under this one. That is the public recipient's doing, not the design's:
  paying a *private* recipient crosses no boundary at all and names nothing.
  Both are measured by the probe.
- **The program is named by its image claim**, because the probe deploys it
  mutably. An undisclosed claim needs an immutable deployment, which is a
  deployment choice and is not exercised here.

## 7. Settled, not only proved

```sh
RISC0_DEV_MODE=1 cargo run --release -p ostrakon-host --features prove --bin settle
```

Everything above proves transactions. This settles three of them, which is a
different claim: each is built as a real `PrivacyPreservingTransaction`, then
**validated** — the privacy circuit's proof verified against its image id, the
nullifiers checked against the spent set, the commitments checked for
membership — and **applied** to chain state. That pair of calls is what a
sequencer makes when it puts a transaction in a block.

1. **Create** — the configuration is written into a private account.
2. **Fund** — a public account pays the vault, a private PDA of this program.
3. **Execute** — a 5-of-5 quorum spends the vault, and the payout lands.

Nothing is seeded. Each transaction proves against the state the previous one
settled, so the membership proofs are real paths into a commitment tree the
earlier transactions built. The execute, submitted a second time, is refused
with `Commitment already seen`: validation rejects it before application, so
the nullifier check never runs, though it would refuse it too. Either way the
chain's own replay protection holds, independent of the program's
executed-digest record.

With real proving, on the 20 CPU cores:

| | prove (s) | transaction (bytes) | validated and applied (s) |
|---|---:|---:|---:|
| create | 152.7 | 226,341 | 0.012 |
| fund | 121.4 | 226,797 | 0.011 |
| execute | 310.8 | 229,559 | 0.011 |

These are the figures §4's caveat asks for. There the membership proofs are
empty, so the circuit hashes no path and the times understate a real chain;
here every proof is a real path into a tree the earlier transactions built,
and the execute carries two of them. The tree is three commitments deep, so
this is the floor rather than the full cost — a chain holding millions would
add a few dozen hashes per account — but it is no longer zero.

Validation is the cheap half: about eleven milliseconds to verify the proof,
check the nullifiers and apply the diff, against minutes to produce it. The
asymmetry is the point of the design.

There is no v0.4 testnet, so there is no public transaction to link. A link
lets a reviewer look; a command that re-runs the settlement lets them check.
Until a testnet exists this offers the second.

One thing worth recording, because it cost an afternoon: a private account's
successor takes the nonce its predecessor's transition hands on
(`PrivateWitness::transition()`), so the plaintext alone never determines the
commitment. Every step here asserts that the commitment the chain recorded is
the one our model of the post-state produces, which is what caught it.

## 8. The rules, one test each

```sh
cargo test --release -p ostrakon-host --test rules
```

Thirteen tests, under half a second, each driving the committed guest binary through the state
machine under the enforced cap:

- a quorum executes
- an action cannot execute below threshold
- a non-member cannot approve
- a key cannot sign twice
- approvals out of order are refused
- a configuration out of order is refused
- an approval does not survive a configuration change
- an approval for another multisig is refused
- an executed action cannot execute again
- the transaction is bounded by the expiry
- an execute whose window has already closed is refused
- two identical payments need only a different nonce
- an approval does not move to another nonce

Enforcing the window is the sequencer's job, so what belongs here is that the
program asks for the right one: `[at, expires_at)`, upper bound exclusive, so
an action never lands at or after its expiry.

## What this does not answer

- **Deposits.** A payment into a private account cannot update an existing one,
  so a vault accrues a family of accounts. Finding and merging them is not
  built.
- **Group-key renewal.** A removed member still holds the group secret and can
  read the configuration until the group re-keys. Not built.
- **`dev` is not a release.** No v0.4 tag, no v0.4 testnet, no deployment.
  Breaking changes land on `dev` weekly, which is why the pin is deliberate.
