# WORKLOG — ONE-1764 [ED-08] Publisher loop

Branch `ONE-1764` off `origin/main` @ `9daac87f4`.
Blueprint: `/Users/olety/.claude-wave5/blueprints/ED/ONE-1764.md`.

## Base reality check (vs blueprint provenance note)

The blueprint's 2026-08-05 reground says `ProposalTextArtifact` / `ProposalArtifactRef`
"do not exist in the engine (`rg = 0`)" and re-anchors the digest off an unnamed
in-vault proposal-text artifact. **On this base they DO exist** — ED-00 landed under
exactly those names:

- `crates/oneiron/src/edit_distance.rs:118` — `pub struct ProposalArtifactRef(EntityId)`
- `crates/oneiron/src/edit_distance/proposal_text.rs:98` — `pub struct ProposalTextArtifact`

The blueprint explicitly binds the **door contract**, not the type names ("this lane
binds the door contract … never the type names"). So the interview arm consumes the
landed names. No deviation — the blueprint's own escape hatch covers it.

ED-B (`attribution.rs` 1759, `miner.rs` 1760) is absent as expected. `escalation.rs`
(1762) and `graduation.rs` (1761) ARE landed on this base.

## Deviations from the blueprint skeleton

### D1 — `IssueSignature::new` gains a `&ModelStackRegistry` parameter

Blueprint skeleton:
```rust
pub fn new(category: IssueCategory, artifact: EntityId, version: u32,
           model_id: &str, counts: &[(CountKey, u32)], content_hash: &str) -> Result<Self>;
```
Shipped: `registry: &ModelStackRegistry` inserted immediately before `model_id`
(every ratified parameter keeps its relative order).

Why: the ratified rule is "`model_id` validated against
`settings/model_versioning.rs::ModelStackRegistry` (reject unknown ids — an unknown
'model id' is a smuggling channel)". Membership cannot be tested without the registry
in hand. The two alternatives are worse: calling `default_model_stack_registry()`
inside the constructor hard-wires the compiled default (a vault running a different
stack set could never emit a signature, and the smuggling gate becomes untestable), and
dropping the check entirely re-opens the exact smuggling channel the keystone exists to
close. The parameter is the only shape that makes the ratified semantic true.

### D2 — interview doors gain `actor` / `draft` / artifact parameters

Blueprint skeleton:
```rust
pub fn open_interview(vault: &Vault, topic: &EntityId) -> Result<InterviewSession>;
pub fn settle_interview_digest(vault: &Vault, s: InterviewSession) -> Result<EntityId>;
```
Shipped (both `#[cfg(feature = "sync")]`, because ED-00's door is):
```rust
pub fn open_interview(vault, topic, actor: &WriteActor, draft: &str)
    -> PublisherResult<(InterviewSession, ProposalTextArtifact)>;
pub fn settle_interview_digest(vault, session: InterviewSession, digest: ProposalTextArtifact)
    -> PublisherResult<EntityId>;
```

Why: ED-00's public door is `ProposalTextArtifact::open(initial, actor, source_turn_ref)`
— there is no way to mint a digest artifact without an actor and an initial body, and
no way to finalize one without the artifact value itself (`finalize(self, vault)`
consumes it). The skeleton's two-argument shape cannot call the door it is ratified to
call. Returning the artifact is what lets the caller reach ED-00/ED-01's edit doors at
all; without it `open_interview` would mint an artifact nobody can edit. Return type of
`settle_interview_digest` stays `EntityId` as ratified — the Δ is reachable from it via
`finalized_proposal_text` + `delta_from_recorded_ops`, so nothing is lost.

`register_peer_actor(vault, artifact.peer_id(), actor)` inside `open_interview` is what
makes the `vault` parameter load-bearing: without the peer→actor binding ED-00 refuses
to honor the stamp and the settle Δ attributes to the device peer instead of the user.

### D3 — "receipted skip" is a durable send-state row, not a receipt record

Done-mean: "Dial OFF → `send_signatures_if_enabled` stores + skips send, **receipted
skip**".

The engine has **no generic receipt-write door**: `ReceiptRecord`s are *projected* from
durable records (gate decisions, comm records, attempt packs) — `receipt.rs` exposes
readers and projections only. Minting a receipt-write primitive is outside the packet
and would be a new primitive, which the blueprint forbids ("no new comm primitives").
Emitting a *comm* receipt for a withheld signature is self-contradicting: the comm
receipt IS the send.

Shipped instead: a `SignatureSendState { Pending, Withheld, Sent }` row in `vault_meta`
keyed by signature id, in its own key space so the ratified `IssueSignature` record
shape stays byte-exact. A skip is therefore durable, readable and asserted
(`signature_send_state` → `Withheld`), which is what "receipted" is for. Flagged as an
interpretation, not silently absorbed.

### D4 — default resolution: explicit dial outranks the install profile

Blueprint: "documented default-resolution order (install profile > setting > compiled
default)".

Shipped chain: explicit dial (`PUBLISHER_ENABLED_KEY`) → install profile
(`PUBLISHER_INSTALL_DEFAULT_KEY`) → compiled default
(`PUBLISHER_ENABLED_COMPILED_DEFAULT`).

Why: read as written, an install profile that overrides a dial the user explicitly set
converts the dial into a wall — which the same blueprint line forbids ("dial off →
signatures still computed + stored locally, nothing sent — **dial, not wall**"). The
blueprint's three-source order is read as the *default*-resolution chain (what applies
when the user has not ruled), with the user's explicit setting on top. Owner-visible
call; flagged for the board.

Compiled default is **disabled**. ARCH-0056 §9 rung 1: "Cloud default ON (owner ruling
r6); self-host picks posture at install". The engine cannot know its posture, and it is
the OSS/self-hostable artifact — so the cloud posture's ON arrives as an install-profile
row, and a bare self-host build sends nothing to a publisher it never chose. This is
posture resolution, not a fail-closed wall: one write flips it.

### D5 — emission arm grounded on `ProposalOutcome`, not on an ED-B cluster type

EMISSION-ARM CONSTRAINT honored. ED-03/ED-04 judged clusters do not exist on this base,
so nothing speculative is invented. The judged-cluster→counts bridge binds the surfaces
that DO exist: `identity_topology::ProposalOutcome` (the ratified three-state judged
outcome, ARCH-0055 r7) tallied over `ReceiptRecord`s —
`tally_judged_outcomes(&[ReceiptRecord]) -> [(CountKey, u32); 3]`. When ED-03/ED-04
land, their cluster passes its own receipts through the same door; no type in this lane
needs to change.

`CountKey` is `{ Judged, Amended, Rejected }` — each arm one-to-one with a landed
`ProposalOutcome` fact. Deliberately NOT edit mass (`ins`/`del`/`kept`/`d_norm`):
ARCH-0056 §9's rung-1 row says signatures carry "counts, pattern hashes. **NEVER text,
NEVER deltas**", and `OpsSummary` numbers are the delta.

### D6 — `IssueCategory` pinned to `skill_attribution::AttributionVerdict`

The keystone ratifies `pub enum IssueCategory`, so it is minted rather than reusing
`AttributionVerdict` directly (which is skill-routing-scoped). Fork risk is closed
mechanically: `IssueCategory::from_verdict` plus a test asserting token equality across
every arm, so the two taxonomies cannot drift apart silently.

## PACKET_AMEND candidates

None. Final `git diff --name-only` is inside the declared packet:
`edit_distance/publisher.rs` (new) + `publisher/tests.rs` (new) + `edit_distance.rs`
(one `pub mod` line) + `lib.rs` (re-exports) + this worklog.

`comm.rs` is **untouched** — the three public doors are consumed from `publisher.rs`,
no internal edits (rider 3 satisfied more strictly than the packet allows).
`settings.rs`, `settings/model_versioning.rs`, `disclosure.rs`, `Cargo.toml`,
`Cargo.lock` untouched.

## Done-means status

- [x] Signature emission from a judged-outcome fixture; constructor refuses sentinel
      free-text at every `&str` argument position (unknown model id, non-hex hash);
      duplicate count key rejected; serialized record contains zero sentinel bytes.
- [x] Publisher party resolves/creates once; signatures land as comm send receipts;
      projector run shows the thread.
- [x] Dial OFF → stores + skips send, skip durably recorded; dial ON → sends. Default
      resolution order tested across all three sources.
- [x] Interview: open creates the digest via ED-00's public door → amendment via the
      landed edit door → settle emits a Δ through ED-01's `delta_from_recorded_ops`.
      No edit-distance computation inside `publisher.rs`.
- [x] No screen/UI code; only existing comm.rs doors called.
- [x] Gates: fmt · clippy -D warnings (`--all-targets --all-features`) · test -p oneiron
      --all-features · default-features build.

## Gate evidence

- `cargo fmt -p oneiron` — clean.
- `cargo clippy -p oneiron --all-features --all-targets -- -D warnings` — clean.
- `cargo test -p oneiron --all-features` — **cargo exit 0**, lib `3822 passed; 0 failed;
  17 ignored`, every integration suite `ok`, doctests `ok`. All 13 publisher tests ran
  inside that suite.
- `cargo check -p oneiron` (default features, no `sync`) — compiles. The single
  `dead_code` warning (`batch.rs::facet_of_endpoints_provably_off_table`) is
  **pre-existing on the base**: present at `9daac87f4`, charged to no lane.

Note on exit-code masking: the first full-suite run was piped through `tail`, so its
exit status was `tail`'s, not cargo's. Re-run unpiped with the status captured directly
— the numbers above are from that run.

## Seam note for ED-03 (1759)

`edit_distance.rs` gains exactly one line (`pub mod publisher;`) appended after
`pub mod proposal_text;`. 1759 appends `pub mod attribution;` to the same list;
alphabetically it lands above `delta`, so a textual conflict is unlikely and the
merge-in law resolves it either way.
