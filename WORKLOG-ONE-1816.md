# WORKLOG — ONE-1816 [BK-05] The agent front (constraint field)

Lane: BK-B L1, lane opener (dispatch gate: none). Branch `ONE-1816` off `origin/main` 8225cec4f.
Blueprint: `/Users/olety/.claude-wave5/blueprints/BK/ONE-1816.md`.

## Packet

Held exactly. `git status` at commit time shows only:

- CREATE `crates/oneiron/src/booking/mod.rs`
- CREATE `crates/oneiron/src/booking/constraint.rs`
- CREATE `crates/oneiron/src/booking/agent_front.rs`
- CREATE `crates/oneiron/src/booking/tests.rs`
- MODIFY `crates/oneiron/src/lib.rs` — `pub mod booking;` + one re-export block, append-only

No `Cargo.toml`, no `Cargo.lock`, no `registry.rs`, no entity/type byte, no `solver.rs`,
no server route, no docs/generated edit. **No PACKET_AMEND candidates.**

## Gates

- `cargo fmt -p oneiron -- --check` — clean
- `cargo clippy -p oneiron --all-features --all-targets` — zero warnings, zero errors
- `cargo test -p oneiron --all-features --lib booking_constraint` — 12/12 named oracles pass
- Full `cargo test -p oneiron --all-features` — see final section

## Blueprint deviations (declared, none silently absorbed)

### D1 — `TimeRange` has no serde derives; the seam owns its own wire adapter
The skeleton pins `ConstraintObject`/`SolveRequest` to `Serialize, Deserialize, Clone, Debug,
PartialEq` while carrying `crate::temporal::TimeRange` fields. Ground check: `TimeRange` derives
only `Debug, Clone, Copy, PartialEq, Eq` (temporal.rs:4) and has no manual serde impl anywhere in
the workspace. The blueprint assumed a serde-ready `TimeRange`.

Resolution: lane-local adapter modules `time_range_serde` / `opt_time_range_serde` in
`constraint.rs`, emitting `{"start":u64,"end":u64}`. temporal.rs is untouched, so the "one
`TimeRange` import path" law and the shared-file wall both hold. Rejected alternative: adding serde
derives to `temporal.rs` — an unclaimed shared file, and unnecessary once the seam owns its
serialization (which the blueprint already assigns to `constraint.rs`).

### D2 — `ModelId` is derived from the resolved tier, not hard-coded
`LlmRequest.model: ModelId` is mandatory, but the blueprint forbids hard-coding a provider/model id
and pins `ConstraintParseConfig` to exactly `{tier, max_input_bytes}` — so there is no field to
carry a host-supplied model id.

Resolution: `tier/<sanitized-resolved-tier-ref>@configured`, mirroring the existing
`llm.rs::dynamic_model_id` idiom used for on-device/endpoint safeguard bindings. The `tier` provider
segment is a routing namespace, not a vendor; the model NAME comes entirely from host config.
A tier that does not resolve returns `InvalidConfig` — never a silent fallback to an expensive or
ungoverned model. Asserted in `booking_constraint_fake_llm_request_is_bounded`, which also greps the
lane for vendor strings.

### D3 — a 1-slot solve renders ONE button, not two
`ConstraintSlotReply`'s blueprint doc comment says "exactly one VoiceLineAtom + 2..=3
ButtonControls", but the done-means governs the 1-slot case explicitly: "1 slot may be duplicated
only by asking the oracle for more and never by inventing one." Implementation renders
`slots.len().min(3)` buttons. Never-invent wins over the nominal 2..=3 shape; 0 slots is a
continuation, so the rendered range is 1..=3.

### D4 — `no_fit_line` is validated, not rendered, by this ticket
`ConstraintFrontOutcome::ContinueByEmail(ConstraintContinuation)` is blueprint-pinned and carries no
card, so no engine code path in this ticket renders `no_fit_line`. Rather than ship a config field
nothing reads, `ConstraintFrontCopy::validate()` checks all four strings at turn start; ONE-1815 /
ONE-1819 render the continuation from a checked value.

### D5 — `ModelLocality::ThirdParty` on the parse envelope
`CallEnvelope` requires a locality and the pinned config carries no locality dial. Chose
`ThirdParty`, matching `policy_model`'s default safeguard binding, on the reading that a host's cheap
parse tier is hosted. **Flagged for the screen**: if a host is expected to bind this purpose to an
on-device tier, locality must become a config dial (a one-field `ConstraintParseConfig` change) —
raise it there rather than guessing wider now.

### D6 — the parser system prompt is machine-facing Rust, precedent-grounded
`CLAUDE.md` forbids hard-coded prompt/persona or user-facing English in engine Rust. Grounding:
`policy_model::classify_system_prompt()` is exactly this shape — a terse machine instruction for a
classifier, never displayed. `constraint_system_prompt()` follows it. All VISIBLE copy (voice,
deflect, email) stays in `ConstraintFrontCopy`, the host-supplied localization seam.

## Judgment calls beyond the skeleton (bounds, not walls)

The skeleton fixes the seam types; these are the fail-closed bounds that make its laws structural
rather than nominal. All are dials or format validation — no approval step, no new gate.

- **`validate_visitor_tz`** (bounded + IANA charset). `visitor_tz_override` is the ONE free-form
  string the parser may emit, and `SolveRequest.visitor_tz` is a `String`. Without this, a model
  could smuggle the visitor's sentence into the solve request and
  `booking_constraint_free_text_never_reaches_oracle` would be true only by convention. The test
  asserts the smuggling case is refused *before* the oracle is called.
- **`ConstraintObject::validate` rejects non-canonical order.** `canonical_bytes` validates first, so
  a hand-built unsorted object cannot produce bytes at all — canonicalization is not merely offered,
  it is the only path to a hash.
- **Bounds**: `MAX_LOCAL_TIME_WINDOWS = 8`, `MAX_VISITOR_TZ_BYTES = 64`,
  `MAX_INPUT_BYTES_CEILING = 4096` (ceiling on the caller's dial, not a replacement for it),
  `MAX_SESSION_REF_BYTES = 120` (the session ref becomes a lens id — see VERDICT-FIX F5).
- **`#[allow(clippy::too_many_arguments)]`** on `run_constraint_turn` — the 8-arg signature is the
  ratified seam. Bundling the args would hide the capability boundary the ticket exists to expose.

## Seam custody note for later layers

`EventTypeKey`, `BookingError`, `ConstraintObject`, `SolveRequest`, `RankedSlot`, `SolveResult`,
`SlotOracle`, `SlotMask` live ONLY in `booking/constraint.rs`. `booking/mod.rs` is re-exports only
(asserted mechanically in `booking_constraint_seam_compiles_from_constraint_home`, which scans the
comment-stripped source for any definition keyword). ONE-1823 adds `solver.rs` implementing
`SlotOracle` and must not redefine or move any of the eight.

The fixture oracle is `#[cfg(test)] pub(crate) mod fixture` inside `constraint.rs` — plain cfg(test),
no `test-hooks`, no `test-support`. `booking_constraint_fixture_oracle_is_deterministic` asserts the
lane contains no `feature = ` gate of any kind, which forecloses both by construction.

## K3 SIMPLIFY pass

One deletion, nothing else warranted:

- `agent_front.rs`: deleted the one-use `surface_error` helper and routed `card()` through
  `surface()` directly (`GeneratedUiCard::card` returns `Result<_, Error>`, the exact shape
  `surface()` wraps). Net −4 lines, zero behavior change.
- Surveyed and deliberately KEPT: the `TimeRangeWire` `From` adapter impls (the idiomatic form of
  the serde-with layer; inlining struct literals at four sites is not an elegance win), the separate
  `validate_visitor_tz` / `validate_session_ref` charset validators (merging would ADD a
  parameterized helper), `ConstraintFrontCopy::validate` (declared D4 decision), and
  `top_ranked_slots` (the two-pass index sort is what preserves the oracle's relative order among
  the rendered top three). No test file, seam type, or public API touched.

Gates after the pass: `cargo fmt -p oneiron -- --check` clean; `cargo clippy -p oneiron
--all-features --all-targets` zero warnings; `cargo test -p oneiron --all-features --lib
booking_constraint` 12/12.

## VERDICT-FIX

Five verdict-verified REAL findings, each fixed at its chokepoint and mutation-verified
(red demonstrated on the pre-fix tree, green after). Two findings were REJECTED with derivation by
the adjudicator and are not relitigated here; both are recorded under "Banked" below.
Named oracles: 12 → 15.

### F1 — `fixture-test-blocks-real-solver` (P1, tests.rs)
`booking_constraint_fixture_oracle_is_deterministic` asserted that
`crates/oneiron/src/booking/solver.rs` does **not** exist. ONE-1823 creates exactly that file and
does not own this test file, so the assertion made a planned, correct future event into a
deterministic red for a lane that had already merged. The done-means phrase "ONE-1816 tests run
before `solver.rs` exists" is an **ordering fact about dispatch**, not a permanent invariant.

Fix: dropped the filesystem probe. The stable property — independence — is now asserted on the two
files this ticket owns outright (`constraint.rs`, `agent_front.rs`): neither reaches for a solver, so
the oracles run on the fixture alone whether or not `solver.rs` exists. `mod.rs` is deliberately
excluded from that scan: ONE-1823 legitimately adds `pub mod solver;` there.

Mutation: created a placeholder `src/booking/solver.rs` → the pre-fix test failed on the `.exists()`
assert; post-fix the whole `booking_constraint` set passed 15/15 with the file present. The
placeholder was deleted in the same command and never staged (it is a blueprint NON-CLAIM).

### F2 — `slot-buttons-have-no-action-manifest` (P1, agent_front.rs)
Every reply routed through `GeneratedUiCard::card`, which builds `actions: Vec::new()`
(lens.rs:1297 → `new` → `interactive` with an empty manifest). `LensRenderFrame::validate_action_event`
(lens.rs:3113) resolves a click against `render.actions` and hard-rejects any action the card never
declared — so the embedded `ButtonControl.action` alone is not sufficient under the generated-UI
contract. Every slot button was rendered and unusable: the lane's only commit path was dead.

Fix: `slot_button_node` → `slot_button`, returning the node **and** its
`GeneratedUiActionDeclaration`; `slots_card` collects them and assembles through
`GeneratedUiCard::interactive`. Shape:
- `element_id` = the button's own `booking-slot-N` atom id;
- `action` = the *same* `SelfUiAction` value the control carries (the equality
  `validate_generated_ui_interactivity` and `validate_action_event` both check);
- `action_id` = `booking.select_slot.N` — per-slot, because each slot carries its own engine-authored
  arguments and a card must declare each action id **exactly once** (lens.rs:1129). The `command`
  stays the single `BOOKING_SLOT_BUTTON_ACTION` for every slot, so "commit is always this one button
  action" is unchanged;
- `tier` = `DeterministicTool` — a trigger tier: arguments are engine-authored, a click carries no
  client `$state`, and execution stays behind the host's write chokepoint. `Local` would admit client
  state patches; `ModelRoundTrip` would hand the slot back to a model, which this ticket's capability
  boundary forbids.

The deflect card keeps an empty manifest — it has no control, so it declares nothing that could be
named. New oracle `booking_constraint_slot_buttons_are_declared_actions` pins all of it, including
that the manifest survives into `card.render()`.

Mutation: pre-fix the new oracle failed with `card.actions.len()` 0 vs 2 — the finder's exact trace.

### F3 — `slot-oracle-makes-front-future-non-send` (P1, constraint.rs)
`run_constraint_turn` holds `&dyn SlotOracle` across the backend `.await` and calls it afterwards, so
without a `Sync` bound the turn future is not `Send`. ONE-1819 serves this front from the
`oneiron-server` Axum surface, whose handler futures must be `Send` — the settled lane-head seam was
therefore uncallable from the layer it exists to feed.

Fix: `pub trait SlotOracle: Send + Sync`. The method shape is untouched, so the seam ONE-1823
implements is unchanged; this matches the existing `LlmBackend: Send + Sync` precedent (llm.rs:100)
for the other host-injected capability in the same signature. The fixture's recorder moved
`RefCell` → `Mutex` accordingly.

Mutation: the new oracle `booking_constraint_front_future_is_send` failed to compile pre-fix with
`error: future cannot be sent between threads safely` plus E0277 on `dyn SlotOracle` — the finder's
exact failure.

### F5 — `session-ref-prefix-exceeds-lens-id-bound` (P2, agent_front.rs)
Admission accepted a 128-byte session reference, but the card id is `booking-<session_ref>` and a lens
token is bounded at 128 bytes (lens.rs:60/4872). A 121-byte reference passed admission, spent the
model call **and** the solve, then failed at surface assembly with a 129-byte id.

Fix: the prefix is now part of the bound —
`MAX_SESSION_REF_BYTES = MAX_LENS_ID_BYTES - CARD_ID_PREFIX.len()` = 120, checked at admission before
either spend. The prefix literal is a named constant used by both the bound and the id construction,
so the two cannot drift.

Mutation: pre-fix, the new oracle's 121-byte case returned `Surface(...)` after one backend call and
one solve instead of `InvalidConstraint` before either. The oracle also asserts that a 120-byte
reference really renders, so the bound is pinned against the engine's behavior rather than a guess.

### F6 — `local-input-bound-leaks-to-provider-wire` (P2, constraint.rs)
`config.max_input_bytes` was inserted into `LlmRequest.params`. Both hosted adapters copy every
`params` entry unchanged into the provider HTTP body
(`crates/oneiron-llm-openai/src/lib.rs:274`, `crates/oneiron-llm-anthropic/src/lib.rs:284`), so a
hosted parse call would carry an unsupported `max_input_bytes` field.

Fix: removed from `params`. The bound stays exactly what it was — local admission state, enforced in
`parse_constraint_with_backend` before the request is built (that enforcement and its test are
unchanged). `max_output_tokens` stays: it is a real generation parameter and the repo convention
(`policy_model.rs:367`). The lane's own assertion was inverted to pin the absence.

Mutation: the inverted assertion failed on the pre-fix tree.

### Banked (not relitigated — adjudicated REJECTED with derivation)
- **BANK-1 → ONE-1823**: semantic timezone resolution. `validate_visitor_tz` enforces IANA *shape*,
  not membership; separating `afternoon` from `CET` needs a real tz database, which this packet
  cannot add (`Cargo.toml` is a NON-CLAIM, no dep reservation minted, none in the workspace). The
  ratified guarantee this ticket owns — the original sentence never reaches `SolveRequest` — is
  enforced and tested. ONE-1823 must fail closed on unresolvable zones for host-detected tzs anyway.
- **BANK-2 → postmortem/owner, not a lane defect**: whether tier-derived `ModelId`s
  (`tier/<resolved>@configured`, the `SafeguardModelBinding` pattern at llm.rs:706) should gain a
  catalog-coupled resolution facility engine-wide. No such facility exists anywhere in the engine
  today; adding one would be a blueprint-level amendment. See D2 for why this ticket derives the id.

### Gates
- `cargo fmt -p oneiron -- --check` — clean
- `cargo clippy -p oneiron --all-features --all-targets` — zero warnings
- `cargo test -p oneiron --all-features --lib booking_constraint` — 15/15
- `cargo test -p oneiron --all-features` — **3524 passed, 0 failed** (lib), every integration and
  doc-test suite green

### Packet
Unchanged and still exact: `booking/constraint.rs`, `booking/agent_front.rs`, `booking/tests.rs`
touched; `booking/mod.rs` and `lib.rs` already correct and untouched by this round. No `Cargo.toml`,
no `Cargo.lock`, no `solver.rs`, no `lens.rs`/`llm.rs`/`policy_model.rs` edit — the manifest fix
composes the existing `GeneratedUiCard` contract rather than widening it.
