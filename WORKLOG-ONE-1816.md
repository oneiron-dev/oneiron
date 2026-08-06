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
  `MAX_SESSION_REF_BYTES = 128` (the session ref becomes a lens id).
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
