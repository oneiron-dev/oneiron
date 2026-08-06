# WORKLOG — CAL GATE prefix rule

Branch `w5/cal-gate-prefix`, cut off `origin/main` 8225cec4f.
Owner-ruled scope (OWNER-RULINGS-20260806-1300.md item 1): exactly the rule + the
tripwire flip.

## Defect

The merged CAL-09 read/write surface (ONE-1791, PR #591) mints `calendar.*`
claims, but `gate::default_policy_manifest()` carried no `calendar.` prefix
rule. The default manifest resolves criticality from a prefix allow-list and
defaults everything else to `critical`, so every approved calendar write hit the
criticality floor and pended. On a default vault the whole CAL read surface was
inert, and `calendar_surface_oracle.rs` pinned that inert truth deliberately.

## Change

### 1. The rule — `crates/oneiron/src/gate.rs`

One prefix rule for the `calendar.` predicate namespace in
`default_policy_manifest()`, `criticality: normal` / `sensitivity: normal`,
built with the same idiom as the neighbouring `profile.` namespace rule (bare
`prefix`, no `exact` flag). Rule order is irrelevant to resolution:
`PolicyPack::axes_for_predicate` is longest-prefix-wins, ties restricted.

### 2. The tripwire flip — `crates/oneiron/tests/calendar_surface_oracle.rs`

`calendar_claims_are_gate_pending_under_the_default_policy_manifest`
→ `calendar_claims_resolve_normal_criticality_under_the_default_policy_manifest`.
The old name asserted the old truth, so it was renamed; the module doc-comment
reference was updated in the same pass.

The test now pins the new resolved behaviour positively rather than negating the
old one:

- an approved `calendar.*` claim candidate COMMITS through the real gate on a
  stock vault, and the stored row is `Approved` + `Active`;
- the positive-projection arm the old doc-comment reserved is enabled: the claim
  reads back through `MemoryFacade::calendar_read`, with `blocks_time == true`.
  `blocks_time` is derived from the admitted `calendar.time_kind` claim rather
  than the EVENT header, so it can only be true if the gate passed the claim
  through to the projector.

### 3. Census for other inertness pins

`rg` over the gate tests and the oracle file. Findings:

- `calendar_surface_scopes_read_search_and_freebusy` (same file) does NOT pin
  manifest-hole inertness — it pins the tier-scoping property (a claim that did
  not clear admission is invisible on read/search/freebusy). Its fixture writes
  at `Proposed` via the envelope, so it stays green on its own terms. The shared
  `store_calendar_event` helper gained an explicit `approval` parameter so the
  proposed tier is now a stated fixture intent rather than a side effect of the
  manifest gap, and the stale prose ("the admission tier the default policy
  manifest actually permits") was corrected.
- `claim/tests.rs::write_door_validates_calendar_claim_structure` goes through
  the raw `put_claim` door, not the gate, so it is manifest-independent.
- The `calendar::query` / `calendar::freebusy` unit tests run on a
  manifest-cleared vault; unaffected.

No `gate/tests.rs` unit test pinned the old truth, so that file is untouched.

## Mutation-verify

Verified in both directions by stashing the `gate.rs` rule alone:

- WITHOUT the rule, the new test fails at the write door with
  `GateWriteRejected { outcome: "pending", reason_codes: ["gate.pending.criticality_floor"] }`.
- WITH the rule, it passes, including the read-surface projection arm.

The old tripwire also went red the moment the rule landed (its `expect_err`
fired on a commit that succeeded) — the flip is a real behaviour change, not a
test rewrite around unchanged code.

## Gates

- `cargo fmt --check` — clean.
- `cargo clippy -p oneiron --all-features --all-targets -- -D warnings` — clean.
- `cargo test -p oneiron --all-features` — green, 0 failed across all targets
  (lib target 3509 passed / 17 ignored; `calendar_surface_oracle` 5/5).

## Base-red (charged to no lane)

`cargo test -p oneiron-server --all-features` has one pre-existing failure,
`handler::tests::the_real_codec_rows_run_the_same_codec_package_axum_resolves`:
the row pins `tokio-tungstenite@0.29.0` but the tree resolves `0.28.0`. Verified
red on the clean tree with both of this lane's files stashed — a dependency
resolution drift, unrelated to the gate or calendar. The other 393 server tests
pass.

## Packet

- `crates/oneiron/src/gate.rs`
- `crates/oneiron/tests/calendar_surface_oracle.rs`

No `Cargo.toml` / `Cargo.lock` changes. No other file touched.
