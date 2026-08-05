# WORKLOG — ONE-1791 [CAL-09] SDK/MCP calendar verbs + safeguard screen

Lane: CAL · branch `ONE-1791` cut from `w5/redo/cal-1782-clean` @ `8eac700`
(ONE-1782 / CAL-00 redo — the CAL frontier head at dispatch time).
Blueprint: `/Users/olety/.claude-wave5/blueprints/CAL/ONE-1791.md`
Claims: `/Users/olety/.claude-wave5/blueprints/CAL/CLAIMS.md`

## State

Engine + server + N-API legs **DONE and green**. Docs-satellite leg **NOT DONE**
— see "Remaining leg" below; it is unreachable from this worktree.

## What landed

### 1. Calendar query/projection core

`/Volumes/Cinema/w5-lt/cal/crates/oneiron/src/calendar/query.rs` (CREATE)

- DTOs per the blueprint skeleton: `CalendarRangeDto`, `CalendarSel`,
  `CalendarEventView`, `CalendarReadRequest`, `CalendarSearchRequest`.
- `read_event` / `search_events` on `&Vault` (pinned skeleton signatures) plus
  `read_event_scoped` / `search_events_scoped` on `&ScopedRead`.
- **One admission chokepoint**: `CalendarRead` has exactly two arms — the
  internal `Vault` lane (applies `claim_surfaceable`) and the `ScopedRead` lane
  (applies `claim_surfaceable` *and* policy scoped-read grants). Nothing in the
  module reads a claim any other way, so read/search/freebusy cannot diverge.
- No second calendar store: an EVENT's occurrence is the entity header's
  indexed `occurred_start`/`occurred_end` pair; everything calendar-specific is
  a CAL-00 claim. Family membership is CAL-00's exact table via
  `is_calendar_claim_predicate`, never a `calendar.` prefix match.
- Single-cardinality predicates (`calendar.time_kind`, `calendar.status`) pick
  the **lowest-`EntityId`** live claim — the same deterministic tie-break the
  freebusy merge representative uses — so a data defect cannot make the
  projection iteration-order dependent.
- `CalendarSel.system` is validated (blank tokens rejected) but never filters:
  1791 precedes 1784, so selection stays deferred to CAL-02's passport index.

### 2. Busy-only freebusy projection

`/Volumes/Cinema/w5-lt/cal/crates/oneiron/src/calendar/freebusy.rs` (CREATE)

- C5 signatures verbatim: `BusyInterval { start_utc, end_utc, source }`,
  `BusyUnion = Vec<BusyInterval>`,
  `freebusy(&Vault, &[CalendarSel], TimeRange) -> Result<BusyUnion>`, plus
  `freebusy_scoped` for the actor lane.
- Checked inclusive→half-open conversion in **one** helper (`half_open`), used
  for both the query window and each occurrence; an inclusive end of `u64::MAX`
  fails `Error::ArithmeticOverflow` rather than wrapping to an empty union.
- `normalize_busy` clips to bounds, drops empties, sorts by
  `(start, end, source)`, merges overlap **and touch**, and keeps the lowest
  `EntityId` per merged component.
- Busy-only law applied here: `busy_transparency == free` excluded, and
  **cancelled EVENTs excluded** (see deviation D2).
- Recurrence expansion is a documented deferred leg (CAL-03 / ONE-1785); the
  `expand_window` call site is marked in `freebusy_in`.

### 3. Optional inbound safeguard hook

`/Volumes/Cinema/w5-lt/cal/crates/oneiron/src/calendar/safeguard.rs` (CREATE)

- `CALENDAR_SAFEGUARD_CONFIG_KEY`, `CalendarInboundBody`,
  `CalendarScreenVerdict`, `CalendarBodyScreener`, `CalendarAdmissionRequest`,
  `Screened<T>`, `screen_then_claim` — exactly the blueprint skeleton.
- OFF by default ⇒ `Skipped`. Enabled with no injected screener ⇒
  `Indeterminate { reason_code: CALENDAR_SAFEGUARD_REASON_NO_SCREENER }`, never
  `Clear`: an unwired screen has examined nothing.
- `Flagged`/`Indeterminate` never promote, never execute body text, and add no
  approval wall — the caller still admits at the imported tier with the verdict
  attached. The admission callback takes the typed request by value and runs
  exactly once in every branch.

### 4. Rust + N-API SDK surfaces

`crates/oneiron/src/facade.rs`, `crates/oneiron-napi/src/facade.rs` (MODIFY)

- `MemoryFacade::calendar_read` / `calendar_search` / `calendar_freebusy` /
  `calendar_invite`. All four verify the actor binding first and read through
  the actor's **scoped-read lane**.
- `CalendarFreebusyIntervalDto` carries `{start_utc, end_utc}` only — the
  internal `source` is dropped at the DTO boundary, not lost internally.
- `CalendarInviteSurfaceInput` is C7's exact five fields
  (`method|uid|sequence|ics_blob_ref|recipient`, `deny_unknown_fields`), never
  an `OutboundDraftInput`. It builds the generic draft internally
  (channel `calendar`, verb `invite`, deterministic idempotency key) and
  delegates to `schedule_outbound`. No direct connector path exists.
- N-API mirrors every DTO field-for-field with the house `i64` timestamp
  conversion; the invite method stays a closed `REQUEST|CANCEL` set.

### 5. One closed MCP tool + gateway dialect + discovery

`crates/oneiron-server/src/{mcp.rs, mcp/tests.rs, api.rs, api/discover.rs,
api/mcp_gateway.rs}` (MODIFY)

- `McpToolName::Calendar` → `oneiron.calendar`; catalog grows to exactly six
  tools. `McpToolName::operations()` exposes the closed
  `read|search|freebusy|invite` set (`MCP_CALENDAR_OPERATIONS`).
- `McpCalendarToolArgs { schema_version, actor, consent, operation }` with a
  serde-tagged `McpCalendarOperation` (`tag = "op"`, `deny_unknown_fields`).
  JSON Schema is a `oneOf` of four fully-closed branches.
- Gateway `execute_mcp_calendar` dispatches **only** through `MemoryFacade`,
  threads `State<Arc<SyncServer>>` at the handler, and maps typed
  `FacadeError`s. No `ApiState`, `AppState`, `VaultFacade`, or `WritePrincipal`
  introduced.
- Discovery advertises `mcp.tool.<name>` per tool plus `mcp.tool.<name>.<op>`
  per closed operation, **derived from `McpToolName`** so catalog and
  advertisement cannot drift. `api.rs` owns the token prefix constant.

## Deviations from the blueprint (with reasons)

**D1 — MCP args carry the house actor/consent envelope.** The skeleton showed
`McpCalendarToolArgs` as a bare serde-tagged op enum. Every other tool in the
catalog carries `{schema_version, actor, consent}`, and two existing tests
(`mcp_tool_schemas_are_closed_and_versioned`, `ensure_mcp_actor_matches`)
require it — a bare enum would have had no actor to match against the
authenticated connector. The op enum is therefore nested under `operation`.
The ratified properties are unchanged: one tool, a serde-tagged op
discriminator, exactly four arms, each arm closed, and the invite arm typed to
C7's five fields.

**D2 — freebusy excludes cancelled EVENTs.** Not spelled out in the blueprint.
A1 never deletes a cancelled EVENT, so cancellation is only representable as
`calendar.status`. Leaving cancelled events in the union would force BK-00 to
re-filter, which is exactly what the busy-only projection law forbids. One
predicate read, documented at `CalendarEventFacts::is_cancelled`.

**D3 — the facade reads through `ScopedRead`.** The rest of `MemoryFacade`
reads the vault directly; scoped-read is normally the server's `core:read`
lane. Calendar bodies are imported foreign content and the blueprint's oracle
requires scoped-read rules to apply, so the calendar verbs opt into the
stricter lane. Safe by construction: with no scoped-read grants in the manifest
the lane is permissive, and an actor's calendar view can only ever be a subset
of the internal projection.

**D4 — `api.rs` change is a constant, not a route.** The blueprint asks api.rs
to help discovery advertise the tool and its operations; it does not ask for a
REST calendar surface, and leg 3 scopes the surface to "one closed MCP tool".
api.rs therefore contributes `MCP_TOOL_CAPABILITY_PREFIX` (beside `API_LEVEL`
and the `SKILL_PACK_*` constants discover.rs already imports from it), keeping
1791 the api.rs writer without inventing routes.

## KNOWN HOLE (found here, NOT fixable in this lane) — needs owner routing

`gate::default_policy_manifest()` resolves claim criticality from a prefix
allow-list (`profile.`, `affect.vad`, `skill.*`, actor-confidence,
provider-enrichment, `edge.provenance`) and defaults everything else to
`critical`. **`calendar.*` is absent.** Consequence, verified end to end:

- an approved-tier `calendar.*` write is rejected
  `GateWriteRejected { outcome: "pending", reason_codes: ["gate.pending.criticality_floor"] }`;
- the tier the door does admit is `proposed`, which is not `claim_surfaceable`;
- therefore, on a default vault, **every calendar read verb correctly returns
  empty** — the CAL read surface is inert until a rule lands.

`crates/oneiron/src/gate.rs` is a lane-wide CAL non-claim, so CAL-09 cannot fix
it. Fix is one rule (`prefix: "calendar."`, `criticality: normal`,
`sensitivity: normal`) in the default manifest, owned by the GATE lane or by
CAL-02 (ONE-1784) when it wires ICS ingest. Recommend banking as a
`needs: owner` item and gating CAL-02 dispatch on it.

Pinned as a tripwire by
`calendar_claims_are_gate_pending_under_the_default_policy_manifest` in
`/Volumes/Cinema/w5-lt/cal/crates/oneiron/tests/calendar_surface_oracle.rs`:
when the rule lands, that test fails loudly and the oracle's
positive-projection arm can be enabled. Positive projection is meanwhile
covered by the in-crate unit tests, which run on a manifest-cleared vault
(`test_util::open_test_vault_with`, the house convention for gate-free claim
fixtures).

## Remaining leg — docs satellites (NOT DONE)

Blueprint leg 5 claims four files in the **oneiron-docs** repo
(`workbench-engine-asks.astro` ask #8, `oneiron-backlog.astro` row,
`oneiron-arch-0003-semantic-memory.astro` §G.1 calendar rows,
`registry/oneiron.json` cross-notes). They are out of this worktree: the docs
repo has no CAL lane worktree and its main checkout is currently on another
lane's branch (`docs/secret-custody-byte-77`). Editing it from here would
collide with that lane. Needs either a docs worktree for CAL or an owner
ruling. Serialization to preserve: 1791 → 1780 → 1822 on §G.1, and 1791's
ask #8 before CA ONE-1780's ask #7.

## Tests added

Unit (`crates/oneiron/src/calendar/`):
- `freebusy_excludes_free_events_by_busy_transparency`
- `freebusy_excludes_cancelled_events`
- `freebusy_checked_converts_inclusive_range_to_half_open`
- `freebusy_sorts_clips_and_merges_touching_intervals`
- `freebusy_merge_uses_deterministic_source_representative`
- `freebusy_ignores_events_without_the_calendar_family`
- `calendar_search_filters_calendar_range_and_text`
- `calendar_search_bounds_limit`
- `calendar_selector_is_ignored_until_passport_index_lands`
- `calendar_read_projects_only_family_events`
- `calendar_surface_admits_only_surfaceable_claims`
- `calendar_safeguard_defaults_off`
- `calendar_safeguard_runs_before_claim_when_enabled`
- `calendar_safeguard_passes_typed_admission_request_with_verdict`
- `calendar_safeguard_indeterminate_never_elevates_imported_content`

Integration (`crates/oneiron/tests/calendar_surface_oracle.rs`):
- `calendar_surface_scopes_read_search_and_freebusy`
- `calendar_surface_rejects_invalid_ranges_with_the_typed_facade_error`
- `oneiron_calendar_invite_routes_only_through_schedule_outbound`
- `calendar_claims_are_gate_pending_under_the_default_policy_manifest`

Server (`crates/oneiron-server/src/mcp/tests.rs`):
- `oneiron_calendar_schema_is_closed_and_op_specific`
- `mcp_tool_catalog_stays_closed_over_six_tools`

N-API (`crates/oneiron-napi/src/facade.rs`):
- `calendar_bridge_dtos_mirror_the_engine_surface`

`freebusy_expands_recurring_series_before_union` is deliberately NOT written —
CAL-03 (ONE-1785) lands after this ticket, per the blueprint's deferred-leg
note. Its call site is marked in `freebusy_in`.

## Gates

- `cargo fmt --all --check` — clean.
- `cargo clippy -p oneiron --lib --all-features -- -D warnings` — clean.
- `cargo clippy -p oneiron --test calendar_surface_oracle --all-features -- -D warnings` — clean.
- `cargo clippy -p oneiron-server -p oneiron-napi --all-targets --all-features -- -D warnings` — clean.
- `cargo test -p oneiron --all-features` — **3223 lib passed / 0 failed**, all
  integration targets green (~3500 total).
- `cargo test -p oneiron-napi --all-features` — 17 passed / 0 failed.
- `cargo test -p oneiron-server --all-features --lib` — 372 passed / **1 failed
  (pre-existing)**, see below.

### Pre-existing failures on the parent tip (NOT introduced here)

1. `cargo clippy -p oneiron --all-targets` fails with 4 errors, all in
   `crates/oneiron/src/secret_custody/tests.rs` (last touched by `e0352a0`,
   ONE-1919 / #566): two `unused_mut` (lines 397, 436), one
   `field_reassign_with_default` (line 156), one `items_after_statements`
   (line 256). With those three lint classes masked, the whole crate including
   every test target is clippy-clean — this lane adds zero lint debt. The lane
   law forbids touching a file outside CLAIMS, so they are left for the
   L1-SECRET lane or an owner fix-forward.
2. `oneiron-server` `handler::tests::the_real_codec_rows_run_the_same_codec_package_axum_resolves`
   fails on a `tokio-tungstenite` 0.28 → 0.29 resolution drift. No file in this
   diff touches websocket/codec code or any Cargo manifest.

## Packet check

`git diff --name-only` ⊆ CLAIMS. Files touched:

CREATE — `crates/oneiron/src/calendar/query.rs`,
`crates/oneiron/src/calendar/freebusy.rs`,
`crates/oneiron/src/calendar/safeguard.rs`,
`crates/oneiron/tests/calendar_surface_oracle.rs`.

MODIFY — `crates/oneiron/src/calendar/mod.rs`, `crates/oneiron/src/lib.rs`,
`crates/oneiron/src/facade.rs`, `crates/oneiron-napi/src/facade.rs`,
`crates/oneiron-server/src/mcp.rs`, `crates/oneiron-server/src/mcp/tests.rs`,
`crates/oneiron-server/src/api.rs`, `crates/oneiron-server/src/api/discover.rs`,
`crates/oneiron-server/src/api/mcp_gateway.rs`.

No `Cargo.toml` / `Cargo.lock` edit. No `registry.rs`, `edge.rs`, `gate.rs`,
`outbound.rs`, `serialize.rs`, `temporal.rs`, `store.rs`, `context_pack.rs`, or
`calendar/claims.rs` edit. No new entity byte, `EdgeKind`, claim predicate, or
connector manifest. No push, no merge.

## Simplify pass (K3, post-implementation)

Three deletions, no behavior change, no test/fixture edits, no public wire or
engine API change:

1. **`crates/oneiron-server/src/mcp.rs`** — deleted the duplicate
   `McpCalendarInviteMethod` enum. The invite arm now carries
   `oneiron::CalendarInviteSurfaceMethod` directly, exactly as the blueprint
   skeleton pinned; the serde wire shape (`REQUEST|CANCEL`, UPPERCASE) is
   identical, so the closed-schema tests are untouched.
2. **`crates/oneiron-server/src/api/mcp_gateway.rs`** — the invite arm passes
   `method` straight through (the enum-to-enum conversion match died with
   deletion 1); collapsed the `let structured` / `let mut structured` shadow
   into one binding.
3. **`crates/oneiron/src/calendar/freebusy.rs`** — `normalize_busy` dropped its
   `bounds` parameter and the bounds re-check in `retain`: the collection-site
   `clip` already guarantees in-bounds non-empty intervals, so the conjuncts
   were unreachable. The empties guard stays (blueprint-named contract).

Considered and left alone: narrowing `CalendarRead` to `pub(crate)` (would
touch the public surface — out of simplify scope); unifying the N-API
`calendar_range_to_engine` Option dance in `calendar_freebusy` (its shape is
pinned by an in-file test assertion); merging the facade's two range-check
messages (test-pin risk on the typed error text); the MCP-local selector/range
DTOs (deliberate `deny_unknown_fields` closure the engine DTOs lack).

Gates after the pass: `cargo fmt --all --check` clean; clippy `-D warnings`
clean on `oneiron --lib`, `oneiron --test calendar_surface_oracle`, and
`oneiron-server`/`oneiron-napi --all-targets`; `cargo test -p oneiron
calendar_` + `freebusy` (38 tests) green, `--test calendar_surface_oracle`
4/4 green, `oneiron-server --lib mcp` 31/31 green, `oneiron-napi` 17/17 green.
