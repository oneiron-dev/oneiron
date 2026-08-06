# WORKLOG — ONE-1823 [BK-00] availability solver + slot-mask projection

Branch `ONE-1823`, cut from `origin/main` @ `54c2c17db` (1812 #607 + 1783 #606 +
1816 + 1791 merged). BK-A layer 1 of 4.

## What landed

| Path | Mode |
|---|---|
| `crates/oneiron/src/booking/config.rs` | CREATE — `EventTypeConfig` family, claim codec, exact-predicate validator, descriptor rows, `(page_ref, key)` lookup |
| `crates/oneiron/src/booking/solver.rs` | CREATE — eight pure stages, `BookingSolver: SlotOracle`, `ActiveHoldSource`, `BookingCounts`, `slot_mask` |
| `crates/oneiron/tests/booking_solver.rs` | CREATE — 11 boundary oracles |
| `crates/oneiron/src/booking/mod.rs` | MODIFY — re-exports only |
| `crates/oneiron/src/claim.rs` | MODIFY — one booking-family arm, appended after CAL |
| `crates/oneiron/src/lib.rs` | MODIFY — crate-root re-exports only |

`booking/disclosure_rung.rs` was in the PACKET as a MODIFY (Slots payload wire).
**Zero diff was needed**: ONE-1812 landed `RungProjection::Slots(SlotMask)`, the
`None` ⇒ `BookingError` rule, and `validate_slot_mask` complete. This lane
consumes it and asserts it (`public_rung_cannot_exceed_slots`,
`slot_mask_contains_no_calendar_or_event_detail`) rather than touching a file it
does not need to change.

## Blueprint deviations

**D1 — `EventTypeConfig` / `BookingEventTypeClaimValue` derive `PartialEq`, not
`Eq`.** The blueprint skeleton already spells these two without `Eq`; the seam's
`EventTypeKey` carries only `PartialEq` (1816's five-derive law), so `Eq` cannot
compile here. `WeeklyWallWindow` and `HostAvailabilityConfig` keep `Eq` exactly
as the skeleton has them. No signature moved — this is the skeleton as written.

**D2 — `ActiveHoldSource: Send + Sync`.** The blueprint's trait is unbounded, but
1816-F3 made `SlotOracle: Send + Sync`, and `BookingSolver` holds
`&dyn ActiveHoldSource`. Without the bound the solver cannot implement the seam
trait at all. Additive; no method signature changed.

**D3 — the flex pool is a second pipeline pass, not a ninth stage.** All eight
stage signatures are byte-for-byte the blueprint's. "Flex surfaces only after the
primary mask is empty" is realized by running the same eight stages a second
time on a configuration whose working hours are widened by `flex_windows`, and
setting `flex_used` on the result. The alternative — threading a flex flag
through five stage signatures — would have deviated from five ratified
signatures instead of none.

**D4 — two calendar-error wrappers, not one.** The blueprint asks for "one
opaque calendar-error wrapper rather than restating TZ variants". No TZ variant
is restated, but whose zone failed decides the `BookingError` variant, so there
are two one-line wrappers: `host_zone_error` → `InvalidConfig` (configuration)
and `visitor_zone_error` → `InvalidConstraint` (request data). Collapsing them
would report a visitor's malformed zone as a host misconfiguration.

**D5 — `#[expect(clippy::unnecessary_wraps)]` on `load_booking_counts`.** The
blueprint pins the fallible signature because ONE-1813 reads storage there; on
this layer the body is storage-free and clippy is right that the `Result` is
currently unnecessary. `expect` (not `allow`) is deliberate: when layer 2 adds
the read, the attribute becomes unfulfilled and the compiler orders its deletion.

## Rulings inside the ratified shape

- **Interval convention.** Every `TimeRange` crossing a solver stage boundary is
  half-open `[start, end)` — the convention `BusyInterval` and `SlotMask` already
  use. The engine's `TimeRange` is inclusive, so the conversion happens exactly
  twice: at `SolveRequest.window` ingest, and at the `freebusy` call. Stated at
  the top of `solver.rs`.
- **Buffers expand by `pre + post` on BOTH sides.** Both the existing meeting and
  the candidate carry the event type's buffers, so the gap either side of a busy
  interval must hold one meeting's `post_buffer_min` and the other's
  `pre_buffer_min`. Growing busy by that sum and requiring the *unpadded*
  candidate to fit is exactly the rule, and it keeps a candidate's footprint
  equal to its booked duration.
- **Slot grid is epoch-anchored.** Candidate starts satisfy
  `start % (slot_step_min * 60) == 0` against the UNIX epoch, not against each
  mask's own start. A per-mask grid would give two hosts different instants and
  make `Both` routing intersect to nothing where the hosts genuinely share time.
- **Caps are visitor-local by DAY IDENTITY, not by UTC containment.** A
  `BookingCountBucket` is charged to the visitor-local civil day its
  `window_start_utc` falls on, so the same table read in another `visitor_tz`
  charges different days. Pinned by
  `visitor_local_daily_and_weekly_caps_use_typed_booking_counts`, which shows one
  table binding the cap in UTC and not binding it in `America/Los_Angeles`.
  Absence of a bucket is zero confirmed bookings (the table is sparse), never
  unknown occupancy.
- **Caps are re-applied at the emit chokepoint.** Stage 5 prunes per host before
  routing; stage 8 applies the same shared helper to the final routed set, so the
  guarantee is a property of what leaves the solver whatever routing mode ran.
  This is what makes `counts` load-bearing in `rank_and_emit` rather than a dead
  parameter.
- **A spring-forward gap on a working-hours boundary SKIPS that occurrence.** The
  border reports the gap typed; the blueprint leaves skip-vs-shift to the caller.
  Skipping never invents availability and never widens a window silently.
- **Ranking is preference-then-time.** A slot inside any host's
  `preferred_hours` outranks one that is merely bookable; ties break by UTC
  start then end via `f32::total_cmp`. No round-robin, weighting, pool, or
  minimize-gaps shaping was added — those are explicitly later picks.
- **Civil-date arithmetic is local integer math** (Hinnant `days_from_civil` /
  `civil_from_days`, ~25 lines), not a third-party date type. The TZ border
  already hands out civil fields; turning them into a day number and a weekday
  needs no database, and doing it here is what keeps every booking signature free
  of a chrono-family type.
- **An absent per-host freebusy projection is a typed wiring error**, never an
  empty union — an unbound host must not read as "free all day"
  (`attach_busy_union`, `BookingSolver::busy_by_host`).

## Known holes (recorded, not fixed)

1. ~~**`gate::default_policy_manifest()` has no `booking.` rule.**~~ **CLOSED by
   the VERDICT-FIX round (F4) under a PACKET_AMEND — see below.** The one
   `booking.` prefix rule now lives beside CAL's `calendar.` one, the pinned hole
   test is the positive form, and `unseeded_vault()` is gone.
2. **`CalendarSel.system` is inert until CAL-02 (ONE-1784) lands passports.** The
   solver calls `freebusy` separately per host with that host's selector binding
   — the ratified call shape — but on this baseline every host receives the same
   vault-wide union. No booking code compensates; the blueprint's verbatim seam
   says the solver must not depend on the selector before then.
3. **`load_booking_counts` returns an empty table.** Confirmed bookings live in
   the session-keyed lifecycle rows ONE-1813 lands in BK-A layer 2. The
   visitor-local bucketing law lives in the cap stage, so layer 2 supplies
   `confirmed` and changes nothing else. `NoActiveHolds` is the matching
   scaffolding on the hold side, blessed by the blueprint.
4. **`HostAvailabilityConfig.calendar_refs` is configuration data the solver does
   not query.** `CalendarSel` carries no calendar id on this baseline, so the
   request-time `calendars_by_host` binding is what CAL is asked; `calendar_refs`
   is the page editor's declaration and BK-02's reconciliation input. Documented
   on the field.

## PACKET_AMEND candidates

**One, raised in the VERDICT-FIX round (F4):
`/Volumes/Cinema/w5-lt/bk/crates/oneiron/src/gate.rs`** — the single `booking.`
policy-manifest prefix rule that unblocks the production configuration write
path. Rationale, blast radius, and the CAL precedent are in the VERDICT-FIX
section below. This is a deviation-board item.

Otherwise none. Every other changed path is in the PACKET;
`booking/disclosure_rung.rs` was claimed and needed no diff (above).
`booking/constraint.rs` and `booking/agent_front.rs` were consumed, never edited.
`Cargo.toml` and `Cargo.lock` untouched; no `registry.rs` diff; no entity or type
byte allocated.

## Done-means evidence

`cargo test -p oneiron --all-features --test booking_solver` — 11/11 green:

- `eight_step_pipeline_order_oracle` — ten candidates enter, each of the eight
  stages removes its own witness, two survive; neutralizing any one stage's knob
  returns exactly that stage's witness.
- `busy_union_is_consumed_without_status_refilter` — `free` and `cancelled`
  occurrences are excluded by CAL's union, and the solver's answer reproduces
  that without re-deriving occupancy.
- `flex_pool_surfaces_only_after_primary_mask_is_empty` — `flex_used` false while
  ordinary slots exist, true only on the fallback, and never on an empty
  fallback; `allow_flex_pool: false` keeps the pool shut.
- `visitor_zone_is_validated_at_calendar_border` — four malformed zones fail
  typed, no UTC fallback, `SolveResult` leaks no zone/wall/offset, and the
  Europe/London gap skips only the skipped hour.
- `synthetic_config_bypasses_page_lookup` — solves verbatim with no claim in the
  vault (the claim path fails typed on the same page), holds still scoped by the
  supplied subject, key mismatch typed.
- `booking_event_type_index_uses_canonical_prefix` — shortcut key is
  `b"booking.event_type.v1:"` + digest over both axes; the configuration resolves
  from synced claim truth with no shortcut written; supersession retires the old
  configuration and the solve follows the live one.
- `slot_mask_contains_no_calendar_or_event_detail` /
  `public_rung_cannot_exceed_slots` / `booking_seam_has_one_definition_home` /
  `booking_source_carries_no_third_party_time_type` /
  `booking_claims_are_gate_pending_under_the_default_policy_manifest` (renamed to
  the positive form and joined by four more oracles in the VERDICT-FIX round —
  the suite is 15/15 at the tip).

Inline unit oracles in `config.rs` (6) and `solver.rs` (13) cover the defect
table, the claim codec round trip, descriptor rows, civil-date round trips, the
wall-window border, buffers, notice/horizon presets, the grid, caps, holds,
routing, ranking, and the constraint mask.

Gates on `54c2c17db + this branch`:

- `cargo fmt -p oneiron` — clean.
- `cargo clippy -p oneiron --all-features --all-targets` — clean.
- `cargo test -p oneiron --all-features` — green.

**Flake charged to no lane.** One full-suite run reported
`batch::tests::authority_fold_backfills_legacy_missing_first_seen_sidecars_once`
failing on `migrated >= observed_before`, where both sides are
`unix_seconds_now()` sampled around a fold. It passes in isolation and the
re-run of the whole lib suite on the identical tree is green (3664 passed, 0
failed). The test lives in `crates/oneiron/src/batch/tests.rs`, which this lane
never touches, and the assertion is a wall-clock second-boundary race predating
this branch.

## SIMPLIFY pass (K3, post-impl)

Five deletions, no additions; no test assertion, fixture, or public signature
moved:

1. `rank_of` lost its dead `_visitor_tz` parameter — ranking reads host zones
   only, and the parameter was carried through `rank_and_emit` for nothing.
2. `intersect` collapsed to `.max()`/`.min()` (the manual if/else re-stated the
   standard library).
3. `working_hours_mask` no longer re-runs `config.validate()` — `solve` is the
   one door in and validates before the pipeline; the stage-level duplicate was
   a defensive branch. The `# Errors` doc now says so.
4. `apply_event_type_knobs` lost its `duration == 0 || step == 0` early return —
   the same validated-config guarantee makes both unreachable (validation
   rejects zero at the door).
5. `config.rs`: `map_err(|_| storage_failure(()))` became
   `map_err(storage_failure)`, and the single-use `WRITE_CLASS_ORDINARY`
   constant was inlined into the one descriptor row.

Considered and kept: the `is_finite` rank filter (blueprint-mandated
"rejects non-finite ranks"), the `#[expect(unnecessary_wraps)]` on
`load_booking_counts` (ratified layer-2 contract, deviation D5), and the
shape-check + resolve-check pair on `visitor_tz` in `solve` (different failure
taxonomies: IANA-shape vs unresolvable zone).

Gates after the pass: `cargo fmt -p oneiron` clean; `cargo clippy -p oneiron
--all-features --all-targets` clean; `--test booking_solver` 11/11 and
`--lib booking::` 50/50 green; full `cargo test -p oneiron --all-features`
green.

## VERDICT-FIX (post-simplify)

The finder returned seven items; the verdict adjudicated four REAL, one
rejected-by-blueprint, and two banked. Each REAL finding was fixed at its
chokepoint and mutation-verified — the witness test was run RED on the tip
before the fix and GREEN after — in one commit per finding.

### F3 — `unbounded-window-work` (P1) → `ec1273ef3`

The caller's `SolveRequest::window` drove the freebusy query, the hold read, and
stage 1's per-local-day walk across every host, while the booking horizon clipped
only the OUTPUT, at stage 4. A visitor could ask for centuries against a page
that opens for a fortnight and force CAL recurrence expansion plus per-host day
iteration across all of it; `EventTypeConfig` also placed no upper bound on
`booking_window_secs`, so the horizon itself was unbounded.

Chokepoint, not call site: stage 4's rule moved into one `bookable_extent()`
home, and `SlotOracle::solve` applies it once BEFORE any read. `freebusy`, the
`ActiveHoldSource` read, and `load_booking_counts` all now see the extent rather
than the request; a request that cannot reach the horizon returns empty without
reading at all. `enforce_notice_and_window` calls the same function, so the rule
has one definition and stage 4 stays the pure stage that owns it (the second
application is idempotent by construction).

Two collateral corrections the fix required:

- The freebusy query is PADDED by `buffer_pad()` — a busy interval just outside
  the horizon still casts its buffer inside it, and a bare-horizon query would
  silently drop exactly those blockers. `buffer_pad` is now the one home for the
  `pre + post` gap, shared with `apply_buffers`.
- `booking_window_secs` is bounded by `MAX_BOOKING_WINDOW_SECS` (366 days,
  re-exported through `booking/mod.rs` and `lib.rs`). The clamp bounds the walk
  relative to the horizon; this is what bounds the horizon.

Mutation evidence: `solve_work_is_bounded_by_the_horizon_not_the_request` records
the window a `RecordingHolds` source is asked for. RED on the tip
(`left: (1772409600, 1806969601)` — the caller's 400 days), GREEN after
(`(NOW + min_notice, NOW + booking_window)`). `configuration_defects_are_named_by_one_table`
gained an `"unbounded window"` row, RED before the bound existed.
`a_busy_interval_at_the_horizon_edge_still_buffers_the_last_candidate` guards the
pad and was itself mutation-checked: replacing `buffer_pad(&config)` with `0`
turns it RED.

### F1 — `claim-read-admission` (P2) → `a07f27592`

`live_config_in_txn` checked predicate, subject, and `lifecycle == Active` only,
skipping the canonical `claim_surfaceable` gate every sibling reader uses
(`saved_query.rs:1590`, `calendar/outcome.rs:408`). Approval, lifecycle, and
staleness are independent axes, so an Active **Proposed** or **Rejected**
`booking.event_type` claim — or an Active stale one — could drive a page's public
availability without ever having cleared read admission.

Fix: the liveness test routes through `crate::claim::claim_surfaceable`. Doc
comments that said "active" now say "surfaceable".

Mutation evidence: `only_surfaceable_configuration_claims_configure_a_solve`
writes a Proposed configuration at the lexicographically smallest claim id — so
the deterministic winner scan reaches it first — and asserts the page reads as
unconfigured, then that an approved claim written afterwards is what is served.
RED on the tip (the Proposed claim configured the solve), GREEN after.

### F4 — `claim-write-path-blocked` (P2) → `02b3f8abf` — **PACKET_AMEND**

`gate::default_policy_manifest()` carried a `calendar.` prefix rule but no
`booking.` one, so every booking-family claim fell to the manifest's `critical`
default and was gate-pending on write. The production page-editor path for a
`booking.event_type` configuration was dead, and the claim-backed solve was
reachable only from `Vault::open_unseeded_for_test`. Worklog "Known holes" item 1
recorded this; the verdict ruled it a fix, not a hole.

**PACKET_AMEND: `/Volumes/Cinema/w5-lt/bk/crates/oneiron/src/gate.rs`** — one
prefix rule (`criticality: normal`, `sensitivity: normal`), byte-for-byte the
shape CAL landed for `calendar.`, appended beside it. `gate.rs` is a lane-wide BK
non-claim in CLAIMS.md ("GATE-lane wall; no BK edit"); this is the amendment, for
the deviation board. No other line of `gate.rs` is touched, and the GATE lane's
137 `gate::` unit tests stay green.

Consequences inside the packet: the pinned hole test became
`booking_claims_resolve_normal_criticality_under_the_default_policy_manifest`
(the positive form `tests/calendar_surface_oracle.rs` uses), and the
`unseeded_vault()` fixture that existed only to route around the hole is deleted
— every configuration oracle now runs against the real write gate on a stock
vault.

Mutation evidence: the flipped test is RED on the tip with
`GateWriteRejected { outcome: "pending", reason_codes: ["gate.pending.criticality_floor"] }`,
GREEN after; `booking_event_type_index_uses_canonical_prefix` goes RED→GREEN with
it, which is the proof the fixture was load-bearing.

### F7 — `empty-selector-broadening` (P2) → `3a42e647a`

`BookingSolver::busy_by_host` errored on a MISSING host binding but passed a
present-but-empty selector slice straight to `freebusy`, which — as this lane's
own oracle at `tests/booking_solver.rs` proves — returns the unfiltered
all-calendar union. A host whose selector resolution produced nothing became busy
with every event in the vault: the same wiring-defect class, handled
asymmetrically, and in the more dangerous direction (silent suppression rather
than a visible error).

Fix: one `.filter(|selectors| !selectors.is_empty())` before the existing
`ok_or_else`, so both shapes of unbound host raise the same typed
`BookingError::InvalidConfig`.

Mutation evidence: `an_empty_calendar_selector_binding_is_a_wiring_defect` proves
`freebusy(&vault, &[], monday())` is non-empty, then asserts missing and empty
bindings are both typed while a real binding solves. RED on the tip, GREEN after.

### Not relitigated

- **F2 `cap-source-stub`** — rejected by the verdict as blueprint-verbatim
  ratified layer-1 scaffolding; ONE-1813 fills `load_booking_counts` under the
  frozen signature per the `#[expect]` handoff note. Untouched, except that the
  function now receives the bookable extent rather than the raw request window
  (F3), which its doc comment records for layer 2.
- **F5 `self-hold-exclusion-dropped`** — banked as an ONE-1813 dispatch note:
  `solve()` is the public-mask path where ALL live holds must subtract, so
  `exclude_session_key: None` is correct there.
- **F6 `node-local-cache-divergence`** — banked as a P3 doc nit on the
  `load_event_type_config` comment. Deliberately left as banked; the adjacent
  "active"→"surfaceable" wording changes above are F1's, not F6's.

### Packet

Diff is `booking/config.rs` + `booking/solver.rs` + `booking/mod.rs` (re-export
line only) + `lib.rs` (re-export line only) + `tests/booking_solver.rs`, all
claimed — plus the one amended `gate.rs` rule above. `claim.rs` unchanged by this
round and still carries exactly one exact-predicate hook after the CAL arm.
`booking/constraint.rs` and `booking/agent_front.rs` untouched. No `Cargo.toml`
or `Cargo.lock` diff; no `registry.rs` diff; no entity or type byte allocated.

Gates: `cargo fmt -p oneiron` clean; `cargo clippy -p oneiron --all-features
--all-targets` clean at every commit; `--test booking_solver` 15/15 and
`--lib booking::` 50/50 green; full `cargo test -p oneiron --all-features` green.
