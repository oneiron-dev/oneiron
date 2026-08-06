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

1. **`gate::default_policy_manifest()` has no `booking.` rule.** It has a
   `calendar.` one, so every booking-family claim falls to the manifest's
   `critical` default and is gate-pending on write. The fix is one rule in
   `crates/oneiron/src/gate.rs` — a **lane-wide BK non-claim** (CLAIMS.md
   "GATE-lane wall; no BK edit"). Pinned rather than fixed by
   `booking_claims_are_gate_pending_under_the_default_policy_manifest`; the
   configuration oracles run on `Vault::open_unseeded_for_test`, exactly as
   `tests/calendar_outcome.rs` does for the same gap on `calendar.`.
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

None. Every changed path is in the PACKET; `booking/disclosure_rung.rs` was
claimed and needed no diff (above). `booking/constraint.rs` and
`booking/agent_front.rs` were consumed, never edited. `Cargo.toml` and
`Cargo.lock` untouched; no `registry.rs` diff; no entity or type byte allocated.

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
  `booking_claims_are_gate_pending_under_the_default_policy_manifest`.

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
