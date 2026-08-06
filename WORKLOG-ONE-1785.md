# WORKLOG — ONE-1785 [CAL-03] recurrence series expansion

Branch `ONE-1785` off `origin/main` 98195c3b8 (ONE-1783 #606 + ONE-1823 #614 merged).
Worktree `/Volumes/Cinema/w5-lt/cal-1789`.

## PACKET as executed

- CREATE `/Users/olety/Desktop/code/oneiron/crates/oneiron/src/calendar/series.rs`
- MODIFY `/Users/olety/Desktop/code/oneiron/crates/oneiron/src/calendar/mod.rs`
  (module decl, exactly two `CalendarError` variants appended after ONE-1783's four,
  series re-export surface, owner-module enum test)

Not touched: `calendar/claims.rs`, `edge.rs`, `registry.rs`, `serialize.rs`, `temporal.rs`,
`oneiron-vault-contract/src/lib.rs`, any `Cargo.toml`, `Cargo.lock`.

## Deviations / narrowings — declared, none silent

### D1 — PACKET narrowed: `crates/oneiron/src/lib.rs` NOT modified

The relay brief granted "lib.rs append re-exports". I did not use it.

- The blueprint's own `Claims` section lists only series.rs CREATE + mod.rs MODIFY.
- `CLAIMS.md` does not list ONE-1785 among the `lib.rs` claimants; the CAL writer
  order on that file is `1782 -> 1791 -> 1786`.
- ONE-1783 set the precedent: `CalendarError`, `WallTime`, `utc_to_wall`, `wall_to_utc`
  are reachable as `oneiron::calendar::*` and are NOT re-exported at the crate root.
- The blueprint's shared-consumer oracle asks for `expand_window` to be public
  **under `oneiron::calendar`**, which the mod.rs re-export already satisfies.

Adding series names to a shared-append file for zero consumer benefit would only
create a rebase collision with ONE-1791/ONE-1786. Narrowing, not widening: no
PACKET_AMEND needed. If a later CAL ticket wants the root re-export, it owns lib.rs
anyway.

### D2 — recurrence is stepped on the wall clock, with the zone applied at the CAL-01 border

Blueprint text: "Convert the master's `dtstart_utc` to local wall time through tz.rs,
expand in the named IANA zone, convert each occurrence back through the same border."
The keystone skeleton's inline recipe says the same mechanically: "Seed from
`utc_to_wall(...)` ... convert each occurrence via `wall_to_utc`".

Implemented exactly that recipe: the `rrule` engine is handed the seed's **civil
fields** in a fixed carrier zone and does pure civil arithmetic; the named IANA zone
is applied only at the `wall_to_utc` border.

This is forced, not stylistic. `rrule-0.14.0` `src/iter/utils.rs::add_time_to_date`
falls back to `midnight + duration` when a local time does not resolve, so handing the
engine the real zone makes it **silently shift a spring-forward occurrence into the
adjacent hour** (its own test pins `America/Vancouver 2021-03-14 02:22:10` doing this).
That erases the gap the border exists to report and makes the blueprint's
`expand_window_dst_gap_is_typed_error` unreachable. Stepping the wall clock and letting
CAL-01 decide the instant is what makes gap -> `NonexistentWallTime`, fold -> earliest
offset, and the preserved London wall hour all true at once.

Observable contract is unchanged: no `rrule` or chrono type crosses a public signature.

Consequence handled: RFC 5545 pins `UNTIL` to a UTC instant while the rule steps a wall
clock, so `UNTIL` is carried across the same border before the walk. Left untranslated
it would end a series at the zone's offset from where the author put it (up to 14h).
A machine-local `UNTIL` (no `Z`) is deliberately left for the crate's validator to
reject rather than laundered into UTC.

### D3 — expansion step budget maps to `InvalidRecurrenceRule`

"No unbounded collect, forever iterator" needs a finite bound, and the enum append is
exactly two variants. `RRuleSet::all(limit)` does not supply one: its limit counts only
in-window dates, so a `FREQ=SECONDLY` master whose `dtstart_utc` predates the window by
a year fast-forwards ~31.5M iterations before the first countable date, and the crate's
own `MAX_ITER_LOOP` guard only covers buffer-empty spins. So the walk is driven directly
with an explicit step budget (`MAX_EXPANSION_STEPS = 100_000`, module-private).

Exhausting it returns `CalendarError::InvalidRecurrenceRule { rule }` — the owner enum's
"invalid **or unsupported**" arm, per its own error text. Not a private fallback error,
not a third variant, and never a truncated `Ok` (a silently short vector is the same
class of lie as a silently empty one).

### D4 — the walk ends on the recovered instant, not on the window's wall clock

A fall-back fold maps a *later* wall clock onto an *earlier* instant, so an occurrence
can sort after the window end on the wall clock while its instant is still inside the
window. Worked case, now pinned as
`expand_window_keeps_a_folded_occurrence_past_the_window_wall_clock`: `Europe/London`,
window ending `2026-10-25T01:30:00Z` (01:30 GMT, the *later* leg of the fold); an
occurrence at wall 01:45 BST recovers to `00:45Z`, inside the window, yet 01:45 > 01:30
on the wall clock. A walk that stopped at the window's wall clock would drop a busy hour
and let the owner be double-booked in it.

So the walk terminates on `recovered_start > window.end` (the recovered instants ascend,
so the first one past the window is the last one worth walking to), and the window's wall
clock is used for one thing only: deciding whether a nonexistent wall time is the
caller's problem. Inside the window's wall clock a gap is the caller's skip-vs-shift
verdict and is returned; past it a gap simply ends the walk, because a wall time the zone
never observes has no instant and therefore cannot be in the window either way. My first
cut used a flat one-day slack on the upper bound instead, and its own gap test caught it:
a two-day London window ending before the transition still errored, because the slack
walked into the 03-29 gap the caller never asked about.

The lower bound stays exact: `wall_to_utc` is increasing, so a wall time below the window
start's wall time always recovers below `window.start`, and skipping before the
conversion keeps gap errors scoped to occurrences the window actually asked for.

### D5 — `calendar_error_appends_recurrence_variants_in_owner_module` lives in mod.rs

The done-means asks the test to prove the *owner module's* enum shape, and it is written
as an exhaustive `match` with no wildcard, so appending or reordering a variant fails to
compile. That tripwire has to live where the enum lives: ONE-1784/1786/1788/1790/1787 all
MODIFY `calendar/mod.rs` and would land on it naturally, whereas in series.rs it would
force a foreign ticket to edit a file it does not own. All other named tests are in
series.rs.

## Findings the tests forced

### F1 — `INTERVAL=0` / `COUNT=0` returned `Ok([])` (fixed in-lane)

`rrule-0.14.0` validates `FREQ=DAILY;INTERVAL=0` and `FREQ=DAILY;COUNT=0` as acceptable,
then `RRuleIter::generate` short-circuits on both (`if rrule.interval == 0 { return true }`,
`if matches!(self.count, Some(0)) { return true }`) and the iterator yields nothing. That
is precisely the shape the blueprint forbids: a defective rule arriving as an empty
calendar, indistinguishable from a quiet week. RFC 5545 makes both rule parts positive
integers, so `expand_window` reads them off the validated rule and returns
`InvalidRecurrenceRule`. Caught by `expand_window_malformed_rule_is_typed_error`, which
now carries both.

### F2 — `sort_unstable` + `dedup` are assertions, not transformations (kept, deliberately)

Probed by deleting `dedup` and re-running: the suite stayed green, i.e. no reachable
input duplicates today. The engine yields ascending civil times and the border is
increasing, so ascending-and-unique currently falls out of the pipeline. Kept anyway,
and the test says why rather than pretending the fixture proves a de-duplication:
normalization is a postcondition this door promises to two later consumers (CAL-09
freebusy, ONE-1539/CMT-2), and inheriting it from a third-party crate's yield order —
which grows a merge queue the moment a rule carries more than one generator — makes it
rot silently. Two lines, O(n log n), buys a guarantee that cannot decay.

## Base red on `origin/main` 98195c3b8 — charged to no lane

`cargo check -p oneiron --all-features --tests` fails on the base commit, before any
edit of mine:

```
error[E0063]: missing field `approx` in initializer of `edit_distance::delta::OpsSummary`
  --> crates/oneiron/src/edit_distance/escalation/tests.rs:26:22
```

ONE-1758 (#612) added `OpsSummary::approx`; ONE-1762 (#613) merged after it with an
`OpsSummary` literal that predates the field. Zero textual conflict, so both PRs were
green on their own bases — the named semantic-merge-skew class. The whole `oneiron` lib
test target does not build on main right now, so no lane cutting from this commit can run
a test.

I patched it locally (`approx: false`) only to verify my own work, then reverted; the
lane diff contains no `edit_distance` byte. Verify with `git diff --name-only`. It needs
a one-line fix from whoever owns that file — flagging, not taking.

## Gate log

- `cargo check -p oneiron --all-features` (lib) — clean.
- `cargo test -p oneiron --all-features --lib calendar::` — 56 passed, 0 failed
  (15 series tests + the owner-enum test + CAL-00/01/07/09 unchanged).
- `cargo test -p oneiron --all-features` (full crate, base red patched locally) —
  3806 + all integration targets passed, 0 failed.
- `cargo clippy -p oneiron --all-features --all-targets` — clean.
- `cargo fmt -p oneiron --check` — clean.
- Packet check: `git status --porcelain` = `M calendar/mod.rs`, `?? calendar/series.rs`,
  `?? WORKLOG-ONE-1785.md`. `Cargo.lock` is dirty from the `rrule` resolve and is never
  staged.

## SIMPLIFY pass (K3) — verdict: NO EDIT WARRANTED

Deletion-biased review of the impl leg at 6e5686e22, against the doctrine checklist:

- **Layers** — five private helpers, one job each: `wall_clock` (2 uses), `wall_clock_at`
  (3 uses), `invalid_rule` (4 uses), `parse_rule`, `wall_clock_of`. The two single-use
  helpers earn their names: `parse_rule` keeps the UNTIL-border translation out of the
  main walk, and `wall_clock_of` is the named inverse conversion the fold arm reads
  through. Nothing to collapse.
- **Duplication** — none; `wall_clock_at` exists precisely because the seed/window-bound
  conversion was written three times.
- **Defensive branches** — every error arm is a ratified typed verdict (gap, fold,
  inverted window, never-fire rule, step budget), each pinned by a named test. The
  `wall_clock(...).ok_or(TimestampOutOfRange)` arm is one line of invariant insurance
  naming the correct owner-enum error; deleting it would restructure, not simplify.
- **Speculative generality** — none: the public surface is exactly the blueprint's six
  names plus the two blueprint-minted `From` impls. `RRuleSet::limit()` is load-bearing
  (enables validation limits for the direct-Iterator path this module uses), not
  vestigial. `sort_unstable` + `dedup` were already probed by the implementer (F2) and
  are the door's normalization postcondition, kept.
- **Guard reachability** — the `start >= window.start` push guard looks redundant under
  `wall_to_utc` monotonicity but is reachable exactly at a fold when `window.start`
  stands on the later leg; it is the symmetric twin of the D4 termination rule and stays.
- **Comment density** — matches the module's established voice (cf. `tz.rs`); prose is
  not structure and was left alone.

Public API, test assertions and fixtures untouched by construction (zero code edits).

Gate receipt at handoff: `cargo check -p oneiron --all-features` clean; `cargo clippy
-p oneiron --all-features --lib` clean; `cargo fmt -p oneiron --check` clean;
`cargo test -p oneiron --all-features --lib calendar::` — 56 passed, 0 failed (base-red
`approx: false` patch applied for the run, reverted; `git status --porcelain` =
`M Cargo.lock` only, unstaged per law).

## VERDICT-FIX (Opus, on the simplify tip 25a456525)

Finder returned 4 items; adjudication banked item 1 and confirmed three REAL P2s. All
three fixed at their chokepoint, each red-before/green-after by deleting the fix line and
re-running the test that names it. Item 1 (`rrule-failure-typing`, the `Ok([])` for
`FREQ=HOURLY;INTERVAL=2;BYHOUR=10`) is **not relitigated**: it was rejected with
derivation as valid RFC text truthfully matching nothing, and the demanded
phase-reachability analysis is exactly the hand-rolled RFC 5545 recurrence semantics
blueprint bullet 6 forbids.

### V1 — `dst-fold-until-correctness` (P2, REAL): UNTIL is an instant, not a wall clock

`UNTIL=20261025T011500Z` was translated once onto the London wall clock and handed to the
recurrence engine as its stopping point. Inside the fold that translation is lossy in the
one direction that matters: the bound reads 01:15 GMT, while the 25th's occurrence stands
at 01:30 BST — *later* on the clock, and 45 minutes *earlier* as an instant (00:30Z vs
01:15Z). The engine stopped on the clock and dropped an occurrence the rule's author had
kept, so a freebusy consumer would show the owner free in an hour they are booked.

Fix: the rule's `UNTIL` becomes a second **instant** bound, next to the window's own end,
and the series ends at `min(window.end, until_utc)` — the same dual shape the window
already had (instant for membership and termination, its wall clock only for scoping gap
errors). The engine still gets a wall bound so it stops walking, but a deliberately loose
one (`UNTIL_WALL_SLACK_SECS`, a day; no post-epoch IANA transition rewinds a clock that
far), because no wall time can be equal to the instant inside a fold. Overshoot is cut
exactly by the instant bound.

Two consequences, both pinned:
- `expand_window_ends_an_until_series_on_the_utc_instant` — the finder's trace. Was
  `[1792715400, 1792801800]`, now `[1792715400, 1792801800, 1792888200]`.
- `expand_window_does_not_report_a_gap_after_the_series_ended` — the gap-error scope
  follows the *series* end, not the window's: a series that stopped the day before
  London's spring-forward gap no longer turns a completed expansion into
  `NonexistentWallTime`. Mutation-verified by restoring `last` to `window.end`.

Regression the slack would otherwise have introduced, caught and closed: the engine's own
`UntilBeforeStart` validation is now a day loose, so `FREQ=DAILY;UNTIL=<a day before
DTSTART>` would have returned `Ok([])` — the exact silent-empty class this module exists
to refuse. The never-fires gate now reads the exact instant and joins it to the
`INTERVAL=0` / `COUNT=0` arms: three ways to never fire, one verdict. Mutation-verified
(deleting the clause returns `Ok([])`), pinned as a third case in
`expand_window_malformed_rule_is_typed_error`.

### V2 — `rrule-validation` (P2, REAL, both arms): a thin input guard on the text

`parse_rule` treated dependency parse + range validation as complete RFC validation. It
is not, in two ways the finder reproduced:

- **`COUNT` + `UNTIL` co-present.** RFC 5545 makes them mutually exclusive;
  `FREQ=DAILY;COUNT=2;UNTIL=20260131T090000Z` returned `Ok([1767603600, 1767690000])`. A
  rule naming two endings names none, and picking one for its author is not this door's
  call — rejected.
- **Non-RRULE content lines.** `ContentLineCaptures` reads the property name and
  `TryFrom<ContentLineCaptures> for RRule` then ignores it, so `DTSTART:FREQ=DAILY`,
  `EXRULE:FREQ=DAILY`, `EXDATE:FREQ=DAILY` and `RDATE:FREQ=DAILY` all parsed into a
  fabricated daily series — including `EXDATE`, whose whole job is to *remove*
  occurrences. The property name is now checked on the text: `RRULE` or nameless, case
  insensitive per the RFC.

Both are guards on the input string, not recurrence stepping: the vetted validator stays
the RFC authority for everything it does cover. Pinned by
`expand_window_rejects_text_the_dependency_alone_accepts`, which also asserts the three
accepted spellings (`FREQ=…`, `RRULE:FREQ=…`, `rrule:FREQ=…`) still expand. Each arm
mutation-verified separately.

### V3 — `public-api-surface` (P2, REAL): the crate-root re-export, D1 reversed

The impl leg narrowed the packet and declared it as D1. The relay packet grants "lib.rs
append re-exports" explicitly and the adjudication confirmed the finding, so D1 is
withdrawn, not re-argued: `crates/oneiron/src/lib.rs` now appends `SeriesDtStart`,
`SeriesExceptionKey`, `exception_identity`, `expand_master_window`, `expand_window` and
`mask_master_exceptions` to the existing `pub use crate::calendar::{…}` block. Append
only — no existing name moved, no `CalendarError` re-export invented, so the rebase
surface against ONE-1791/ONE-1786 is one contiguous added line group.

Pinned by `series_surface_is_reachable_from_the_crate_root`, which names each item's
**signature** at the root path rather than just importing it, so the shared-consumer
oracle (engine scalars in, `Result<Vec<u64>, CalendarError>` out, no wrapper) is checked
at the same time. Red-before was a compile error: six `E0425`/`E0412` at the crate root.

### Gate log (VERDICT-FIX)

- `cargo fmt -p oneiron --check` — clean.
- `cargo clippy -p oneiron --all-features --all-targets` — clean, zero warnings.
- `cargo test -p oneiron --all-features --lib calendar::series` — 19 passed, 0 failed
  (15 before, +4 named tests).
- `cargo test -p oneiron --all-features` — 3809 passed in the lib target plus every
  integration target, 0 failed.
- Packet: diff touches `crates/oneiron/src/calendar/series.rs`,
  `crates/oneiron/src/lib.rs` and this worklog. No `Cargo.toml`, no `Cargo.lock`, no
  `calendar/claims.rs`, no `edge.rs`, no `registry.rs`.
- Base red on 98195c3b8 (`OpsSummary::approx`, ONE-1758/ONE-1762 semantic merge skew) is
  unchanged and still blocks the lib test target on a clean base. Patched locally with
  `approx: false` for the runs above and reverted; `git diff` contains no
  `edit_distance` byte.
