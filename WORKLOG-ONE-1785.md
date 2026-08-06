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
