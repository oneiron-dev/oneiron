# WORKLOG — ONE-1758 [ED-02] Myers reconstructed-diff lane

Branch `ONE-1758` off `origin/main` b3c1fd756 (ED-A layer 3 of 3; 1756 #607-era,
1757 #608, 1761 #609 already merged).
Blueprint: `/Users/olety/.claude-wave5/blueprints/ED/ONE-1758.md`.

## What landed

| file | action |
|---|---|
| `crates/oneiron/src/edit_distance/myers.rs` | CREATE — two-pass line diff |
| `crates/oneiron/src/edit_distance/myers/tests.rs` | CREATE — fixtures |
| `crates/oneiron/src/edit_distance/delta.rs` | MODIFY — reconstructed producer, third chooser arm, pinned `d_norm` moved onto `OpsSummary` + move-discount term |
| `crates/oneiron/src/edit_distance/delta/tests.rs` | MODIFY — see PACKET_AMEND below |
| `crates/oneiron/src/edit_distance.rs` | MODIFY — `pub mod myers;` |

Shape: pass 1 is classic Myers O(ND) over INTERNED line ids (a shared
`HashMap<&str, u32>`, so equal ids mean equal lines — no hash collision can
make two different lines diff as one); pass 2 pairs each deleted id against an
identical insertion by multiplicity and moves the pair out of `ins`/`del` into
`moved`. Common head/tail lines are trimmed before Myers runs, which is what
keeps a one-line edit inside a 10k-line artifact exact and cheap.

`d_norm` is the blueprint formula verbatim:
`clamp((ins + del + 2·MOVE_DISCOUNT·moved) / (len_before + len_after), 0, 1)`.

## Deviations from the blueprint (declared, none silently absorbed)

1. **`MOVE_DISCOUNT = 0.1`, not the relay's `0.2`.** The dispatch relay said
   `MOVE_DISCOUNT = 0.2`; the blueprint says `0.1` in two internally-consistent
   places (the skeleton `pub const MOVE_DISCOUNT: f32 = 0.1;` at line 23, and
   line 14's "a moved line-pair costs `0.2` instead of the `2.0`", which is
   `2 · 0.1`). Read the relay's `0.2` as the per-PAIR cost transcribed into the
   const name. Took the blueprint. If the owner meant a per-pair cost of 0.4,
   this is a one-const change and `a_relocated_block_costs_the_discount_of_a_replaced_one`
   is the test that moves with it.

2. **`LineDiff.approximate` is an accessor, not a field.** The blueprint's
   skeleton has both `LineDiff.approximate: bool` AND "flows into Δ
   `ops_summary` as an `approx` field". Two mutable copies of one fact can
   disagree; `OpsSummary.approx` is the one that reaches disk, so it is the
   single source and `LineDiff::approximate()` reads it. Caller ergonomics are
   unchanged except for the parens.

3. **The precedence test uses `moved` as the spy, not an injected flag.** The
   blueprint asked for "spy/flag in test". A real spy needs indirection (fn
   pointer or trait) that the same blueprint forbids ("no generic diff trait").
   `moved` is a strictly better witness: it is the ONLY counter no other
   producer can fill, so the test offers the chooser a context whose texts are
   a pure relocation (Myers would report `moved == 2`, asserted separately) and
   then asserts the chosen Δ carries `moved == 0` and equals
   `delta_from_recorded_ops` exactly. Myers cannot have run.

4. **No `lib.rs` re-exports** (the relay listed `lib.rs append re-exports` in
   the packet; I declined the slot rather than used it). Sibling `delta.rs`,
   the module this one feeds, has zero root re-exports — every consumer rides
   `crate::edit_distance::delta::*`, and all ED-02 consumers are in-crate. r2
   also says this lane never becomes the substrate; advertising
   `oneiron::myers_line_diff` at the crate root works against that. Reachable
   as `oneiron::edit_distance::myers::*` regardless. Cheap to add later if a
   downstream lane wants it.

## PACKET_AMEND candidate — `crates/oneiron/src/edit_distance/delta/tests.rs`

Not named in the dispatch PACKET (which names `delta.rs`, `myers.rs`,
`edit_distance.rs`, `lib.rs`). It is the `#[cfg(test)]` submodule OF
`delta.rs`, ED-lane-owned, landed by 1757 in this same stack — CLAIMS.md gives
`delta.rs` to {1757, 1758}. No other wave-5 lane claims it.

Two reasons the file had to move, both forced by the blueprint:

* `OpsSummary` gained `approx`, so five struct literals needed `approx: false`
  (mechanical; no assertion semantics touched).
* `DeltaCaptureContext` gained `texts`, so two struct literals needed
  `texts: None` (again preserving each test's meaning — the empty-context test
  still asserts `DeltaCaptureUnavailable`).

Beyond the mechanical sync I renamed two now-stale tests and added four Δ-level
ones (see below). Fixture-sync law observed: no existing assertion's expected
value changed.

## Design notes worth a screener's attention

* **`normalized_distance` deleted; `OpsSummary::d_norm(len_before, len_after)`
  replaces it.** The blueprint calls the formula "the ratified metric, all
  lanes" and 1758 makes it three producers. A free fn in `delta.rs` that
  `myers.rs` cannot see would have meant a second copy of the formula — the
  exact drift the pin exists to prevent. All three producers now normalize at
  one site, and `the_move_discount_reaches_d_norm_through_the_pinned_formula`
  asserts the reconstructed lane's `d_norm` equals `ops.d_norm(4, 4)` rather
  than a number Myers computed for itself.
* **`edit_mass` is now `f64`** (was `u32`) because the move term is fractional.
  `2.0 * MOVE_DISCOUNT` is exactly `0.2f32` (doubling is exact in binary), so
  no existing exact-equality assertion moved: `recorded_ops` still scores
  exactly `0.5`, field-diff full-rewrite still exactly `1.0`.
* **Cap = `MAX_EDIT_SCRIPT: usize = 1024`, private.** The cap IS the memory
  bound: the backtrackable trace is `(D+1)²` cells packed at offset `d²`
  (~4 MiB worst case at 1024). Past it the trimmed middle is charged as a whole
  replacement — an upper bound, never an understatement — pass 2 still runs
  over it, and `approx` rides the Δ to disk. `wall_reversed` in the fixtures is
  the interesting case: 1024 relocated lines blow the cap AND still pair, so
  the bound self-corrects from `d_norm 1.0` down to `0.1`.
* **Guard cells in the frontier.** First test run panicked at `max_d == 0`
  (both middles empty after the trim, i.e. identical texts): the greedy rule
  reads diagonal `k±1`, and at `|k| == max_d` one neighbour is off the board.
  Frontier is `2·max_d + 3` wide with `offset = max_d + 1`; the off-board cell
  reads `0`, which is exactly what the classic `v[1] = 0` seed means. Caught by
  four fixtures, not by inspection — worth a screener's eye.
* **Move pairing is deliberately dumb about blank lines.** Deleting three blank
  lines and inserting two elsewhere reads as two moves. At line granularity
  that is defensible, and the alternative (excluding "uninteresting" lines) is
  a heuristic this lane is explicitly not allowed to grow.

## Boring-by-law compliance

No generic diff trait, no char-level mode, no rename detection, no new deps
(`Cargo.toml` untouched), no imports from `edit_roundtrip` / `edit_settle` /
`distance.rs`. `myers.rs` imports exactly `std::collections::HashMap` and
`edit_distance::delta::{OpsSummary, u32_saturating}` (the latter lifted from
private to `pub(super)` rather than copied).

## Done-means

- [x] Identity `d_norm 0` · full replace exactly `1` (one-line replace = 2/(1+1),
      pinning the SUM denominator) · known edit script with exact ins/del/kept ·
      move fixture asserting `relocated.d_norm == MOVE_DISCOUNT * replaced.d_norm`
- [x] Bounds `[0,1]`, per-side line accounting (`before == del + moved + kept`,
      `after == ins + moved + kept`) and `before→after == after→before`
      symmetry, all over a fixture table of eight shapes
- [x] 10k-line artifact with a one-line edit stays exact (`approx == false`,
      `kept == 9_999`); over-cap input returns marked approximate and a Δ
      fixture DECODES the payload and reads the flag back
- [x] `capture_delta_best` precedence: recorded > field_diff > reconstructed
- [x] No new deps; no forbidden imports
- [x] fmt · clippy (`--all-features --all-targets`, clean) · `cargo test -p oneiron --all-features`

## Notes for the orchestrator

* **Pre-existing flake, charged to no lane:**
  `bm25::tests::bm25_diagnostics_increment_for_targeted_search_corruption`
  failed once in the first full-suite run (`left: 3, right: 1`) and passed on
  the flake-guard re-run (whole suite green, exit 0, zero `test result: FAILED`).
  It asserts an exact delta on a PROCESS-GLOBAL counter
  (`bm25_diagnostics_snapshot().count(MalformedPostingAlignment) == before + 1`,
  `crates/oneiron/src/bm25/tests.rs:1919`), so any concurrently-running bm25
  test that increments the same kind breaks it. Passes in isolation. This
  lane's diff touches five `edit_distance*` files and nothing in bm25 — a
  test-isolation defect in bm25's own suite, worth a ticket, not a fix here.
* `Cargo.lock` shows dirty in this worktree — cargo re-locked 16 packages
  (icalendar/rrule/chrono-tz family) that `main`'s `Cargo.toml` requires but
  its committed lock lacks. **Not this lane's change and NOT committed** (lock
  law). It reproduces on a clean checkout of b3c1fd756 the moment cargo runs.
* Commits: `e110644c4` (lane), plus a follow-up threading the end corner into
  `backtrack` (drops a dead `unwrap_or` fallback) and this worklog.
