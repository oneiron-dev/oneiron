# WORKLOG — Cluster A fix-forward on ONE-1728-ca-fix

Branch `ONE-1728-ca-fix` cut from worktree root `42cb5e6` (carries #566 ancestry through the redo lineage).
Worktree: `/Volumes/Cinema/w5-lt/spine-1728-ca`. Workers never push; orchestrator publishes above main tip `59a430183` after CY.

Union verdict fix-orders on this branch: CAL restore · ROUTE/lock/shell · SESSION-DOORS.

## FIX-CAL — calendar.* structural validation dispatch arm restored (seat Opus) — DONE

Finding: Qodo-4 + Codex-1 deduped. `validate_claim_body_and_decode` in
`/Volumes/Cinema/w5-lt/spine-1728-ca/crates/oneiron/src/claim.rs` chained thirteen predicate-aware
structural arms (edge.provenance … delivery_window) with **no calendar arm**, while
`crates/oneiron/src/calendar/claims.rs:10-13` documents `validate_calendar_claim_structure` as
"wired into the write-only validator chain in `crate::claim`". The wire was dropped in the
extraction redo.

### Ground truth (own the grep)

- Arm existed at `8fb98e642` (ONE-1782 [CAL], #573) as the **last** arm of the chain, after `delivery_window`.
- Removed at `42cb5e62b`; the squash-merge `7978e74c9` (#578) also lacks it → **the regression is live on main**, not branch-local.

### Red baseline (before fix), `cargo test -p oneiron --lib calendar`

    calendar::claims::tests::calendar_claims_require_event_subjects          FAILED
    calendar::claims::tests::calendar_claim_validator_rejects_malformed_shapes FAILED
    claim::tests::write_door_validates_calendar_claim_structure              FAILED
    13 passed; 3 failed

Every failure is `left: Ok(())` where a rejection was required — malformed calendar claims were
storing through the public write door.

### Fix

Restored the arm at its exact pre-removal position (last, after `delivery_window`):

    } else if crate::calendar::claims::is_calendar_claim_predicate(&body.predicate) {
        crate::calendar::claims::validate_calendar_claim_structure(&body)?;
    }

`validate_claim_body_and_decode` (doc comment + body) now diffs **byte-identical** to the
pre-removal `8fb98e642` version. Two added lines; no other file touched.

### Mutation verification

1. **Arm absent** (the red baseline above) → the 3 tests fail. Guard+call are load-bearing.
2. **Mutant A** — validator body stubbed to `if true { return Ok(()); }` with the arm present →
   the same 3 tests fail. Proves the *call* is load-bearing, not merely the `else if` guard
   (an arm that matched but no-op'd would not be caught by (1) alone).
3. **Arm-order safety** — the arm is last, so an earlier matcher intercepting a `calendar.*`
   predicate would leave it dead. Verified none can: every earlier matcher is exact-table
   `.contains()` or exact `==` (no prefix matching anywhere in the chain), and
   `rg '"calendar\.' crates/oneiron/src/ --glob '!calendar/**'` returns nothing — no foreign
   family table holds a calendar string. All 12 predicates reach the arm.

### Gates

- `cargo test -p oneiron --lib calendar` → 16 passed, 0 failed (3 previously-red now green).
- `cargo fmt --all -- --check` → clean.
- `cargo test -p oneiron` (full package) → **2984 passed, 0 failed**.
- `cargo clippy -p oneiron --all-targets --all-features` → 2 errors, both in
  `crates/oneiron/src/secret_custody/tests.rs` (`field-reassign-with-default`,
  `items-after-statements`). **BASE-RED**: reproduced identically on the clean base with my diff
  stashed. Outside this diff (my diff is `claim.rs` only), charged to no lane, quarantined per the
  base-red rule. Belongs to the L1-SECRET packet.

## FIX-ROUTE — route revalidation · segment install · lock order · shell claim (seat Opus) — DONE

Four commits on top of the CAL leg's tip `24251f18`, one per fix-order, each with its own
TEST-MUTATION receipt in the commit message:

| commit | order | shape |
|---|---|---|
| `ab8bf9d9` | R1 (P1) | base witness txn revalidates the session write route |
| `b1021127` | R2 (P1) | session retrieval telemetry installs its overlay txn segment |
| `1aadaf1b` | R3 (P1) | base writer taken BEFORE the segment permit (ABBA removed) |
| `e5752b5c` | R4 (P2) | room shell claim is a reservation, released on failure |

Files touched: `crates/oneiron/src/facade.rs`, `crates/oneiron/src/facade/tests.rs`,
`crates/oneiron/src/pipeline.rs`, `crates/oneiron/src/pipeline/tests.rs`,
`crates/oneiron/src/store.rs`, `crates/oneiron/src/off_record/lifecycle.rs`.

### R1 — stale route under an OnRecord→OffRecord flip

`witness_into_session` minted the route, took the `Base` arm, and handed the turn to `witness()`,
which had never heard of the route. Overlay arms revalidate inside their txn AND are excluded from
a mode publication by `seal_writes` draining the active segment; a base-routed witness carries no
segment, so nothing stopped it committing turn + messages + continuation shell to durable base
under a room that had flipped back off-record.

`witness()` now delegates to `witness_with_route(turn, Option<&SessionWriteRoute>)`, which
revalidates as the LAST statement inside the write transaction (every staged row rolls back with
the refusal). It deliberately does NOT take the session state lock: `tag_turn_off_record` holds
that lock across its own write txn (state → writer), so a base writer taking it inverts the order.
Residual window (named in the doc comment): the instant between the check and `wtxn.commit()`.

**Mutation**: `route.revalidate()?` replaced by `let _ = route;` with the `if let` kept → the new
test fails holding a `WitnessReceipt`, i.e. the base rows landed. The CALL is load-bearing, not the
guard.

### R2 — the session telemetry arm was 100% dead

`run_for_pack`'s `session_view` arm opened a base write txn and staged through the composed
`vault_meta` accessor with NO txn segment installed, so every call failed with "session overlay
write requires an active txn segment", was swallowed by the warn-and-continue path, and returned
`telemetry_run_id: None`. The K8 pre-close census therefore had zero context receipts to evaporate
and an in-room caller could not see its own runs.

Segment now installs inside the `with_write_txn` closure and the guard commits after the base txn
returns. `SessionStoreView` gained the overlay handle it already composed over plus
`install_txn_segment()` (a staging site should not need the session handle threaded alongside the
view). Deliberately NOT changed: the view's snapshot stays pre-segment — the retrieval-run staging
body has no read-modify-write on a key it writes in the same call, unlike the witness, which
re-takes a view per journal entry for exactly that reason.

**Mutation A** (install removed = the shipped shape): fails at "a session run registers its
telemetry row". **Mutation B** (installed, guard dropped instead of committed): fails at "the run
row is readable through the room's composed view".

### R3 — ABBA: segment permit before base writer

`acquire_segment_lease`'s own comment pins the order ("Base writers are acquired before this
permit; there is no reverse-order path") and the witness obeys it. Both overlay arms in
`off_record/lifecycle.rs` did the opposite (`install_txn_segment()` then `with_write_txn`), so a
witness holding the base writer and waiting for the permit met a telemetry/`vault_meta` run holding
the permit and waiting for the writer. Nothing in the stack has a timeout: a hard hang on one room.

Both arms now install inside the closure, order install → revalidate → stage (once the segment is
installed, `seal_writes` must drain it before publishing a new mode generation, so a revalidate
that passes after the install is genuinely exclusive against the flip). The staging view moved
inside with the install, preserving its reason to exist (segment-aware, unlike the scoring view).

**Mutation** (pre-fix order restored in `search_text` only): the new 3-thread test fails on its
watchdog at 90.01s — "concurrent room witness + telemetry deadlocked". With the fix: ~0.3s. The
race runs in a DETACHED driver thread with a channel watchdog on purpose — a deadlock inside
`thread::scope` hangs the suite even while unwinding, so a regression must fail, not hang.

### R4 — one-shot claim consumed before fallible work

`claim_overlay_conversation_shell` did `mem::replace(overlay_shell_staged, true)` with no rollback,
consumed BEFORE `id_from_optional_hex` / `encode_witness_message_body` (caller-controlled) and
before the write txn. A first witness with `message[0].id = "zz"` returned `Err` having staged
nothing, yet the room read as shell-staged: later witnesses staged `PartOf`/`BelongsTo` edges
against a conversation id with no entity row — a dangling journal promote replays at ONE-1730.

BOTH halves of the order taken, because either alone leaves the bug live: the claim moved after all
pre-txn fallible work AND became an `OverlayShellReservation` RAII guard that releases on drop
unless `commit()` runs after the base txn and the segment commit (the txn body is fallible too:
actor binding, overlay budget). Journal order preserved — the shell `Put` is inserted at index 0.
One residual window is named in the doc comment (a second witness reading `None` while the first is
in flight and committing before the first fails); closing it needs the state lock across the write
txn, which is the R3 deadlock.

**Mutation B** (`Drop` rollback removed): the in-transaction test fails — "the released claim let
the next witness stage the shell row". **Mutation C** (claim at the pre-fix position, guard
`mem::forget`ed): the malformed-id test fails — "the room's conversation shell row exists, so no
edge dangles". Note the honest split: with the fix, the malformed-id test alone does NOT exercise
the rollback (the reservation is never reached) — verified by suppressing only the rollback and
watching that test stay green. That is why BOTH tests exist.

### Gates

- `cargo fmt --all -- --check` → clean (exit 0).
- `cargo test -p oneiron --lib` → 2879 passed, 0 failed (per-commit cheap gate, four times).
- `cargo test -p oneiron` (full package, all targets incl. `tests/session_overlay_spec.rs`) →
  **exit 0, every binary green**, lib 2879 passed / 0 failed.
- `cargo clippy -p oneiron --all-targets --all-features` → the SAME 2 errors the CAL leg recorded,
  both in `crates/oneiron/src/secret_custody/tests.rs` (`field-reassign-with-default`,
  `items-after-statements`), plus 3 pre-existing warnings, ALL in that same file. **BASE-RED, L1-SECRET
  packet.** Re-run with only those two lints allowed: zero findings anywhere in this diff.

### Flake, attributed and charged to no lane

One full-package run went red on
`attempt_queue::tests::attempt_queue_cleanup_log_span_has_stable_privacy_preserving_fields`
("cleanup span records=[]"). Grep owned:

- 1 red in 4 full-lib runs on this branch; green on the immediately following re-runs, green on the
  final full-package run, green 6/6 running the `attempt_queue` module alone, and green on a full
  lib run of the parent commit `24251f18`.
- The assertion is purely tracing-capture. SIX tests in six modules (`attempt_queue`, `receipt`,
  `embed`, `sync::bridge`, `gate`, `authority`) install thread-local subscribers with
  `tracing::subscriber::with_default` while the suite runs in parallel, and `tracing`'s callsite
  interest cache is process-global — a classic load-dependent capture flake.
- This diff touches no `attempt_queue` code, no tracing setup, and installs no subscriber.

Charged to no lane per the flake guard. Candidate known-hole for the wave: serialize or
`#[serial]`-gate the six `with_default` tests.

## FIX-SESSION-DOORS — session claim validation · failed-decode surface (seat Opus) — DONE

Two commits on top of the ROUTE leg's tip `23ac997d`, one per fix-order, each carrying its own
TEST-MUTATION receipt in the commit message:

| commit | order | shape |
|---|---|---|
| `c57b62d7` | S1 (P2) | the session write door validates CLAIM bodies |
| `ea40544a` | S2 (P2) | the oracle's ScopedRead census surfaces an undecodable body |

Files touched: `crates/oneiron/src/batch.rs`, `crates/oneiron/src/batch/tests.rs`,
`crates/oneiron/src/branch_store_oracle.rs`.

⚠ The brief's third item, "pipeline.rs missing segment arm", is **R2**, already fixed in
`b1021127`. Confirmed against the diff and NOT double-fixed.

### S1 — the session door judged the type byte, never the body

`apply_ops_session`'s Put arm ran `validate_public_entity_type` and went straight to
`stage_entity_body_row`; `validate_claim_body_and_decode` never ran. A session CLAIM put with a
malformed body staged into the overlay, was journaled, and read back through the room's composed
view. Promote replays that same op through `apply_ops` → `apply_put`, whose D18 arm
(`batch.rs:3191`) does validate — so the write was fail-closed at PROMOTE and
wrong-but-evaporating in-room: the room showed its caller a claim that could never land, and the
refusal arrived a whole session later attached to promote rather than to the write that was wrong.

The arm now runs the full validator before the first staged byte, under **the op's OWN
`allow_reserved_predicate`** — the same field `apply_put` reads off the same op at promote, so
in-room admission is byte-exactly promote's admission. Hardcoding `false` would instead refuse
in-room a body promote WOULD accept: the same divergence facing the other way.

**Red baseline**: the new test's case 1 panicked at `expect_err` — apply returned `Ok`, the
malformed body staged.

**Mutations** (test: `batch::tests::session_apply_validates_claim_bodies_before_staging`; three
cases — undecodable bytes / calendar claim with an EDGE subject / calendar claim with an integer
`tz` value; each asserts `InvalidClaimBody` AND an empty overlay snapshot + empty journal):

1. **M1 arm absent** (the pre-fix shape) → fails on case 1. Guard+call are load-bearing.
2. **M2 result discarded** (`let _ = validate(..)`) → fails on case 1. The `?` PROPAGATION is
   load-bearing, not merely the presence of the call.
3. **M3 `decode_claim_body` substituted** for `validate_claim_body_and_decode` → case 1 PASSES,
   case 2 FAILS. The family structural chain — including the calendar arm restored by the CAL leg
   in `24251f18` — is load-bearing, not just the decode. This is the discrimination that makes it
   the right validator rather than a cheaper one, and it ties the two legs together: the session
   door now enforces the same fourteen-arm chain the base door does.

### S2 — the census swallow was real in SHAPE, unreachable in FACT

Ordered fix applied: `scoped_read_visible_claim_count`'s
`let Ok(body) = decode_claim_body(..) else { continue }` became a propagating `?`.

**But the finding's undercount trace does not hold on this codebase, and the change is a
dead-branch removal rather than a behavior change.** Owning the grep: `ScopedRead::get` →
`get_entity_parts` → `is_claim_raw_readable_in` → `is_claim_raw_readable_with_policy_in` already
runs `decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?` at `claim.rs:515` — the SAME
bytes, the SAME permissive flag — and propagates. A body that reaches the helper has therefore
already decoded once, so the second decode cannot fail. The one adjacent case, a row of exactly
header length, is a deleted shell, which `get` reports as `None` and the loop's other arm handles.

**Receipt for the unreachability claim itself**: the new test PASSES on the unmutated pre-fix tree.
Recorded rather than quietly dropped — a test that would be green anyway is precisely what a
mutation pass exists to expose.

**Two-level mutation** (upstream `claim.rs:515` rewritten to
`let Ok(body) = .. else { return Ok(true) }`, making `get` hand back an undecodable body):

- **WITH the fix** → PASSES: the census still refuses.
- **WITHOUT the fix** → FAILS, returning `1`: the census silently dropped the unreadable row and
  reported a number it could not justify. Qodo-2's scenario exactly — reachable only once the
  upstream contract goes lenient.

That pair is what makes the change load-bearing: it is the guard that keeps the census honest if
`get`'s fail-closed decode is ever relaxed. The reasoning is in the code comment, so the next
reader does not re-litigate a branch that looks dead without knowing why it is safe.

The test (`branch_store_oracle::scoped_read_claim_census_surfaces_an_undecodable_body`) plants
rows through a new `plant_raw_claim_row` helper that bypasses every write door — after S1 that is
the only way left to get an invalid claim body into the store. It asserts a **positive control
first** (a legal planted claim counts 1), so the refusal cannot pass vacuously on an empty
enumeration.

### Gates

- `cargo fmt --all -- --check` → clean (exit 0), both commits.
- `cargo test -p oneiron --lib` → per-commit cheap gate: 2880 then 2881 passed, 0 failed
  (2879 inherited + 2 new tests).
- `cargo test -p oneiron` (full package, all targets) → **exit 0**, 33 test-result-ok blocks,
  lib 2881 passed / 0 failed.
- `cargo clippy -p oneiron --all-targets --all-features` → the SAME 2 errors both prior legs
  recorded, both in `crates/oneiron/src/secret_custody/tests.rs`
  (`field-reassign-with-default`, `items-after-statements`), plus 3 warnings all in that same
  file. **BASE-RED, L1-SECRET packet**, untouched by this diff. Re-run with only those two lints
  allowed: zero findings anywhere in this diff.

### Flake, re-attributed and charged to no lane

One full-package run went red on
`attempt_queue::tests::attempt_queue_cleanup_log_span_has_stable_privacy_preserving_fields`
("cleanup span records=[]") — the SAME test, same shape, the ROUTE leg documented. Flake guard
applied: the `attempt_queue` module alone → 40 passed / 0 failed; the immediately following full
lib run → 2881 passed / 0 failed; the final full-package run → exit 0. Two earlier full lib runs
in this leg were green. This diff touches no `attempt_queue` code, no tracing setup, and installs
no subscriber.

**Second independent occurrence across two legs** — the ROUTE leg's known-hole candidate
(serialize or `#[serial]`-gate the six `tracing::subscriber::with_default` tests) is now
corroborated, not a one-off. Recommend banking it.

NEXT: Cluster A union verdict is COMPLETE on this branch — CAL (`24251f18`), ROUTE R1-R4
(`ab8bf9d9`, `b1021127`, `1aadaf1b`, `e5752b5c`), SESSION-DOORS S1-S2 (`c57b62d7`, `ea40544a`).
Orchestrator publishes + merges above main tip `59a430183` after CY. Workers never push.
