# WORKLOG — ONE-1729 [L1-STORAGE-SPINE P4b]

Session binding + effect policy for `code_run` / `engine_executor`.
Base: `origin/main` 233d8bc34 (ONE-1728/P4a merged, ONE-1924 merged). Branch `ONE-1729`.
Blueprint: `/Users/olety/.claude-wave5/blueprints/L1-STORAGE-SPINE/ONE-1729.md`
(re-aligned 2026-08-07 under owner ruling **R-20260807-02**; the re-aligned text was treated as ratified).

## Gates

| Gate | Result |
|---|---|
| `cargo fmt -p oneiron --check` | clean |
| `cargo clippy -p oneiron --all-features --all-targets` | clean, zero warnings |
| `cargo test -p oneiron --all-features` | **4454 passed, 0 failed, 55 ignored** |
| `tests/of060_fitness.rs` | 4/4 pass, **zero diff** |
| P4b oracle (`branch_store_oracle`) | 27 passed, 0 failed (8 ignored = 1730/1731/1732 stubs) |

Zero-diff pins reconfirmed against `origin/main`: `of060_fitness.rs`, `gate.rs`,
`code_run/tests.rs`, `store.rs`, `facade.rs`, `pipeline.rs`, `off_record/promote.rs`,
`Cargo.toml`, `Cargo.lock`. `STORAGE_ABI_VERSION` unchanged at 15. No entity byte,
migration, or durable session row.

## Packet (exactly the claimed set)

```
crates/oneiron/src/branch_store_oracle.rs   +760
crates/oneiron/src/code_run.rs              +541
crates/oneiron/src/engine_executor.rs       +195
crates/oneiron/src/engine_executor/tests.rs  +34   (PACKET_AMEND, mechanical)
crates/oneiron/src/error.rs                  +14   (append-only, ONE variant)
crates/oneiron/src/off_record/lifecycle.rs  +343
crates/oneiron/src/off_record/mod.rs          +4   (re-export only)
```

`gate.rs` — claimed for rebase context; **zero diff**, as the blueprint expected.
`code_run/tests.rs` — conditional PACKET_AMEND **not needed**: both public constructors
(`HostSelfDispatcher::new`, `EngineNativeExecutor::new`) stayed source-compatible on `&Vault`.

## K3 census (§20 verify-then-delete posture)

Repo-wide `rg`, run before AND after implementation:

| Symbol | Hits |
|---|---|
| `register_code_run_artifact_in_txn` | **0** |
| `code_run_artifact_keys` | **0** |
| `search_text_without_telemetry` | **0** |

Sites referencing the code-run prefixes: **only the two real key builders** —
`code_run_replay_record_key` (`code_run.rs:1345`) and `code_run_raw_output_key`
(`code_run.rs:1352`). No allow-list, no close-sweep, no enumeration of both prefixes
anywhere else. **Zero-hit census as expected; nothing deleted, nothing replaced.**
`code_run:replay:v1:` and `code_run:raw_output:v1:` are unchanged.

No `search_text_without_telemetry` escape hatch introduced. Session `MemorySearch` uses
`ExecutorStorage::search_text` → ONE-1728's composed `OffRecordSession::search_text`,
whose retrieval-run row registers into the room's overlay `VaultMeta`.

## ONE-1936: guard NOT yet landed

`dispatch_memory_supersede_claim` on the merge base reaches
`Vault::supersede_claim_for_code_run_trap` with **no stale-target walk** — ONE-1936's
guard is not present at 233d8bc34. Per the blueprint's conditional, the partition is
asserted **structurally**: the effect-policy rejection fires before the supersede
write-transaction entry point, evidenced by the zero base-delta AND zero overlay-delta
brackets around the public dispatch call in
`durable_memory_write_verbs_stay_policy_rejected_off_record`. Nothing in ONE-1936's zone
was edited; the only supersede diff is the `Canonical | Session` route match around the
unchanged trap call.

## Tracing audit

My diff adds **zero** tracing / log / print statements to `code_run.rs`,
`engine_executor.rs`, and `off_record/lifecycle.rs`. One pre-existing site remains
(`lifecycle.rs:1487`, ONE-1728's fence-scrub deferral) logging a turn-id hex plus a typed
error Display — ids and typed error codes only, no content. Compliant.

## Blueprint deviations — declared, none silently absorbed

**D1 — `ExecutorStorage::Session` carries a `SessionBinding`, not a bare handle.**
Skeleton pins `Session(&'a OffRecordSession<'a>)`. Shipped:
`Session(SessionBinding { session, route, container })`.
*Derivation:* R-20260807-02 rider 2 requires the run's `SessionWriteRoute` to be captured
once at run entry, stored, and used by every apply. ONE-1728's `vault_meta_put` mints its
own route per call (`let route = self.write_route()?`) — exactly the "silently capture a
fresh route" the blueprint forbids on the executor path. Putting the route inside the
Session arm makes "one route per run" a **type fact** rather than a discipline. The enum
stays exhaustive `Canonical | Session`; neither arm exposes `Store` or a base `Vault`.
Sister change: added `OffRecordSession::vault_meta_put_routed` (route-carrying), with
1728's `vault_meta_put` delegating to it — one body, no duplication.

**D2 — `witness_executor_turn` takes an extra `actor: WriteActor`.**
*Derivation:* the entry must call ONE-1728's `MemoryFacade::witness_into_session`, and a
`MemoryFacade` cannot exist without `(actor, actor_class)`; the door runs
`verify_actor_binding_in_txn` on **both** arms (`facade.rs:1975`). Unavoidable. Every
other pinned parameter kept verbatim, including `container: &EntityId` and
`turn_ref: Option<&EntityId>`.

**D3 — facade error mapping.** The skeleton pins `-> Result<WitnessReceipt>` (crate
`Result`) but `witness_into_session` returns `FacadeResult`, and there is no
`From<FacadeError> for Error`; `FacadeError` flattens to code+message, which would destroy
variant discrimination. Door failures map to
`Error::InvariantViolation("executor witness door rejected the session turn")`. **No
oracle-relevant variant is folded**: every refusal this entry owns (GuestTurnRef, stale
route) is raised as a typed `Error` *before* the door is called, and the turn is built
from executor-controlled parts, so a surviving door refusal genuinely is an executor-side
invariant break. Only ONE new error variant was added, per the append-only claim.

**D4 — `Session` + `RouteTarget::Overlay` gate arm.** Blueprint: "uses ONE-1728's
session-armed decision append." **That surface is not on the merge base.**
`SessionStoreView` has no `append_gate_decision_in_txn` (only `Store` does, `store.rs:2435`),
and `gate.rs::check_claim_policy_for_write` takes `&Store`, not `&impl ManifestDbs`. Both
`store.rs` (unclaimed, NEVER) and `gate.rs` (zero-diff pinned) are out of packet, so an
overlay gate path cannot be built without breaking a hard rule.
*Shipped per the blueprint's own hedge* ("structurally present but currently unreachable
… assert that ordering structurally"): the Overlay arm exists and is typed, raising
`Error::OffRecordTalkOnly` — refusal, not an ephemeral decision, and not a dormant
half-path for ONE-1731 to inherit. If a later ticket wants real overlay decisions it must
first generalize `gate.rs`/`store.rs`, which is a visible change in an owning lane.

**D5 — the room's shell is allocated at `enter`.** `overlay_shell` changed from
`Option<EntityId>` (lazy `get_or_insert_with`) to a plain `EntityId` set in
`OffRecordSessionRegistry::enter`.
*Derivation:* R-20260807-02 rider 1 — "created at session entry … one shell per live
session enforced THERE by the session machinery". Lazy allocation made that a property of
whoever touched it first. Dropping the `Option` deletes a state that can no longer occur.

**D6 — `OffRecordSession::search_text` returns `Vec<ScoredEntity>`.** Was
`Vec<EntityId>`. *Derivation:* the blueprint pins
`ExecutorStorage::search_text -> Result<Vec<ScoredEntity>>` and
`SelfMemorySearchResult.results` is `Vec<ScoredEntity>`; projecting scores away in 1728's
accessor would have forced a second scoring body onto the session path. 1728 marked this
fn `#[allow(dead_code)] … "the host-facing caller is ONE-1729's session retrieval
binding"` — this is that arming; the `dead_code` allow is now gone. The oracle's own
`search_text` seam projects ids, so no visibility assertion changed.

**D7 — one container accessor, not two.** `ExecutorStorage::session_container_id` was
collapsed into `HostSelfDispatcher::session_container_id` (the pinned shape). It carries
`#[allow(dead_code)]` with an accurate reason: its consumer is the oracle's identity
assertion; a production executor turn takes the container from the binding it already
holds rather than through a second lookup.

## Oracle: assertions strengthened, never weakened

All three P4b stubs unignored and passing. Two harness adaptations, both declared:

- **`executor_artifacts_and_speak_turns_live_in_overlay_only`** — `bind_actor()` now runs
  *before* `census_before`. The witness door proves its actor exists in base before it
  writes (both arms), so that one row is baseline, not executor residue. This is the
  file's own documented pattern (seam doc lines 63–69; `session_gate_decisions_never_persist_in_base`
  already does it). The `(1,1,1)` positive census and the zero-base-delta census are
  unchanged; **added** assertions that the shell is a single session-owned 32-hex
  `EntityId`, equal to the dispatcher's container, and never the `session_ref` string.
- **`durable_memory_write_verbs_stay_policy_rejected_off_record`** — now iterates **four**
  verbs (the done-means adds `MemoryWriteFixture`) instead of three, and brackets each
  public dispatch call with base **and** overlay census deltas.

New plain `#[test]` functions (all within the blueprint's enumerated allowance):

- `durable_memory_write_verbs_take_the_ordinary_path_after_flip` — post-flip, none of the
  four meets the effect policy; the on-record fixture write lands in base, asserted **by
  claim identity** rather than by count (the gated verbs also move rows, and a count would
  let one stand in for the row under test).
- `executor_utterances_share_one_session_shell` — Speak/Think/Express through the same
  witness entry, one shell across all three plus a second bound run, zero base delta.
- `binding_a_dead_session_refuses_distinctly` — `SessionNotFound` vs `SessionClosing` stay
  variant-discriminable; a handle bound before close refuses rather than writing into a
  dead room; zero census delta.
- `executor_refuses_mismatched_storage_dispatcher_binding` — all three directions
  (canonical+session, session+canonical, two vaults whose refs compare equal) refuse at run
  entry with `InvalidConfig("executor storage/dispatcher binding mismatch")`; the stub
  backend and runtime **panic if reached**, so "before any read or write" is enforced, not
  assumed.
- `run_entry_route_refuses_an_apply_across_a_mid_run_flip` — the run-entry route refuses
  its own apply after a flip, with the typed stale-route family; the pre-flip room is
  intact and base is untouched (no split state).

`SeamError` gained `SessionNotFound` and `SessionClosing`; `map_session_error` and the new
`map_executor_error` map production variants **one-to-one** and panic on anything
unmapped — no message matching, no `is_err()`, no many-to-one fold. Post-flip gate
verdicts are reported as the production `ErrorKind` rather than folded into a `SeamError`,
so a write-gate answer can never be misread as an off-record refusal.

## Notes for the screen

- **Route capture count.** The dispatcher and the executor each capture a route at their
  own construction (both strictly before `load_or_create_record`, neither per-dispatch).
  The run-entry binding check ties them to the same session and the same store, so they
  are minted from one mode epoch and `revalidate` refuses both identically after a flip.
- **Config-marker binding** folds a length-prefixed `storage:canonical` /
  `storage:off-record-session ‖ ref` tag into `executor_config_hash`, so a session literally
  named `canonical` cannot collide with a canonical run. A canonical-written record is
  visible to a session run's composed view, so a mismatched resume refuses before any write.
- **`bind` is a pure lookup**: `vet_off_record_session_ref` → live entry → reject
  closing/gone. No overlay, no re-entry, no mode mutation, no base row.
- **No vault getter.** `OffRecordSession::base_write_vault` is module-private; a `&Vault`
  never leaves `lifecycle.rs`, and it is produced only under a revalidated `Base` route.
  `ExecutorStorage` is match-only delegation; `store_identity` projects a bare pointer.

## SIMPLIFY pass (K3, tip of impl leg)

Deletion-biased review of the full packet diff. The impl leg shipped tight; exactly ONE
edit was warranted:

- **Deleted the stale `#[allow(dead_code)]` on `OffRecordSession::vault_meta_get`**
  (`off_record/lifecycle.rs`). ONE-1728 minted the allow when the accessor had no caller;
  this lane's `SessionBinding::{get_replay_record, get_raw_output}` now call it
  (`code_run.rs:1408`, `code_run.rs:1457`), so the allow and its "ONE-1730 inherits"
  reason were vestigial. Attribute-only deletion, zero codegen delta. The sibling allow on
  `vault_meta_put` stays — it still has no caller until ONE-1730.

Considered and deliberately left: the ~12-line generation-compare overlap between
`Vault::put_code_run_replay_record_if_generation` and
`SessionBinding::put_replay_record_if_generation` is JUSTIFIED duplication — the canonical
body is atomic inside one write txn, the session body is atomic through the route/overlay
machinery, and a shared closure-parameterized helper would obscure two distinct atomicity
domains while touching the landed public compare protocol. The four match-only delegation
bodies and the closed `ExecutorStorage` method set are blueprint-pinned shape, not
duplication. Oracle/tests untouched (assertions/fixtures off-limits; the diff carries no
test-side cruft worth a rule-bending edit).

Gates after the pass: `cargo fmt -p oneiron --check` clean ·
`cargo clippy -p oneiron --all-features --all-targets` clean, zero warnings ·
`cargo test -p oneiron --all-features branch_store_oracle` 27 passed / 0 failed / 8 ignored
(identical to the impl-leg baseline; full-suite green stands from the impl tip — the delta
is attribute-only). Zero-diff pins reconfirmed: `of060_fitness.rs`, `gate.rs`,
`code_run/tests.rs`, `Cargo.toml`, `Cargo.lock` untouched by this pass.

## VERDICT-FIX pass (Opus, tip after simplify)

Sol finder (max) returned 5 items; K3 verdict adjudicated 3 REAL + 2 rejected-with-derivation
(banked as non-gating P3 notes, NOT relitigated here). All three REAL items are fixed at
their chokepoint, and each fix is MUTATION-VERIFIED: reverting it turns its oracle test red.

### REAL 1 — `fresh-search-route-after-run-entry` (P1, `off_record/lifecycle.rs`)

`OffRecordSession::search_text` opened with `let route = self.write_route()?` — a FRESH mint
per call. `ExecutorStorage::search_text` delegated to it, so session `MemorySearch` was the
one apply on the executor path that ignored the run-entry route: a mid-run flip did not abort
a run whose next verb was a search, and the retrieval-run telemetry (a durable write) landed
in BASE for a run whose replay record sat in an evaporating overlay. Verbatim the pattern
done-means 210 forbids.

Fix: the scoring + registration body became `search_text_routed(&SessionWriteRoute, ..)`,
revalidating the CALLER's route on entry; `SessionBinding::search_text` passes the run's
stored route, exactly like its replay and raw-output siblings. `search_text` survives as the
thin one-shot sibling (`write_route()` + delegate) for callers with no run to bind to — it
has a test-target caller outside this packet (`facade/tests.rs`), so it is kept with an
honest one-shot `#[allow(dead_code)]` rather than deleted across a packet boundary.

Oracle: `run_entry_route_refuses_a_search_across_a_mid_run_flip` — capture at run entry, flip,
search; expects `SeamError::LeaseClosed` (the typed stale-route family) plus a byte-identical
28-database base census. Mutation check: restoring the fresh-mint delegation panics with
"a route captured before the flip must not register telemetry after it".

### REAL 2 — `witness-bypasses-binding-check` (P1, `engine_executor.rs`)

`EngineNativeExecutor::witness_turn` is a public, WRITE-CAPABLE entry point this lane added,
but `verify_storage_dispatcher_binding` ran only in `run()`. A mismatched pair that never
called `run` could land a turn through one binding's session carrying the other binding's
actor — a flat violation of the ratified "refuse before any read or write, zero delta" law
(blueprint 191, done-means 206), reachable through the pub API.

Fix: `witness_turn` now calls `verify_storage_dispatcher_binding()` as its first statement,
ahead of the canonical early-return, so both mismatch directions refuse identically at both
entry points. One line; idempotent; no new surface.

Oracle: `executor_witness_turn_refuses_a_mismatched_binding` — session storage + canonical
dispatcher, witness before any run; expects `Error::InvalidConfig("executor storage/dispatcher
binding mismatch")` with room census and base census unchanged. Mutation check: removing the
call lets the turn reach the facade door (it then fails only incidentally, on the foreign
actor's base residency) — the bypass the finder described.

### REAL 3 — `non-atomic-session-replay-cas` (P2, `code_run.rs` + `off_record/lifecycle.rs`)

`SessionBinding::put_replay_record_if_generation` compared through a composed-view snapshot
(`vault_meta_get`, its own read txn) and wrote through a LATER routed write txn
(`vault_meta_put_routed`). Two session-bound executors holding the same expected generation
could both pass the compare and both commit — a lost replay update with each writer told it
won. The canonical sibling (`Vault::put_code_run_replay_record_if_generation`) does the whole
compare+put in ONE write txn, so this broke done-means 204 ("atomic on both routes") and the
method's own doc claim. The SIMPLIFY pass's note that "the session body is atomic through the
route/overlay machinery" was wrong: the route protects the mode epoch, not the row.

Fix: `lifecycle.rs` gains `vault_meta_compare_and_put_routed(route, key, value, accepts_current)`
— the caller's comparison runs against the composed value read INSIDE the transaction that
replaces it, on both route arms (Overlay: after the segment installs, base-writer-then-permit
order preserved; Base: inside the same `with_write_txn`). The comparison stays composed, not
base-only, so a post-flip run still sees an earlier off-record run's overlay row exactly as the
unconditional read does — atomicity is the only behavioural delta. `code_run.rs` keeps the
`CodeRunReplayGeneration` protocol and its existing `Error::ConcurrentWrite` refusal, now
raised from inside the transaction; the replay-record decode never entered `lifecycle.rs`.

Oracle: `session_replay_compare_and_set_refuses_a_row_that_moved` — the interleave is forced by
LMDB's single base writer, not by luck: a competitor holds the writer, releases the bound run
through a barrier, mutates the row, and commits; the run cannot reach its transaction until
after that commit, so a compare taken outside the transaction is guaranteed stale.
Expects `ErrorKind::ConcurrentWrite`. Mutation check: restoring the snapshot-then-put form
returns `Ok` — the lost update, observed directly.

### Rejected items (per verdict, not relitigated)

- finder 1 `off-record-base-commit-race` — indicts the merged, content-ratified ONE-1728 flip
  mechanism (boundary-level guarantee; closing the window needs the state lock held across the
  base commit, the deadlock lifecycle.rs:694-697 documents refusing to build). Banked P3.
- finder 3 `split-executor-dispatcher-route` — both routes ARE captured at run entry and stored;
  at most one is live and it is mode-consistent. A route-equality assertion in
  `verify_storage_dispatcher_binding` would be a new requirement. Banked P3 hardening note.

### Gates

`cargo fmt -p oneiron --check` clean · `cargo clippy -p oneiron --all-features --all-targets`
clean, zero warnings · `cargo check -p oneiron --all-features --all-targets` clean.
Zero-diff pins reconfirmed: `of060_fitness.rs`, `gate.rs`, `code_run/tests.rs`, `Cargo.toml`,
`Cargo.lock` untouched. Diff is 4 files, all in packet: `off_record/lifecycle.rs`,
`code_run.rs`, `engine_executor.rs`, `branch_store_oracle.rs` (three new plain `#[test]` fns
plus their seam helpers; no stub ignore touched, no assertion weakened).

### BLOCKER — full suite could not be re-run on this box (machine-level, not lane-level)

The three new tests and the whole `branch_store_oracle` module were green (serial run) during
the fix pass, and every mutation check ran to completion. Partway through the pass EVERY
`Vault::open` on this machine began failing with
`Storage(Io(Os { code: 28, kind: StorageFull, message: "No space left on device" }))` —
including pre-existing tests untouched by this lane (`vault::tests`: 2 passed / 21 failed) and
including single-threaded runs. It is NOT disk: 290 GB free on the internal volume, 3.5 TiB on
`/Volumes/Cinema`, a 4 GiB real-write probe and an 8 GiB sparse-truncate probe both succeed,
and pointing `TMPDIR` at either volume makes no difference.

Root cause identified: the system's POSIX NAMED SEMAPHORE table is exhausted. LMDB on macOS
(`MDB_USE_POSIX_SEM`) calls `sem_open` for every environment it opens, and `sem_open` from a
FRESH process now fails immediately with `errno 28 (ENOSPC)` — verified directly with a
5-iteration ctypes probe that got zero successes. A per-process limit would have let a fresh
process through, so the exhaustion is system-wide: leaked names from killed test processes
across the concurrently running lanes (load average peaked at 58 during the pass). No hung
`oneiron` test binaries remain to reap, and macOS exposes no CLI to enumerate or unlink
orphaned POSIX semaphores — this clears on reboot, or when whatever still holds them exits.

Consequence: `cargo test -p oneiron --all-features` (final gate, incl. the of060 zero-diff
pin) MUST be re-run by the orchestrator on a healthy box before this lane is treated as
verified. The commit is landed per land-and-hold so nothing is lost. Every sibling lane on
this machine is under the same condition — this is a wave-level environment call, not a
ONE-1729 defect.
