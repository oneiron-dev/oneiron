# WORKLOG — ONE-1570 Arm B settle (retrieval-telemetry registration door)

branch · `ONE-1570-ARMB` off `origin/main` 4f5360daa (post-fence tree; 1731 #640 merged)
worktree · `/Volumes/Cinema/w5-lt/retrieval-api`
role · Opus IMPL · serialized behind RETRIEVAL-API (free)
source contract · `/Users/olety/.claude-wave5/blueprints/STALE/ONE-1570.md` §"Resolved retrieval-telemetry Arm B"

---

## ARM_B_HOST

```
ARM_B_HOST: /Users/olety/Desktop/code/oneiron/crates/oneiron/src/facade.rs
ARM_B_ENTRY: MemoryFacade::recall_in_session  (named public production entry point; sibling of the
             existing public MemoryFacade::witness_into_session, which is already the crate's only
             public production surface taking an explicit &OffRecordSession)
```

### Census record (first action, run BEFORE any edit)

Three candidate hosts were censused exactly as the contract names them.

**1. `oneiron-server` context-pack API handlers — REJECTED (no session surface).**
`crates/oneiron-server/src/api/context_pack.rs` + `api.rs` + `mcp.rs` carry zero off-record
concepts. The only `session_ref`-shaped token in the whole crate is
`context_pack.rs:342-344 voice_session_ref`, which the crate's own test at
`api/tests.rs:8597` documents as "the ILD-3 roster seam is accepted but inert" — a voice-roster
string, not an off-record session ref, never reaching `Vault::off_record_session`. Selecting this
host would require inventing an HTTP off-record session lifecycle (enter/flip/close over the wire)
across `api.rs`, the routers and `openapi.rs`. That is a new feature, not a settle, and lands far
outside the granted claims.

**2. `oneiron-napi` `lib.rs` session surfaces — REJECTED (no session surface).**
`rg 'off_record|OffRecord|session_ref' crates/oneiron-napi/src/` returns ZERO hits. Its
`lib.rs:620 context_pack` / `lib.rs:659 context_pack_scoped` build on `self.vault.context_pack()`
with no session concept at all. Same objection as (1), plus an N-API surface change.

**3. `facade.rs` — SELECTED.**
It is the only censused host that already owns a public production entry point taking an explicit
`&OffRecordSession`: `MemoryFacade::witness_into_session` (`facade.rs:1814`). It is simultaneously
the crate's public retrieval door: `MemoryFacade::recall` (`facade.rs:2842`) is the named public
production entry point that drives `vault.context_pack()` — precisely the telemetry seam the
settle contract governs. The settle therefore adds ONE sibling in an existing established pattern
(`*_into_session`) rather than inventing a host.

The `#[cfg(feature = ...)]` question does not arise: no arm of this work is sync-gated.

### Packet consequence

`crates/oneiron/src/facade.rs` enters the packet as the census-named host file, per the relay's
"(census-named host file(s) ONLY after the census lands them in the worklog)" and the artifact's
granted-claim row "the production host that supplies the off-record `session_ref`". No other
facade region is touched; the footprint is one added method plus its imports.

---

## POST-P6 SUBSTRATE RE-GROUNDING (deviation from the fence-era contract's literal wording)

The contract was authored against the fence-era tree. ONE-1731 (#640) deleted
`note_off_record_context_receipt` and the `offrecord_receipt:v0:` marker family. Re-grounded, the
settle semantics are preserved verbatim but ride the surviving substrate:

| Contract wording (fence era) | Post-P6 substrate (this tree) |
|---|---|
| register through `note_off_record_context_receipt` | stage the retrieval-run row into the session overlay `VaultMeta` keyspace via `SessionStoreView::record_retrieval_run_in_txn` |
| the session-local close set | the overlay rows under `store::RETRIEVAL_RUN_KEY_PREFIX` (`retr_run:v0:`), which `close_off_record_session`'s PRE-CLOSE CENSUS counts as `context_receipts_deleted` (`lifecycle.rs:1380-1390`) |
| close removes the run + `offrecord_receipt:v0:` marker | close drops the overlay; the rows evaporate with the transcript |
| exactly ONE additive optional session-**ref** channel | `PipelineBuilder::in_session(&SessionStoreView)` (`pipeline.rs:595`) — strictly stronger than a bare ref: it cannot be forged from ambient state, the caller must hold a live session handle |

The relay's framing — "session-local, close-consumed, never a durable `vault_meta` marker" — holds
exactly under this mapping. The overlay VaultMeta keyspace is session-local and evaporates at
close; nothing durable is written to base.

Note the module docs (`off_record/lifecycle.rs:47-56`) are precise on this and distinguish TWO
substrates: retrieval-run context receipts ride the **overlay VaultMeta keyspace**, while
emit-adjacent dispatch receipts ride `SessionLocalReceiptLog` (`Vault::off_record_receipt_log`).
The relay brief compressed these two into one. Arm B is the RETRIEVAL half, so it rides the overlay
keyspace, not the emit receipt log. Recorded as a deviation for the board.

---

## STATE OF THE TREE AT DISPATCH (what P6 already landed vs. the Arm B gap)

Already present post-P6 (must NOT be rebuilt):
- `store.rs:1412 SessionStoreView` telemetry seam — `record_retrieval_run_in_txn`,
  `record_context_pack_provisional_retrieval_run_in_txn`,
  `finalize_context_pack_retrieval_run_in_txn`, `delete_retrieval_run_in_txn`,
  `retrieval_runs_in_txn`. Whole-cloth, `#[allow(dead_code)]` pending its callers.
- `pipeline.rs:548 session_view` field + `pipeline.rs:595 in_session()` builder
  (`#[allow(dead_code)]` — zero production callers).
- `pipeline.rs:1944-1972` registration site already routes on `self.session_view`.
- `off_record/lifecycle.rs:656 search_text_routed` already registers the BM25 path into the room.
- `close_off_record_session` already censuses the overlay run rows.

The Arm B gap (this lane):
1. **No production caller reaches `in_session`.** The context-pack/pipeline door is unreachable
   from any host, so a production off-record retrieval still lands its run in BASE.
2. **Context-pack finalize is base-only — the exactly-once break.** `ContextPackRun.store` and
   `UnfinalizedContextPack.store` are `&Store`; `finalize_context_pack_telemetry` and
   `discard_failed_context_pack_telemetry` (`context_pack.rs:1376`, `:1404`) call
   `store.finalize_context_pack_retrieval_run` / `store.delete_retrieval_run` on BASE. A
   session-routed provisional run stages into the OVERLAY, so finalize would target a base row that
   does not exist — the provisional overlay row would survive un-finalized while finalize errors,
   violating "registers the final surviving run EXACTLY ONCE".
3. **`pipeline.rs` log-and-continue on the session arm.** `pipeline.rs:1971-1979` swallows a failed
   run write with `tracing::warn!` and returns the retrieval as successful. On the session arm that
   is exactly the forbidden "log-and-continue": a successful off-record retrieval would return with
   its run absent from the close set.

---

## WHAT LANDED

1. **`off_record/lifecycle.rs` — the registration door.** `OffRecordSession::retrieval_telemetry`
   (crate-private) mints `SessionRetrievalTelemetry` from a CAPTURED route: `Some` while the room
   is off record, `None` once on record. It carries the composed `view` (the provisional
   registration stages through it) AND the `overlay` (later writes mint their own view — see
   deviation D3). `off_record/mod.rs` re-exports the type crate-privately; no public surface gains
   a session channel.
2. **`context_pack.rs` — the exactly-once fix.** `ContextPackRun`/`UnfinalizedContextPack` no
   longer hold a bare `&Store`; they hold `ContextPackTelemetry`, captured ONCE at run entry.
   `finalize`/`discard` dispatch on it, so a run's provisional registration and its finalize
   always reach the same row. `ContextPackBuilder::in_session` is the one additive optional
   channel and forwards to `PipelineBuilder::in_session`.
3. **`pipeline.rs`** — no behavior change; the stale `#[allow(dead_code)]` on `in_session` is gone
   now that a production caller exists, and the doc names it.
4. **`facade.rs` (ARM_B_HOST)** — `recall` and the new public `recall_in_session` both delegate to
   one private `recall_routed`. `session: None` on the canonical door keeps every existing path
   byte-identical. In a room it routes all THREE retrievals the call issues: the context pack, the
   facet-arm pipeline, and the PPR seed search (which was a second, separately-registering
   retrieval — left on the base door it would have published a durable row naming what the room
   searched for).

## PROGRESS LOG

- [x] Read the ratified Arm B settle contract (artifact lines 175-200 + granted claims + settle bar).
- [x] Host census over `oneiron-server`, `oneiron-napi`, `facade.rs`; `ARM_B_HOST` recorded above,
      in the artifact's `ARM_B_HOST:` field, and in `STALE/CLAIMS.md` — all three BEFORE any edit.
- [x] Implementation (the four items above).
- [x] Acceptance regression + negative controls, both MUTATION-VERIFIED (below).
- [x] Final gate: `cargo fmt --check` clean · `cargo clippy -p oneiron --all-targets --all-features
      -- -D warnings` clean · `cargo test -p oneiron --all-features` = **4501 passed, 0 failed**.
      No server/napi crate gate triggered — the census landed the host inside `oneiron`.
- [x] Packet verified: `git diff --name-only origin/main...HEAD` = exactly the seven claimed files.
      No `Cargo.toml`, no `Cargo.lock`. No new marker/key family (`offrecord_receipt` and
      `note_off_record_context_receipt` remain at ZERO occurrences).

## MUTATION VERIFICATION (the oracle is proven, not assumed)

The first version of the acceptance test PASSED against broken code — the room's composed reader
saw the PPR seed-search run and that alone satisfied a set-level assertion while the context-pack
provisional silently never finalized. The test was tightened to name the CONTEXT-PACK run
specifically, then re-verified against two induced mutations:

| Mutation | Result |
|---|---|
| finalize target forced to `Base` (the shipped defect) | **RED** — `left: 0, right: 1` |
| finalize routed to the session but through the pre-built (stale-snapshot) view | **RED** — `left: 0` |
| fix restored | **GREEN** |

`retrieval_runs_in_txn` skips provisional rows, so "0 context-pack runs" is exactly the signature
of a provisional that never finalized. That is what makes this a real oracle rather than a
green-by-construction test.

## CONTRACT COMPLIANCE — law by law

| Settle-contract law | How it holds here |
|---|---|
| exactly ONE additive optional session-ref channel; constructors/results source-compatible | `PipelineBuilder::in_session` (pre-existing) + `ContextPackBuilder::in_session` forwarding to it — one channel, threaded. Every public signature is unchanged; `UnfinalizedContextPack`'s changed field is private. |
| never infer ambient live-session state | The session is an explicit argument on a distinct public door. `recall` consults nothing. |
| ordinary retrievals must not auto-register merely because a session is live | Control A in `on_record_and_ordinary_recalls_never_enter_the_rooms_receipt_set`. |
| production off-record retrieval carries the live session ref through the telemetry seam and registers each successfully-written run | `recall_in_session` → `retrieval_telemetry` → `in_session` → overlay staging, for all three retrievals. |
| register ONLY after the durable run write succeeds, ONLY for a live off-record session | Post-P6 the run write and the close-set membership are the SAME staged overlay row (see D2). Route `Base` ⇒ no registration. |
| no successful off-record retrieval returns with its durable run absent from the close set; never log-and-continue | See D2 — structurally impossible post-P6 rather than guarded. |
| context-pack provisional/final registers the final surviving run EXACTLY ONCE | The captured `ContextPackTelemetry`. This was genuinely BROKEN before this lane; mutation-verified. |
| close removes the registered rows | Asserted via `context_receipts_deleted` in the acceptance test. |
| on-record / commissioned ordinary retrievals never enter the off-record receipt log | Controls A and B; `context_receipts_deleted == 0`. |
| acceptance drives a NAMED PUBLIC production entry point, zero test-side `session_ref` plumbing, zero manual registration calls | `MemoryFacade::recall_in_session`. The test holds a public session handle and calls no registration API. |

## DEVIATIONS + PACKET_AMEND CANDIDATES (nothing silently absorbed)

**D1 — PACKET_AMEND (facade.rs serialization).** `facade.rs` enters the packet as the census-named
host, which the contract anticipates. But ONE-1377 ("facade author_take + serialize NOTE group")
also claims `facade.rs`. Arm B's footprint is one added public method, one private shared body,
and the `recall` delegation — the recall region only, disjoint from the NOTE/author_take region.
Flagged for the board; whichever lands second rebases. Recorded in `STALE/CLAIMS.md`.

**D2 — the contract's fence-era wording vs. the post-P6 substrate (re-grounding, not a weakening).**
The contract says registration failure after the run write must "remove the just-written run or
fail without residue; NEVER log-and-continue". That clause governs the FENCE-ERA two-step: write a
durable base run, then register it into a separate session log — where a failure between the two
strands a durable run outside the close set. Post-P6 there is no two-step: the run write and the
close-set membership are the SAME overlay row, staged in one segment that applies only after the
base commit returns. A failed registration leaves NO row anywhere, so the leak the law exists to
prevent is unrepresentable, and the caller honestly reports `run_id: None`.

I therefore did NOT convert the telemetry write into a hard failure of the retrieval. Doing so
would reverse a decision P6 landed explicitly — `pipeline/tests.rs`
`a_session_pipeline_run_stages_its_telemetry_row_in_the_room` pins "a telemetry write must never
sink a retrieval" as by-design. Under the ratified-reversal rule that needs three independent
groundings; I have one (the contract's fence-era phrasing), and the law's PURPOSE is already
satisfied structurally. **Flagged for adjudication** rather than decided silently — if the board
reads the law as governing telemetry availability rather than residue, the change is a two-line
edit to the session arm of `pipeline.rs:1971`.

**D3 — a real defect found and fixed en route (not in the brief).** A `SessionStoreView` freezes
its overlay snapshot at construction, so the view that STAGES a row cannot READ it back.
`stage_context_pack_retrieval_run_finalize` reads its provisional row before rewriting it, so
routing finalize through the same view the provisional used made finalize a silent no-op that
returned `Ok(())` while leaving the provisional marker standing forever. Hence
`ContextPackTelemetry::Session` carries the OVERLAY and mints a fresh segment-aware view inside
its own write txn — the same discipline `search_text_routed` already uses. Both the stale-view and
base-only variants are mutation-verified RED above.

**D4 — the relay brief's substrate description was imprecise (corrected, see the table up top).**
The brief says retrieval-run context receipts ride `Vault::off_record_receipt_log`. The module docs
at `off_record/lifecycle.rs:47-56` actually name TWO substrates: retrieval-run context receipts
ride the session's overlay `VaultMeta` keyspace, while emit-adjacent dispatch receipts ride
`SessionLocalReceiptLog`. Arm B is the retrieval half, so it rides the overlay keyspace. The
relay's binding requirements — session-local, close-consumed, never a durable `vault_meta` marker
— all hold under the correct substrate.

**D5 — scope boundary, NOT closed by this lane (known-hole candidate).** `in_session` routes
TELEMETRY only; retrieval SCORING for the context pack still reads base, which is P6's own ratified
division ("Retrieval SCORING is untouched by this field"). So a recall inside a room does not yet
retrieve the room's own turns. That is ONE-1729's session context-pack scope, not Arm B's — Arm B
is about the RECEIPT. Noted so nobody reads the green acceptance test as proving in-room recall.

**D6 — observed, pre-existing, unchanged.** The PPR seed search now uses
`OffRecordSession::search_text_routed`, which scores over the composed union in BOTH route states
(only its telemetry write routes). That is the landed P6 behavior of that helper and the documented
semantic for a session handle ("session handles read overlay ∪ base"); this lane neither introduced
nor altered it.

**No PACKET_AMEND needed for test placement.** The acceptance regression lives in
`off_record/tests.rs` (in packet) and drives the host's public entry point from there, so
`facade/tests.rs` was not touched.

---

## SIMPLIFY PASS (K3, 2026-08-07, on impl tip 706db73)

Deletion-biased review of the full Arm B diff (lifecycle/mod/pipeline/context_pack/facade +
tests). Verdict: the implementation is already at its minimal shape — no layers, duplication,
defensive branches, or speculative generality warranted removal.

- `SessionRetrievalTelemetry` carries exactly the two handles both consumers use (`view()` for
  the pipeline's provisional staging, `overlay()` for the segment-aware finalize/discard);
  neither accessor is dead.
- `ContextPackTelemetry`'s `Copy` derive is load-bearing (the error path re-uses `telemetry`
  after the closure captures it); the Base/Session arms are both live; the two session-arm
  write blocks were left un-extracted (two uses, extraction = added structure).
- The facade split (`recall` / `recall_in_session` / shared private `recall_routed`) is the
  smallest shape that keeps the two public doors call-compatible.

**One correction applied (doc accuracy, zero structural change):** two doc comments referenced
a nonexistent method `OffRecordSession::retrieval_telemetry_view`; the landed name is
`retrieval_telemetry`. Fixed at `context_pack.rs:415-416` and `pipeline.rs:593`. No test
assertions, fixtures, or public API touched.

**Gates:** `cargo fmt -p oneiron -- --check` OK · `cargo clippy -p oneiron --all-targets
--all-features -- -D warnings` clean · `cargo test -p oneiron --all-features` green
(3984+ suites all ok on the gating run).

**Flake guard:** one full-suite run showed a single red in
`batch::tests::authority_fold_backfills_legacy_missing_first_seen_sidecars_once`
("migrated first-seen must be the local observation (1786095456)") — a pre-existing
wall-clock non-monotonicity race (`unix_seconds_now` read later, then earlier) in a file this
lane's diff never touches (`git diff 4f5360d..HEAD -- batch/` is empty). Passed in isolation
and on the full-suite re-run. Quarantined as base flake, charged to no lane.

---

## VERDICT-FIX (Opus, 2026-08-07, on simplify tip 0d29ea9)

Finder returned 3 items; K3 verdict adjudicated all 3 REAL (`FIX-REQUIRED`, zero banked, zero
rejected). All three are fixed at their chokepoints below, each mutation-verified red-before /
green-after. Diff stays inside the packet (7 files, no `Cargo.toml`/`Cargo.lock`).

### F1 · `stale-session-route` (P1) — the route now reaches BOTH write arms

**Defect.** `retrieval_telemetry` resolved the route ONCE and collapsed `RouteTarget::Base` to
`None`. A `None` is indistinguishable from "no session at all", so a session-bound assembly whose
room was on record took the canonical base door — which holds no route and never revalidates. A
recall admitted `OnRecord` and flipped `OffRecord` mid-assembly therefore published the room's
`result_ids` durably to base. The same collapse left the overlay arm's registration un-revalidated
for the inverse flip.

**Fix (chokepoint = the door itself).** `SessionRetrievalTelemetry` no longer carries a resolved
target and a bare view; it carries `{vault, route: &SessionWriteRoute}` and OWNS all three
telemetry writes for both targets — `register_run` / `finalize_run` / `discard_run`:

- overlay arm → `staged()`: base-writer-then-segment-permit, `route.revalidate()` INSIDE the
  publishing transaction, view built after the install (segment-aware).
- base arm → `published()`: the base telemetry door opens its own txn and refuses to nest, so the
  route cannot ride inside it the way `witness_with_route` puts it. It is checked on BOTH sides
  instead, and a row that landed under a route the room replaced DURING the write is withdrawn
  (`delete_retrieval_run`) — the compensating shape the settle contract already names.

`retrieval_telemetry` now returns `Result<SessionRetrievalTelemetry<'_>>` (never `Option`).
`search_text_routed`'s hand-rolled `match route.target()` block was DELETED and routed through the
same door, which fixes the base arm the verdict named at `lifecycle.rs:733` and removes the
overlay/assembled drift risk. `PipelineBuilder`/`ContextPackBuilder` now thread the door rather
than a view, so K6's embed-enqueue predicate moved from "a session is attached" to
`stages_in_overlay()` — an on-record room's retrieval is an ordinary base one and must still
enqueue.

**Mutation:** base arm bypassed to a direct `record_retrieval_run` →
`a_base_routed_room_retrieval_refuses_a_run_the_room_no_longer_authorizes` FAILS (returns
`Ok(RetrievalWithTelemetry{ run_id: Some(..) })` with the row in the base ledger). Restored → green.

### F2 · `registration-failure-log-and-continue` (P1) — a room's registration failure sinks the retrieval

**Defect.** Two warn-and-continue paths were reachable via `flip_on_record`'s overlay seal:
provisional write failure (`pipeline.rs`) returned `Ok` with no run in the close set; finalize
failure (`context_pack.rs`) warned, its discard failed on the same seal and was warned away, and
the pack returned `Ok` with provisional residue and ZERO final registrations.

**Fix.** Failure policy keys on whether the caller declared the retrieval to be inside a room:

- `pipeline.rs`: `Err(error) if self.session.is_some() => return Err(error)`. Canonical entries
  (no room) keep the best-effort posture verbatim.
- `context_pack.rs`: `finalize_context_pack_telemetry` now returns
  `Result<Option<RetrievalRunId>>`; on a session telemetry it attempts the discard (residue half of
  the same clause) and then RETURNS the error. Base keeps warn-and-`Ok(None)`.
- Session-bound runs propagate on BOTH targets deliberately: on record the room is also the half
  that can refuse for a stale route (F1), and a K10 refusal warned past is the same
  log-and-continue wearing a different hat.
- Seam closed: `run_unfinalized_with_telemetry` now REFUSES a room's assembly.
  `UnfinalizedContextPack::finish_projected_json` is `pub`, returns no `Result` (oneiron-server
  calls it), and therefore has no channel to carry a room's failed finalize — so a room may not
  take the deferred door at all. That makes the `.ok().flatten()` at that one call site provably
  unable to hide a room's failure rather than merely unlikely to.

**Mutation:** both propagation branches and the deferred refusal disabled →
`a_rooms_failed_run_registration_sinks_the_retrieval`,
`a_rooms_context_pack_fails_when_its_finalize_cannot_land`, and
`a_room_may_not_defer_its_context_pack_finalization` all FAIL. Restored → green.

### F3 · `cross-vault-session-binding` (P1) — store identity checked before any read or write

**Defect.** `MemoryFacade<'v>` borrows `&'v Vault`; `recall_in_session` took a lifetime-untied
`&OffRecordSession<'_>`. Safe public code could pair facade(A) with room(B): A's run row and
`result_ids` stage into B's overlay, and B's room seeds drive A's PPR pack.

**Fix.** `recall_routed` compares `session.store_identity()` against
`std::ptr::from_ref(&self.vault.store)` at entry and returns a typed `FacadeError::bad_request` on
mismatch — the same identity seam `engine_executor.rs:451-460` uses for the executor binding, and
placed before the route mint so no read or write happens first.

**Mutation:** the comparison short-circuited → `recall_in_session_refuses_a_room_from_another_vault`
FAILS (returns a populated `MemoryPack`). Restored → green.

### Supersedes one simplify-pass note

The SIMPLIFY section above recorded `SessionRetrievalTelemetry::view()` and `overlay()` as
load-bearing. F1's fix moves registration INTO the door, so both accessors and the door-time
`read_view()` are now deleted — the handle is two references. `ContextPackTelemetry::Session` drops
its `{vault, overlay}` payload for a single door reference, and its two hand-rolled staging blocks
are gone. Net: the fix is deletion-positive in the production files despite adding two guards.

### Tests added

| Test | File | Guards |
|---|---|---|
| `a_base_routed_room_retrieval_refuses_a_run_the_room_no_longer_authorizes` | `off_record/tests.rs` | F1, base direction (flip OFF record under a base-routed run) |
| `a_rooms_failed_run_registration_sinks_the_retrieval` | `off_record/tests.rs` | F1 overlay direction + F2 pipeline half |
| `recall_in_session_refuses_a_room_from_another_vault` | `off_record/tests.rs` | F3 (and asserts B's overlay stays empty) |
| `a_rooms_context_pack_fails_when_its_finalize_cannot_land` | `context_pack/tests.rs` | F2 finalize half (provisional staged, then seal) |
| `a_room_may_not_defer_its_context_pack_finalization` | `context_pack/tests.rs` | F2 deferred-door seam |

Existing Arm B acceptance + control tests unchanged and still green;
`a_session_pipeline_run_stages_its_telemetry_row_in_the_room` retargeted to the door (its doc
dropped the now-false "warn-and-continue degradation" claim), and
`context_pack_telemetry_finalization_failure_returns_no_run_id` gained an explicit assertion that
the BASE arm keeps its best-effort posture.

### Gates

`cargo fmt -p oneiron` OK · `cargo clippy -p oneiron --all-features --all-targets` clean (zero
warnings) · `cargo test -p oneiron --all-features` green — 52 result blocks, 0 FAILED. No
server/napi crate touched, so no extra crate gate is triggered (per the settle contract's gate
clause).

**Flake guard:** one full-suite pass under doubled machine load showed a single red in
`tests/cb_oracle_tasks.rs`; re-run in isolation 5x and in the clean full-suite run — green every
time, and the lane's diff touches nothing that file reads. Charged to no lane.
