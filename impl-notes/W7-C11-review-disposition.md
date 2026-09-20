# W7-C11 review disposition — reviewed head 41c32f86

## Review collection

The all-state, paginated PR head lookup returned `[[]]`. Paginated repository PR
search for `W7-C11` returned zero items (`incomplete_results=false`). The actual
branch is `w7/W7-C11` in `oneiron-dev/oneiron`. Thus no C11 PR exists, and there
are no Qodo, Codex or CodeRabbit issue comments, reviews or inline threads to
paginate or answer. No provider quota error occurred. Do not post to PR933 or
another ticket. The explanation below must accompany C11's eventual publication.

Original Opus/Grok roots, their calendar and pack/conflict/stream subreviews,
unfinished notes/recovery/DAG/ports subreview records, and the earlier `.w7`
audits are preserved. `target/w7-logs/review-fix/internal-ledger.md` gives the
complete deduplicated source index S1–S12; `ports-context.md` records migration
seams and remaining calls found during the edit. No replacement reviewers or
build fanout was launched.

## Dispositions

- **F-GROK-1..7 (S2; step 21): fix.** Claim reads, writes, lifecycle, target checks,
  expression preference and session-scoped visibility now consume the entity,
  edge and short-ID ports. This also removes related uncited direct reads.
  Historical/raw corruption handling, bounded scans, D19/policy checks and
  session overlay composition are retained. The earlier census counted claim/
  as part of the adapter; this repair removes that disputed boundary rather
  than broadening the exemption. Production claim-subtree census is empty.
- **F-GROK-8 (S2/S3; steps 6–9): fix.** Both calendar connectors now commit EVENT
  birth with an Auto/Active projector-recorded imported origin and the required
  source/external ID fields in one transaction. Semantic candidates still cross
  the imported-evidence Gate as Proposed. Feed and connector drift share one
  origin-preserving writer, including native recurrence/calendar fields.
- **F-OPUS-1 (S1): skip as invalid.** NOTE (1–5), calendar engine (6–9), recovery
  (10–12), criticality (15–16), persistent conflicts/ranking (18–20), MESSAGE
  streaming (24) and all 24 implementation-note entries already exist at the
  reviewed commit. The partial diff did not show them. Source/test paths are
  listed in the internal ledger and the existing per-step notes.
- **S4, S6, S7, S8:** retain existing landable findings and evidence for
  criticality/conflict/stream, recovery, DAG, Android and ports. Unfinished
  subreview drafts are preserved as drafts, not promoted to final reviews.
- **F-S5-DRAFT:** skip. The seventh descriptor is the existing opinion/take kind,
  not a missing required kind. The raw NOTE test also refuses at an earlier
  authoring guard; replicated and authored doors still enforce the kind gate.
- **S9 F1/F5:** skip as disproved by current compilation evidence and the existing
  include_forks HTTP assertion. **S9 F2/F3/F4/F6/F7:** skip as nonblocking
  documentation/naming/extra-coverage suggestions; engine guards and required
  acceptance are covered. No correctness change was alleged by these rows.
- **S10 clock residual:** already fixed by 5c00dadf, before this review. **S10
  regeneration-completion caller:** host-projector API by recorded design; these
  port contracts do not promise an autonomous regeneration worker.

## Latest internal review — S13

Source: `tickets/W7-C11/logs/review-opus-2.jsonl`, completed
2026-09-19T22:34:52Z, source c82d8809 with cb39cbb0 notes. No new review root was
created by this repair seat. Its nine allegations are all **skipped as invalid**:

| S13 finding | Existing implementation / reason |
|---|---|
| 1: Missing notes | This committed `impl-notes/W7-C11.md` has all 24 per-step entries. |
| 2: Missing NOTE system | `note.rs`, `note/kinds.rs`, `note/documents.rs`, `note/verbs.rs`, `note/proposals.rs`; authored and replay kind guards already exist. |
| 3: Calendar is DTO-only | `calendar/origin.rs` validates and stages live origins; batch write guard, imported connector fix b3a4678b and 105 passing calendar tests refute it. |
| 4: Missing canonical recovery | `recovery/canonical.rs`, `recovery/document.rs`, `recovery/ladder.rs`, `recovery/quarantine.rs` implement these doors. |
| 5: Missing DAG vault methods | `conversation_dag/writes.rs:263,268` implements append/move; `scopes.rs:174` resolves scope; `migration.rs:129` migrates; `scope_summary/doors.rs:187,279` implements spawn and mint/land. The completed server build and tests call these engine methods. |
| 6: Criticality fields never populated | `pipeline/criticality.rs` and context-pack hydration resolve the policy; `serialize/pack_preparation.rs:292,300` updates count/overflow; `serialize/token_budget.rs` enforces budgets and emits the warning. Existing criticality tests assert the values. |
| 7: Missing conflicts/ranking | `dreamer_consolidation/conflict.rs`, `dreamer_consolidation/tests/persistent_conflicts.rs`, `context_pack/source_ranking.json`. |
| 8: Missing port traits/adapters | `ports/query.rs:11,52` defines EntityStoreRead/EdgeStoreRead; `ports/lmdb_query.rs` and `ports/memory/query.rs` implement the storage readers. Full compilation and conformance tests completed. |
| 9: Missing MESSAGE streaming | `message_stream/mod.rs`, `policy.rs`, `receipts.rs`, `types.rs`, `tests.rs` implement all five verbs and receipts. |

S13-1..4/6..9 duplicate the already-refuted partial-diff inference in F-OPUS-1.
S13-5 adds the DAG assertion, refuted above. No implementation was removed or
replaced to satisfy these false omissions. The S1–S12 source roots and valid
Grok-finding fixes remain intact.

## Validation — actual results, not event status

`impl-notes/W7-C11-review-validation.json` binds the evidence to source c82d8809
and the factory-tested cb39cbb0 notes-only successor. All saved Rust hashes match.
Calendar integration passed 105 tests. The fixed featureless scoped-read suite
passed 20. Both core all-target Clippy lanes (featureless/all-features) exited 0.

The review chain itself ended **101**, not green: its final six-package command
passed 9,154 and failed one scheduling-sensitive deletion fixture, with 21
pre-existing ignores. It could not construct a race within three attempts. That
test file is unchanged by this repair; no production invariant assertion fired.
The failure is retained and no flake fix is claimed.

The already-owned, normal factory tests-after-review then exited **0** at
2026-09-19T22:33:39.731Z on the same source: **9,155 passed, zero failed or filtered,
21 identical pre-existing ignores**. The formerly failing deletion test passed.
This later factory run, not the failed review-chain command or old 9,154 receipt,
is the final six-package evidence. No additional run was launched, no source was
mutated during factory custody, and no factory state or guard was changed.

Final paginated all-state C11 PR lookup again returned `[[]]`. No actual C11
external review surface or posting target exists; no unrelated GitHub post was
made. Provider quota was not an issue. Android NDK/API36.1 and earlier native
proofs remain separately scoped. No full workspace verify.sh or new Android/Node
runtime result is claimed.


## PR #944 bot repair — reviewed head 4993356c

The earlier no-PR lookups above are historical. The actual review target now is
`oneiron-dev/oneiron#944`, branch `w7/W7-C11`, published head
`4993356c3369a565761c1538abb502161a546d66`. This section supersedes only the old
no-posting-target statements, not the retained findings or validation receipts.

Before edits, all current issue comments, PR reviews, inline comments, and
GraphQL review threads were fetched with pagination. Every thread's nested
comment page reported `hasNextPage=false`. Source bodies were read in full;
file inventories and summaries were not treated as defect reviews. The original
Opus/Grok roots and completed subreviews were recovered, including the late
`review-grok-2` ports subreview that was absent from the old summary.

### Current external ledger

Qodo top-level `5746023377` and review `5258245264` duplicate the following
inline findings; each row retains both the numbered finding and inline ID.

| Source | Disposition and reason |
|---|---|
| Q1 / 4055144975 | Fix: non-owner-grade scoped credentials need both matching principal and actor class. Explicit owner/dev authority remains separate from delegated capability. |
| Q2 / 4055144978 | Skip: intentional adopted-DAG boundary. Authorless ChildOf-only writes must refuse atomically; `/records` supplies actor, parent and advance semantics. Existing engine regression pins this refusal. No invented actor or permission bypass. |
| Q3 / 4055144984 | Fix the real calendar-specific bypass: malformed, non-map, trailing, or origin-stripped writes cannot replace an EVENT with a live calendar origin. Generic opaque non-calendar EVENTs remain legal; the suggested global EVENT schema would break that distinct engine use. |
| Q4 / 4055144989 | Fix: replay may precede an origin claim, but cannot contradict a live origin or remove it from the body. The same rule runs at the shared local/replay put door. |
| Q5 / 4055144992 | Fixed in c7881059/5219e468: canonical recovery preserves validated pending NOTE workflows with a history-independent merge basis. All 10 focused canonical recovery tests passed. |
| Q6 / 4055144998 | Fixed in c7881059/5219e468: remove absent sidecars only within admitted scope, retain preflight/divergence checks and outside workflows, and prove repeated canonical equivalence. Focused recovery tests passed. |
| Q7 / 4055144967 | Skip: MessageStreamError is a composite API wrapper for Error and MemoryError, not an Error domain leaf. Actual typed stream refusals already belong to error::RecordError. No new root export or loss of facade admission detail. |
| Q8 / 4055144971 | Skip: upstream Sudachi lint style, not new first-party suppressions. Preserve the audited snapshot except the documented Android portability changes. REVIEW.md makes comment/style findings informational. |
| Q9 / 4055144995 | Fix: bound the entire retained witness template and appended content by one byte budget. A bounded serialization counter avoids allocating a second payload. Final witness-policy validation remains authoritative. |
| Q10 / 4055145001 | Fix: return one identified result per due stream, including both successful durable receipts and refusals. Refused buffers remain active; a later failure cannot hide earlier completions. |
| Q11 / 4055145005 | Skip: the private Memory conformance adapter has no migration marker, append permit or DAG-adoption API. The alleged migrated state is not representable through its supported ports. Production LMDB admission and the adopted-DAG rejection test remain unchanged. |
| Cursor 4055141305, review 5258241187 | Skip the stated reopen defect: Store construction restores ID_FLOOR before publishing StoreCore. First handoff's ulid is already above the persisted floor; the later txn call persists the new allocation. |
| Cursor 4055141315, review 5258241187 | Skip: pinned NDK27.2.12479018 on ARM macOS uses darwin-x86_64 host tools. Retained native compilation used that exact directory successfully. Duplicates the completed internal Android subreview. |

Service/non-finding comments are retained too: owner request `5745993580`;
CodeRabbit `5745993884` and `5745995645` (542-file limit, unavailable, not pending);
Greptile `5745993938` (automatic review disabled); Cursor summary `5745994484`;
Qodo busy marker `5745994303` and descriptive summary `5746002512` (superseded by
its complete review). Codex `5745994125` reported running at the initial collection checkpoint.
The same job later completed with review `5258308609` and eight findings, all
recorded below. No replacement request or clean no-findings verdict is claimed.

### Internal sources retained and reassessed

- S1 / F-OPUS-1 and S13-1..9: invalid omission claims based on a partial diff.
  The per-feature source citations above remain correct; every named feature
  and all 24 implementation-note entries exist in the committed tree.
- S2 / F-GROK-1..7: already fixed by `7d430f6f` (claim callers use ports).
- S2/S3 / F-GROK-8: already fixed by `b3a4678b` (atomic imported origin and drift).
- S4/S6/S7/S8: preserved subreview conclusions; no additional blocking finding.
- S5 draft: seventh `opinion/take` descriptor is intentional data; the raw NOTE
  guard rejecting before the kind guard does not admit an unknown kind.
- S9 / C11-OO-01 / F1: invalid glob visibility/compile allegation; F5 already fixed
  by `01ddd11f`/`e4634cdf`; F2/F3/F4 are nonblocking docs/naming; F6 asks for extra
  negative-path tests without a broken guard; F7 permits the behavioral pin.
- S10 / C11-OO-02: stream clock sites already fixed by `5c00dadf`; regeneration
  completion is a host-projector port, not a promised autonomous worker.
- S11 is the per-step evidence index. S12 is the historical pre-publication
  no-PR lookup, superseded by this PR's actual surfaces.
- S14 = `review-grok-2.jsonl` and its eight completed subreviews. Notes, calendar,
  recovery, DAG, pack/conflict, Android and streaming reported no additional
  defect. The ports child `sub-79f7032a`, step23, did report a real remaining
  engine-owned mint: `open_interview` persisted a detached wall-clock artifact
  ID. Fix: supply an ID from `vault.new_entity_id` through a narrow constructor;
  keep the detached public proposal API independent of a vault. Strengthen its
  existing end-to-end test with the injected deterministic ID source.
- C11-FR-01/02: earlier secret temporary-path and benchmark platform fixtures are
  fixed by `415632c6`/`da7c04c5`. C11-OO-03/04/05/06 are closed/superseded stored-
  read, runtime, Android and snapshot reports. Original roots are not discarded.
- C11-HR-01: authorized host-routing remedy, not a source defect; C11-HR-02:
  Linux NAPI dev-only dynamic symbols fixed by `cf9a9a46`.
- C11-CG-01/02: offline Sudachi resolution and parity-fixture clock drift fixed by
  `c71d87f8`/`d583201f`; existing focused and full evidence retained.

### Validation boundary

The latest pre-repair mandatory factory run actually completed: 9,155 passed,
zero failed/filtered, 21 pre-existing ignored across the six touched packages.
The log was re-counted, all saved source hashes matched, and the diff from tested
`cb39cbb0` to published `4993356c` contains notes only. This is valid baseline
and unchanged-crate evidence, NOT a pass for the new Rust changes above. The
prior review-chain deletion-race failure remains recorded separately.

Fresh changed-source test and lint results will be appended only after the
commands finish. The installed Cargo dispatcher, normal ticket/host guards,
action-scoped `W7_CARGO_EXCLUDE_MACBOOK=1`, two compiler jobs and four runtime
threads remain in use. No factory state, host guard or launcher was changed.


### Codex completed review 5258308609 (published head 4993356c)

Collected all REST pages and 21 GraphQL threads, including full nested comments.
The existing Codex job completed at 2026-09-19T23:23:41Z; it was not restarted.
All eight findings were read and assessed before this follow-up edit round:

| Inline ID | Distinct finding / assessment |
|---|---|
| 4055199497 | Valid refinement of Q4: first-arriving bodies may defer the claim match, but end-of-forward replay must quarantine missing/conflicting origins. Initial put-order tolerance is not permanent validity. |
| 4055199499 | Valid: an already-DAG forest currently passes the visited-count cycle check. Require one trunk root, preserving the legacy unparented-turn chaining behavior. |
| 4055199503 | Valid: unconditional sourceFrontiers decoding at shared body staging incorrectly reserves a field in opaque PERSON/ASSET bodies. The unowned decoder was removed; explicit dependency doors remain. |
| 4055199511 | Duplicate of Q10/4055145001 with the starvation consequence. Already fixed by identified per-stream outcomes in 35bd84ed; the loop processes every due stream, including those after a refusal. |
| 4055199518 | Valid: normal reverse rematerialization lacks document carriers. Repair normal export/replay, including later edits, without bypassing egress or deletion. |
| 4055199529 | Valid: append session membership only reaches vault_meta. Carry validated membership in replicated record state and rebuild the two local indexes. |
| 4055199534 | Valid recovery companion to Q5/Q6: Reject deletes its fork doc but validation requires every receipt fork. The same recovery repair must represent rejected decisions without requiring deleted text. |
| 4055199539 | Valid: per-NOTE text sidecars are not covered by active-store hard purge. Repair local/replay/headerless deletion and prevent stale replay resurrection. |

Qodo's latest edited summary 5746023377 reorders findings and marks the four
skipped Q2/Q7/Q8/Q11 findings dismissed. Ledger Q numbers retain their original
review numbering; inline IDs remain the stable join key. Blank review shells
for replies carry no additional defects. No earlier source finding is removed.


The read-only replay assessment confirmed all four mechanisms. Two proposed
remedies were not adopted: inferring a dependency schema from a coincidental
field shape still violates the opaque-body boundary, so the unowned decoder
was removed; accepting forests with a new orphan-root sidecar would change the
single-root DAG contract, so malformed received forests are refused atomically.
The original review/session roots were preserved throughout; that custody rule
was not a requirement to accept disconnected graph roots.

Thread follow-ups `4055197859`, `4055197868`, `4055197876`, `4055198000` are Qodo's
explicit dismissals of `4055144978`, `4055144967`, `4055144971`, `4055145005`
respectively. They were read, not treated as unexamined duplicate thread IDs.

### Integrated local repair candidate

Local commits `35bd84ed`, `c7881059`, `5219e468`, and `cf30cded` implement the
valid findings above. The latter carries ordinary NOTE sync and erasure, not
a change to canonical recovery semantics. All original roots and prior
validation failures are retained. The 2026-09-20 paginated refresh found 8 issue
comments, 26 review records, 44 inline comments, and 21 complete review threads;
no new defect was added. The removed/superseded Qodo busy and review-summary
comments remain identified by their captured source IDs.

All 21 inline roots now have replies. The NOTE transport/erasure replies name
the initial 17 passing cases and the separate teardown failure explicitly; they
do not claim the follow-up rerun passed. No final summary, push, merge, or close
has been performed at this checkpoint.

| Source root | Posted reply |
|---|---|
| 4055141305 | [4055192717](https://github.com/oneiron-dev/oneiron/pull/944#discussion_r4055192717) |
| 4055141315 | [4055192715](https://github.com/oneiron-dev/oneiron/pull/944#discussion_r4055192715) |
| 4055144967 | [4055192756](https://github.com/oneiron-dev/oneiron/pull/944#discussion_r4055192756) |
| 4055144971 | [4055192713](https://github.com/oneiron-dev/oneiron/pull/944#discussion_r4055192713) |
| 4055144975 | [4055227303](https://github.com/oneiron-dev/oneiron/pull/944#discussion_r4055227303) |
| 4055144978 | [4055192714](https://github.com/oneiron-dev/oneiron/pull/944#discussion_r4055192714) |
| 4055144984 | [4055227315](https://github.com/oneiron-dev/oneiron/pull/944#discussion_r4055227315) |
| 4055144989 | [4055227301](https://github.com/oneiron-dev/oneiron/pull/944#discussion_r4055227301) |
| 4055144992 | [4055290132](https://github.com/oneiron-dev/oneiron/pull/944#discussion_r4055290132) |
| 4055144995 | [4055227305](https://github.com/oneiron-dev/oneiron/pull/944#discussion_r4055227305) |
| 4055144998 | [4055290135](https://github.com/oneiron-dev/oneiron/pull/944#discussion_r4055290135) |
| 4055145001 | [4055227307](https://github.com/oneiron-dev/oneiron/pull/944#discussion_r4055227307) |
| 4055145005 | [4055192718](https://github.com/oneiron-dev/oneiron/pull/944#discussion_r4055192718) |
| 4055199497 | [4055278335](https://github.com/oneiron-dev/oneiron/pull/944#discussion_r4055278335) |
| 4055199499 | [4055278353](https://github.com/oneiron-dev/oneiron/pull/944#discussion_r4055278353) |
| 4055199503 | [4055278333](https://github.com/oneiron-dev/oneiron/pull/944#discussion_r4055278333) |
| 4055199511 | [4055269022](https://github.com/oneiron-dev/oneiron/pull/944#discussion_r4055269022) |
| 4055199518 | [4055358292](https://github.com/oneiron-dev/oneiron/pull/944#discussion_r4055358292) |
| 4055199529 | [4055278336](https://github.com/oneiron-dev/oneiron/pull/944#discussion_r4055278336) |
| 4055199534 | [4055290136](https://github.com/oneiron-dev/oneiron/pull/944#discussion_r4055290136) |
| 4055199539 | [4055345118](https://github.com/oneiron-dev/oneiron/pull/944#discussion_r4055345118) |


## Review closeout validation — source `bf6a174de98339a0439a3f593e2e4dcb5fc0652f`

All corrective checks completed with the installed dispatcher, normal ticket and
host guards, and the owner-approved `W7_CARGO_EXCLUDE_MACBOOK=1`.

| Check | Actual result |
|---|---|
| Normal six-crate `cargo test --no-fail-fast --jobs 2 ... -- --test-threads=4` on `e7af2e41` | Exit 101: 9,172 passed, three failed, 21 ignored |
| Corrected NOTE/booking/prep/OF-060 focused nextest, all features | Exit 0: 24 passed, 7,601 skipped |
| Focused featureless core nextest | Exit 0: 43 passed, 6,574 skipped |
| Core + server Clippy, all targets/all features, `-D warnings` | Exit 0 |
| Core Clippy, all targets/no default features, `-D warnings` | Exit 0 |
| Server-production Clippy, no all-targets/all-features, `-D warnings` | Exit 0 |
| Changed-source rustfmt check | Exit 0: 66 Rust files |
| Code-map check | Exit 0: 2,598 files, 17 artifacts current |

The full run's three failed cases now pass in the focused rerun. The NOTE replay
move is byte-equivalent after module-path rebinding and formatting across all six
files; its runtime laws passed again. The remaining 9,172 successful full-run cases
are reused. No claim is made that the full command was repeated on the final
candidate or that the workspace-wide coordinator gate ran. Existing vendor
warnings were not suppressed or edited.

Exact commands, failures, source hashes, and the move proof are recorded in
`impl-notes/W7-C11-bot-validation.json`. Earlier pending-validation statements in
this file are historical checkpoints, superseded by this section. The initial
local transient-service results are not mislabeled as guarded receipts; the
missing dispatcher settings and correction remain recorded above.

The final paginated feedback refresh (round 9) contains eight issue comments,
30 reviews, 48 inline comments and 21 threads. All outer and nested pages are
complete. Only our two validation replies and their blank review shells were new;
no new finding appeared. All 21 roots have replies. Native sync/deletion follow-ups
are `4055513690` (root `4055199518`) and `4055513679` (root `4055199539`).

No push, merge, close, factory-state rewrite, launcher change, or docs-mirror edit
was performed. Publication remains with the launcher.
