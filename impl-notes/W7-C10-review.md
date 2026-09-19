# W7-C10 review recovery ledger

Base: `34551442f14d261814367335f40247d23bbcac03`.
Saved Grok message `5d8b9de8` and Opus message `cde08f54` were consumed by
factory at 2026-09-19 14:09Z before edits. Complete original lane reports retained at
`/home/lexi/w7-build/tickets/W7-C10/review-recovery/`.

## Own-PR collection before fixes

GitHub REST `pulls?state=all&head=oneiron-dev:w7/W7-C10&per_page=100`,
paginated to exhaustion, returned no PR. `gh pr view` also found no PR.
Thus no own-PR Qodo/Codex/CodeRabbit comments, reviews or inline threads exist yet;
this is not a pending or quota-failed Codex request. PR933 and its consolidation
packet belong to W7-C08 (`0c458e0a...`) and are inapplicable to this branch.
Do not post C10 changes to C08. Preserve this result with the raw API receipts.

## Deduplicated actionable findings

| ID | Sources | Assessment / action |
|---|---|---|
| R01 | Opus B1 | Valid: format vault-contract files. |
| R02 | Opus B2, retrieval lane | Valid: update Python default, vocabulary, docs and wire fixtures; exercise default recall. |
| R03 | Opus B3, board lane | Valid: fix Max temporal sigma; pin all five pipeline stage presets (also Grok 1). |
| R04 | Opus B4, board lane | Valid: settle cut-short fork hash after HyDE retry boundaries; regression test. |
| R05 | Grok 2, Opus retrieval lane | Valid: depth high/xhigh/max observable stage differences and nonempty partial result. |
| R06 | Grok 3, Opus retrieval lane | Valid: facade raw-deadline test cuts expansion and preserves admitted direct hits. |
| R07 | Opus read-modes lane | Valid: retain non-document revisions across habit's derived rewrite; default indexed pack must not fail. |
| R08 | Opus read-modes lane | Valid: explicit text/vector writes cannot silently disappear while a revision is pending. |
| R09 | Opus read-modes lane | Valid: server hydrate must round-trip emitted revision-pinned short refs. |
| R10 | Opus E1, board lane | Valid: withdraw unsupported scaling flag; require defensible evidence before claiming sublinear cost. |

## Nonblocking findings and decisions

- D1: retain observation-only WebSocket rate handling per step 22; correct stale advertising.
- D2: control-key verifier and feedback delivery are explicit host composition APIs, not
  a second authentication scheme silently mounted on vault routes. Review exact contract
  before any new deployment plumbing; correct unsupported Host::secret claim.
- D3: keep per-call manifest read (live-edit acceptance) and per-vault mutex, not a process-global
  mutex. Existing fleet measurements include this cost; no unmeasured optimization claim.
- D4: remove router-construction runtime panic by starting receipt worker on runtime-backed use.
- D5: unconditional Loro is required for featureless exact read/history; correct obsolete rationale.
- D6: retain PPR cache version change to prevent old layout reuse; pre-GA, no migration burden.
  State that current receipts do not demonstrate universal speedup including preparation.
- D7: no threshold restriction added. `residual_survives_codec_and_only_pushes_above_stored_threshold`
  deliberately tests non-default persisted thresholds and lowering them for deeper work.
  Cache state is local-derived, not peer input; forcing SCORE_EPSILON would remove a tested
  residual contract rather than repair a demonstrated production defect.
- D8: residual cardinality remains bounded by visited graph state, not a new arbitrary truncation
  that would break exact resume. Larger cache rows are a stated storage tradeoff.
- D9: fleet floor is an opt-in CI workflow, not a PR gate; state accurately.
- D10: five-level retrieval vocabulary intentionally rejects retired aliases pre-GA.
  MCP LLM effort is a different protocol and remains unchanged.
- D11: merge rehearsal conflicts are integration work, not license to rebase or edit other trees.
  Preserve C15 document fields if updating against main; regenerate maps.

Validation and final dispositions will be appended after implementation.


## Publication and validation handoff — 2026-09-19

After the recovery commits, C10 was published as PR #939 at
`b4e0d63d6df2ca2dbc74b304d9475b75b31702f8`. PR #933 remains unrelated C08 custody.
The repair/disposition explanation is posted at
<https://github.com/oneiron-dev/oneiron/pull/939#issuecomment-5742758448>.

The first complete own-PR refresh collected top-level comments, reviews, inline
comments and GraphQL review threads. At that snapshot there were no reviews or
inline findings. Codex comment `5742741731` reports **Running**, not quota failure;
Qodo comment `5742743884` reports work in progress. CodeRabbit comment `5742741448`
explicitly reports auto-review disabled. These are statuses, not clean reviews.
Greptile is disabled and Bugbot declined this diff; neither was counted as a pass.
The raw paginated receipts are retained with the ticket. Refresh these same
surfaces before any additional bot-driven repair, and record provider failures
explicitly rather than waiting on a failed request.

All recovery changes are committed separately by concern. Current main is merged;
only comment differences in the two secret fixtures needed manual resolution.
Generated code maps were regenerated, C15 document connection state was retained,
and the merge rehearsal returned success. Scoped and full native validation are
queued under the existing C10 target lock and one existing MacBook slot. A pending
job is not passing evidence; terminal results will be appended here.


## Qodo refresh at d5215429 — 2026-09-19 14:49 UTC

Complete REST pages and GraphQL threads were refreshed before further fixes.
Review `5256053552`, summary comment `5742778055`, and all three inline comments
are retained with raw head IDs. The review object cites b4e0d63d; the finding
links and inline objects cite d5215429 (a documentation-only descendant).
All three thread-comment pages and the thread list report no next page.
Codex still reports Running; CodeRabbit still explicitly skips automatic review.
No provider error or clean result was inferred from either status.

- Q1 / inline `4053486714`: valid. Feedback HTTP client rejections must not all
  become ambiguous delivery. Return definite failure for deterministic 4xx;
  preserve ambiguity for network failures, server failures, and 408/409 where
  timeout or duplicate-operation conflict does not prove absence of a side effect.
  Pin the transport outcome's delivery flag with real loopback responses.
- Q2 / inline `4053486709`: not applied. `wire_telemetry` is a deliberate public
  host-observation API, like the other host-composition modules: the host can set
  RC42 thresholds and read typed window receipts/questions from its vault without
  a tenant HTTP endpoint. Repository call sites are not the complete set of users
  of this exported Rust surface. Narrowing the module would remove that supported
  host door, not repair a demonstrated runtime error.
- Q3 / inline `4053486712`: overflow-bucket recommendation not applied. OF-520
  explicitly requires correct per-actor counters/receipts, including the 50k-agent
  acceptance fixture. Aggregation silently loses those counts and changes per-actor
  threshold detection. Keys come from authenticated principal bindings (failed
  authentication uses one fixed bucket), not arbitrary request headers. Memory is
  proportional to the host-authorized identity roster seen in a window. This is a
  stated exact-accounting tradeoff, not a claim of constant memory. A future
  disk-backed exact counter is a separate design; no lossy cap is introduced here.


### First native validation result

MacBook validation at `637ebe1c` reached the scoped compile and returned 101:
`builder_effort.rs` named the sigma constant through the wrong parent module;
the idle publisher supplied one extra boolean to `apply_ops`. Both call sites
are corrected directly. No test pass was inferred from this failed compile.
The full macOS test stage uses the exact seven known benchmark exclusions from
`.github/workflows/ci.yml`; these unchanged platform cases remain Linux coverage,
not passing macOS evidence. All changed benchmark tests still run.

The complete bot surfaces were refreshed again before these corrections. No new
findings appeared. Qodo replies `4053503849` and `4053504033` explicitly confirm
the telemetry decisions as intentional. Codex remains Running, not failed.


## Codex terminal refresh — six findings at b4e0d63d

Codex comment `5742741731` now reports Completed, not quota failure. Complete
comments/reviews/inline threads were collected before new repairs. The six inline
findings are retained with original head `b4e0d63d` and stable IDs:

- C1 `4053512297`: facade items reread live after indexed pack hydration. Carry
  each entity's source revision into typed item construction.
- C2 `4053512305`: a single pack-level pin is applied to unrelated entities.
  Restrict that pin to its own entity; do not approximate another entity's history.
- C3 `4053512315`: filesystem isolation evidence is path-racy. Bind the isolation
  check and vault open to the same directory identity; add a deterministic swap test.
- C4 `4053512327`: missing VAD is scored as maximally unlike. Use neutral VAD.
- C5 `4053512335`: cached duplicate IDs can inflate scores/propagation mass.
  Validate unique score IDs and frontier/residual `(id,hops)` keys at decode.
- C6 `4053512344`: document chat drops a caller's revision pin in hydrated refs.
  Preserve the resolved pin in the hydrated view and both projections.

The queued r3 validator was stopped before admission so these repairs are in the
next tested snapshot. No active compiler was interrupted; no test pass is claimed.


C3 uses a single descriptor, not adjacent pathname checks: managed open uses
`Vault::open_owned`; the writer lease exposes its borrowed pinned directory for
both fscrypt ioctl and UID/mode fstat. Linux LMDB open uses that same lease fd.
A final lease/path check rejects a renamed root, even for a canary, before the
DEK MAC gate. The swap regression uses the existing per-call probe seam, not a
process-global hook. macOS native isolation remains false; its canary rule is
unchanged. No unsafe block or process global was added.

The exact-revision item projector moved unchanged into `memory/recall/items.rs`
after the repair reached the 800-line bar. Its new regression has its own module.
No baseline was raised. All four ratchets and the 701-name root surface still pass.

## Latest Codex findings (2026-09-19 15:37 UTC)

Complete PR939 REST comments/reviews plus GraphQL review-thread refresh retained at `/home/lexi/w7-build/tickets/W7-C10/review-recovery/pr939-20260919T155803Z`. All pages are complete. These seven additional findings are assessed separately from the earlier six; none replaces an original finding. Scoped regression proof at `218ea673` is 72/72 green on the MacBook; broader validation remains active.

- `4053637002` — VALID — facet recall selects the indexed frontier and returns a pinned reference; shared HTTP search projection reads Indexed. Added exact-body/ref and Summary/Full regressions.
- `4053637007` — VALID — deletion removes the authentication evidence, so citation resolution now fails EntityNotFound rather than accepting a caller-recomputed hash. Original and forged post-delete citations are both refused.
- `4053637009` — VALID — first request after restart restores a persisted matching active window before incrementing counts; regression also pins threshold-question idempotence.
- `4053637013` — VALID — revision capture and first pin use millisecond wall-clock precision. The server idle tick now also passes true milliseconds. Added a deterministic boundary-precision test.
- `4053637016` — VALID — index_only must be disjoint from all five persisted families, before any transaction writes; regression checks each family and absent turn anchors.
- `4053637018` — VALID underlying binding gap; literal requested-turn equality SKIPPED because unchanged families deliberately reuse earlier claims. A durable per-claim writing-frontier binding is minted in the same transaction and verified by the common claim read/write door. Test preserves unchanged-turn reuse and rejects a forged reference for both turns. No deployed-vault migration required pre-GA.
- `4053637022` — VALID — every successful embedding pass invokes entity-local due publication, regardless of global queue occupancy. An event-gated real-worker regression holds the second leased request and checks that an already-staged revision was published while backlog remains.

### Validation at `218ea673`

- MacBook scoped nextest: **72 passed**, 0 failed, 9008 filtered; run `5dba0ac1-d077-4b8a-9d3a-d9821510e9ad`. All original regression tests and the first six Codex regressions passed.
- Full touched-crate MacBook nextest: **6474 passed (515 retried), 2645 failed**, 28 skipped. Widespread `StorageFull` / OS error 28 occurred while test vaults used the system-volume temporary directory. This is NOT a full pass. Native logs and exact commands remain under ticket `review-recovery/native-at-218ea673/`.
- Found one independent deterministic failure: the shipped server skill-pack copy still carried the old effort names and enforced-WebSocket claim. Synchronized it byte-for-byte with the already-correct root artifact.
- Disk receipt after the run: system/temp volume 38,563,040 KiB available; external Cinema volume 863,011,352 KiB available. Next validation uses a ticket-owned real-path temporary directory on Cinema, with a 100 GiB free-space check on both test and build volumes. No other ticket, cache, or shared capacity was changed. Non-space assertion failures are retained separately and must be rechecked; they are not silently waived.
- The seven latest fixes above are pending native validation. Full-gate follow-up remains required; neither this scoped pass nor the failed broad run is a verdict.

### Resource diagnosis and compiler continuation after `fb33b12a`

- `7637f25e` exposed a private-module import in server search; `8b3f3f94` uses the existing public `oneiron::memory::ReadMode` re-export.
- `8b3f3f94` exposed two regression-fixture compile mistakes. `fb33b12a` uses the public `Vault::query` to obtain a hit, then projects through `ScopedRead`; it also preserves the original valid-citation drift assertion for a still-live edited entity. Only post-deletion resolution is refused.
- At `fb33b12a`, the latest scoped run compiled and ran **61 tests: 25 passed, 36 failed**. The pure millisecond-clock and shipped skill-pack checks pass. Vault-opening tests still fail `StorageFull` / OS error 28 on Cinema despite >800 GiB free. Moving test temporary files alone did not solve this.
- The bounded native POSIX probe is decisive: one fresh named semaphore opens, but a second simultaneous fresh semaphore returns ENOSPC. `kern.posix.sem.max=10000`; the linked LMDB binary imports `sem_open`. A private System V semaphore probe succeeds. Probe-owned objects are removed; no unrelated semaphore, process, cache, or kernel setting was changed. Owner action is needed to raise POSIX semaphore capacity or reclaim proven orphaned POSIX semaphores. This is not a request to raise the unrelated System V limits.
- Compiler-only lanes continue independently. Strict workspace clippy found ten core lints; `1d6dc059` fixes them without suppressions. Two existing write-path blocks moved into private helpers to remain below the 500-line function limit. Both files remain below 800 lines, and the ratchet counters are unchanged. These lint repairs are pending clippy confirmation; runtime failures are not waived.

### Compiler progress at `42250f08`

- Workspace Clippy (`--workspace --all-targets --all-features -- -D warnings`) passed on the MacBook. This confirms the core lint repairs, the server import/map simplifications at `858b06fe`, and fixture-only lint repairs at `42250f08`. No assertions or test coverage were removed.
- Featureless Clippy then found a helper and its re-export that had only a sync-enabled embedding-reconciler caller. Both now use `#[cfg(feature = "sync")]`; all base-mode tests remain enabled. The all-features compiled behavior is unchanged, so its green Clippy evidence is retained while the failing and remaining compile lanes continue.
- Complete PR939 comments, reviews, and inline threads were refreshed at 16:53:45 UTC. There are no new actionable findings. CodeRabbit remains skipped, Qodo reports zero current bugs, and Codex reports running on `42250f0`; that is pending activity, not a pass.
- A fresh POSIX probe still fails on its second simultaneous semaphore with ENOSPC. Runtime validation remains pending capacity recovery. The workspace Clippy pass does not waive runtime or the remaining compile gates.

### Additional Codex findings at `949f006b` (17:14 UTC)

Complete PR939 comments/reviews/inline threads are retained in the 17:15:06 UTC refresh and `codex-949f006b-findings.json`; review `5256658024` genuinely completed. These findings add to, not replace, the previous ledger:

- `4053957167` — VALID, repaired: decoder and writer require the exact `SCORE_EPSILON` bit pattern. Added a pure codec regression and aligned the residual fixture with the supported format; arbitrary persisted thresholds are not supported.
- `4053957174` — VALID, repaired: identical type/body with changed temporal metadata creates and retains an exact frontier, and advances Indexed immediately only when previously clean. Existing pending content stays pending; staged text/vector/token/phonetic work is retargeted atomically and its debounce clock is preserved. Simply ignoring header-only writes was rejected because it breaks exact pinned/indexed reads. Added clean and already-pending regressions.
- `4053957181` — VALID, repaired: validate caller state before the persistence-failure latch; retain in-transaction validation for session writes. Added a public pipeline regression showing later valid telemetry persists after invalid input. Existing storage-failure latch coverage stays enabled.
- `4053957186` — VALID, repaired: both activity decode doors validate review/proposal ordering before any subtraction or mutation. Added a pure decoder regression and a stored-corruption test for aggregation and review. All four repairs await current-candidate validation; vault-dependent regressions still need host capacity recovery.

The narrow `sync,test-hooks` test binaries compile at `949f006b`. Python collection initially failed because the validation runner's next source sync removed the editable extension; installing and checking in the same snapshot fixes that setup failure. All 146 Python tests collect; the 10 no-vault export/error tests pass. Vault-dependent tests and full gates remain pending POSIX semaphore recovery. These are not waived.

### Guarded portable validation and Codex review at `6520275f`

Mac compilation and three pure regressions passed at `6520275f`. The owner authorized only portable Rust runtime tests through the normal guarded fallback with MacBook excluded; host slots, reserves, and thread settings were not overridden. The first Arch run (`af79b6a4-14bd-4dfc-bca1-7a1c38959457`) ran 66 focused tests: **65 passed, one telemetry fixture failed**. Metadata publication/pins, healer corruption refusal, the seven previous Codex regressions, and the retained benchmark/open-gate assertions passed. The telemetry fixture must expect the pipeline's typed `InvalidConfig` refusal, then still prove that a later valid row persists. Broader stages did not run after this failure.

Complete latest PR939 receipts include Codex review `5256826790` at `6520275f`, completed 17:51 UTC; raw findings are retained in `codex-6520275f-findings.json`:
- `4054092606` — VALID: grant touches, connector-key rewrites, and sweep finalization now capture revisions before replacing bytes. Erasure of identity-event author stamps instead removes retained history, so a prior pin cannot recover erased authorship. Existing public-door fixtures now pin before and after these operations. Revision capture remains lazy for opaque, unpinned rows.
- `4054092614` — VALID: score encode/decode rejects negative mass, including subnormal values; the decoder used by legacy and state rows shares this check. Zero and positive mass remain valid.
- `4054092620` — VALID: idempotent intake verifies that the live deterministic ASSET exists, has the right type, and still contains the exact submitted bytes. Missing/replaced evidence returns typed `CorruptedIndex`, without resurrecting erased bytes. A regression covers deletion and replacement.
- `4054092623` — VALID: the shared decoded frame dispatch resumes SLIM after the sync revocation gate and before RPC/subscription/sync work. Keepalive ping/pong and invalid frames do not resume. A real established-socket test sheds during a journaled outbound call, keeps SLIM through a ping/pong, then resumes on an app request.
- `4054092629` — VALID repository scheduling rule: the fleet workflow now selects generic OS/architecture labels. The performance receipt still requires the exact approved measured host/build fingerprint; a different machine requires a new approved floor and does not silently inherit another machine's performance claim. No runner labels or host settings were changed.

All earlier findings remain in this ledger. No full runtime or full-gate pass is claimed.

The five latest repairs and corrected telemetry expectation await candidate-bound validation. No newly repaired finding is marked proved before its runtime result.

Pre-runtime checks for these repairs: formatting passed; code-map regeneration reported no changed artifacts; ratchet stayed `2 / 98 / 91 / 33`; root surface stayed 701; all seven fleet-receipt fixture tests passed. These fixtures validate rejection/comparison logic, not new measured benchmark throughput.


## Codex review 5257041165 at 1f1ab564 — next repair candidate

Complete own-PR REST comments/reviews/inline comments and GraphQL threads were
refreshed before applying these repairs. The refreshed snapshot has 12 issue
comments, 45 reviews, 73 inline comments, and 34 complete review threads, with no
new or edited findings after the nine below. Raw receipts remain under the ticket's
`review-recovery/` directory. Earlier internal and bot dispositions remain intact.

| Inline ID | Decision and repair |
| --- | --- |
| 4054244647 | Valid. Capture indexed revisions in each ranking transaction, carry them through depth fusion, reranking, recall, pack hydration and HTTP evidence projection. Never replace a missing pin with the latest frontier. Later channels cannot mix a new revision's score with an old body. Tests publish an edit inside the host reranker and after the depth result returns. |
| 4054244650 | Valid. Wire receipt/question keys bind both window boundaries, preserving distinct durations with the same start. Restart and duration-change fixtures cover both rows. Pre-GA v2 keys have no compatibility decoder. |
| 4054244651 | Valid. Persisted retrieval-run decoding validates state and maps invalid state to typed corruption, before either read door returns it. |
| 4054244654 | Valid. Managed prepare-reap freezes and drains the shared telemetry writer under its mutex. Existing WebSockets, HTTP observation, periodic flush, thresholds, and Drop cannot write while frozen. Reap-abort resumes observation; shutdown does not thaw a quiescent process. |
| 4054244656 | Valid. Keep top-level engine identity-key stripping but preserve nested user-owned `identity_key` data in every serializer. |
| 4054244659 | Valid. Entity input/vector refusals produce typed per-revision failed receipts and allow independent candidates to publish. Storage/provider-wide failures still abort. The server checks provider locality before starting the pass. |
| 4054244660 | Valid. Add required `partial` to TypeScript and Python public retrieval metadata types. Runtime DTO bytes do not change. |
| 4054244663 | Valid. Every feedback queue decode binds the embedded id to its durable queue key. Corrupt rows fail before digest, close, replay or dedup can mutate another item. |
| 4054244665 | Valid. Report-blocked uses a host-owned witness envelope type, not ordinary thought content. Public witness doors reject that reserved type; only crate-private executor routes admit it, including session promotion. Actual thought-dispatch and public-witness spoof tests accompany the genuine effect replay test. |

No new finding is skipped. Qodo's historical zero-finding result and CodeRabbit's
disabled/skipped review are not substitutes for validation of this candidate.

Guarded portable r2 at `1f1ab564` finished with rc101 before running tests. It
exposed misplaced connector-key fixture assertions (`old_pin`/`old_raw` were in
a different test). The assertions now sit with their lifecycle fixture setup.
The raw failure and original candidate remain archived; none of its eight tests
or later planned stages is claimed green. Validation of the repairs is pending.

Type-only validation for 4054244660 passed on the repaired bytes: TypeScript 5.9.3
compiled the public consumer through `check:retrieval-types`; the MacBook Python
3.12 review environment passed the runtime-evaluated TypedDict contract (1/1).
Source hashes and raw command output are in `latest-nine-type-checks/`. This is
not a native Rust or full Python vault-suite pass.


## Guarded validation at 6adcf847

Focused run `94679160-57eb-46e7-bcdc-5d9ee906f12e` compiled core/server and ran
22 tests: 21 passed, one failed (rc100). All nine latest-review repairs have
passing focused evidence, including the separate client type checks. The one
failure was the earlier WebSocket-resume regression: its ordinary socket actor
had no first-party outbound policy ceiling, so dispatch was correctly held before
the sink ran. The test now uses the same separately seeded outbound sender and
owner-grant setup as the managed outbound-shed fixture. It retains the original
human socket principal and does not weaken production gate behavior.

Formatting, code-map generation, ratchet, root-surface pin and diff check passed.
The full script and narrow sync suite remain unrun because the focused stage
failed. The complete PR refresh before this fixture repair found no new completed
Codex finding at 6adcf847; the automatic review was still running. The public type
finding 4054244660 is resolved with unchanged-byte TypeScript/Python proof.


## Codex reviews 5257427262 / 5257577053 — follow-up at 978c05ff

The complete PR939 corpus was refreshed before these edits: 15 issue comments,
62 reviews, 95 inline comments, and complete GraphQL thread/comment pagination.
Codex completed review 5257577053 at 978c05ff; Qodo reported zero active findings;
CodeRabbit remained disabled/skipped, not approved. All earlier internal, Qodo,
Codex and subreview receipts/dispositions remain retained. The seven findings
below are valid; none is skipped. Raw IDs and head-bound receipts are under the
ticket's `review-recovery/` directory.

| Inline ID | Repair and regression |
| --- | --- |
| 4054512606 | Session world narrowing reads the revision captured with each hit, not the mutable live world. Missing pins fail closed. The helper now requires the revision map explicitly. A world move remains in the indexed world until idle publication. Current actor/status admission remains live. |
| 4054512607 | Pack vectors are included only when the selected body pin equals the current indexed pin in the same transaction. Old pins retain old bodies but do not borrow a newer vector; unpublished Live bodies do not borrow the old vector. Unversioned rows retain existing behavior. |
| 4054512612 | The failure ladder persists the complete authentic healer case in the same transaction as its lease-fenced failure. Both Reserved and agent-definition dispatch verify that case, failed parent, task, scope and run before dedupe/enqueue/oversight. Public DTOs and deterministic correlation refs confer no authority. Fabricated queued/leased/manually failed parents and altered scope/evidence are refused. |
| 4054641521 | Managed argv-only admission explicitly refuses both failure-signal environment variables, including false/empty values. Isolated child-process fixtures assert the typed environment error without process-wide test mutation. |
| 4054641524 | Board reconstruction checks for a live TURN in its existing read transaction. Deleted, archived and wrong-type anchors cannot unlock retained documents. Hard/soft deletion tests retain a sibling turn to prove shared board history is not destroyed. |
| 4054641525 | Every decoded auth.bind attempt records exactly once. Successful binds use the authenticated principal; rejected/missing/rebound tokens use unauthenticated. Receipt maps contain only the fixed verb and actor, never token/params. |
| 4054641527 | Public control-key record lookup now runs the same key-binding and timestamp validator as credential consumers. Corrupt digest/time fixtures return typed Corrupt without mutating the stored row. |

At 978c05ff, guarded r4 passed code-map, fmt, workspace Clippy, featureless
Clippy, server-production Clippy and strict workspace rustdoc. Full nextest
failed: 748 passed, one failed out of 749/9459 run, 21 skipped, 8710 unrun.
The stale-vector-token fixture passed a seconds-rounded timestamp to the
millisecond idle door. It now uses an explicitly elapsed idle instant; all
vector/token/publication assertions remain. This is a fixture-clock repair,
not an assertion inversion. Featureless runtime, doctests and narrow sync did
not run after that failure. These seven repairs and the clock fix await the
successor guarded run; no full-gate pass is claimed.
