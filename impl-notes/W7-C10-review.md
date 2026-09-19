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
