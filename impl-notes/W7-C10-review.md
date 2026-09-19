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
