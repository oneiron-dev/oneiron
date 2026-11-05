# ROOT TASKS layout over raw HTTP (FIX 12570, HTTP slice)

Status: parent 12570 PART, ROOT raw HTTP only. Not full 12570.

## Partial scope

One authenticated actor's ROOT TASKS-row token budget, durably staged and
commit-linked to an explicit actual TURN. Nothing else in 12570 ships here.

Covered:

- `GET|POST /v1/core/context-board/layout/tasks` (one raw HTTP API, no SDK
  row, no MCP verb, no catalog/generator change).
- Actor-keyed durable live default plus ONE pending staged write.
- Explicit TURN projects the staged pending snapshot NOW before render; the
  SAME accepted history transaction activates the exact candidate.
- Explicit per-request `tasks_budget_tok` still wins for that render and
  never consumes pending.
- Existing 5426 renderer (`render_with_token_budget`), metadata
  (`TasksRowBudget`), hook-pin/tag (`pin_hook_tasks`/`tag_hook_pins`) and
  global SHED order remain.

Explicitly OPEN (full 12570 PART):

- MCP/run/chat next-turn application of the staged layout.
- Fork-specific store, eager fork copy, or independent fork layout. Forks
  hold no copy in this slice and must not pretend otherwise.
- Full shares summed across all sections, folds, filters, keep/note rows,
  owner defaults/settings, prefix epoch handling, or full-board layout.
- Any new numeric cap, default, timeout, row/byte/count cap, or speed/GPU/
  deploy/server/build claim.

## Zero and reset

Stored and wire budgets are token counts for concrete TASKS rows only
(including their `fits:` rows and the overflow footer). Project/fanout lead
rows ride outside the allotment.

- `None` (no row, live `None`, or an activated reset) keeps the native
  100-row path (`render`, `RENDER_ROW_CAP`). It is not zero.
- `Some(0)` is a literal zero for optional rows: the footer (and any hook
  pins the caller adds after) may exceed it and are reported, never
  withheld.
- The raw stored request is preserved. Only the effective projection clamps
  to the actual global cap (`min(stored_u64, cap_as_u64)` before the `usize`
  cast, proven to fit). Explicit over-cap per-request budgets keep their
  existing 400 (`tasks budget exceeds board cap`); staged values never
  refuse hydration.

## Staging

- POST `{budget_tok}` is REQUIRED nullable unsigned. Missing `budget_tok`
  (including `{}`) is 400 and never resets. Explicit `null` stages a reset;
  `0` stages literal zero; unsigned stages that many tokens.
- Repeated writes replace ONE pending batch and bump the monotonic stage
  counter; they never queue per turn.
- GET reports `{live_budget_tok, pending}` for the caller's own actor only.
  `pending: null` is no pending; `{"budget_tok": null}` is a staged reset;
  `{"budget_tok": N}` is a staged set. Staged reset is never flattened with
  no pending. GET never mutates. Revision numbers stay internal.
- A hydration without TURN reads LIVE only and never activates pending.
- Staging needs `core:write` plus an entity principal and declared actor
  class. Reading needs `core:read`; without an entity identity it returns
  an empty state without reading storage. An identified HTTP caller reads
  or stages only its own actor's row.

## Overrides

- Explicit per-request `tasks_budget_tok: Some` uses its exact requested
  budget for that render (validated against the SAME effective board cap
  before ANY retrieval, FIX 14248) and never selects or consumes pending.
  This slice ignores pending entirely then: no candidate. Newer staged
  writes wait for a later actual TURN that uses the stored layout.
- Explicit TURN with no per-request override projects the SELECTED pending
  snapshot NOW before render (pending when present, else live), clamped to
  the SAME resolved global board cap the final frame renders under. The SAME
  accepted history transaction then activates the exact candidate.
- No-turn reads never activate, even when pending exists.

## Concurrency

- The captured candidate binds its actor, the row's fresh real incarnation,
  the captured live revision, and the captured pending revision/value. Its
  type is public for transport; all fields stay private and are consumed
  only by the new TURN record method.
- Activation runs in the SAME returned `RwTxn` after `stage_board_turn`
  succeeded (existing author/readability/once-only proofs keep precedence)
  and before accept/commit, so it commits if and only if the accepted
  response commits. A declined accept drops BOTH writes.
- Actor mismatch is the existing `NotTurnAuthor`. Every other drift skips
  silently and never refuses the current board: a missing row (erased after
  capture) never resurrects; an incarnation mismatch (erase+recreate ABA)
  never activates; a live-revision mismatch (another successful TURN already
  advanced live) never overwrites.
- A pending-revision move alone still activates the exact rendered candidate
  while retaining the newer pending batch; a still-matching pending revision
  clears. No CAS-mismatch refusal, retry, timer, or default.
- Keyed-retry idempotency and the once-only TURN anchor keep their existing
  semantics; the TURN gate (`board_turn_target`) still parses/auths first
  and the SAME-writer history still proves author/once-only finally.

## Restore limitations

- Side table `CONTEXT_BOARD_TASKS_BUDGET`
  (`b"context_board.tasks_budget.v1:"`, `Named` MessagePack, `Engine`
  payload, never `Authored`, no stored notes): ids, counts and token state
  only.
- Actor scrub on erase: a live actor's row leaves with it. Activation
  requires an existing row; reads never create rows.
- Restore class CONTENT: the image's rows come back as historical content.
- Payload Unclassified, explicitly registered, no `Getter`/tag. Historical
  checkpoints stay under the vault-wide seal and are named on the capture
  receipt (`NOT_COMPARTMENTED`). No checkpoint actor-erase or global restore
  closure is claimed.
- No new database (reuses `vault_meta`), no archive allowlist entry (not
  carried until a later lane adds it), no open-gate or storage-gate change.
