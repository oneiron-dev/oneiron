# ROOT TASKS layout for HTTP and native chat (FIX 12570)

Status: parent 12570 PART. Supports ROOT raw HTTP, live chat `start_turn`,
admitted queued Continue/Retry boards, native attenuated-fork TASKS snapshots,
and live-only run-board sizing, not full BOARD-LAYOUT.

## Partial scope

One authenticated actor's ROOT TASKS-row token budget, durably staged and
commit-linked to an explicit actual TURN or a live chat answer's TURN.
New native attenuated forks also inherit that actor-keyed TASKS state once.
Other sections and fork families remain outside this slice.

Covered:

- `GET|POST /v1/core/context-board/layout/tasks` (one raw HTTP API, no SDK
  row, no MCP verb, no catalog/generator change).
- Actor-keyed durable live default plus ONE pending staged write.
- Explicit TURN projects the staged pending snapshot NOW before render; the
  SAME accepted history transaction activates the exact candidate.
- Live `POST /v1/ai/chat` projects its answering agent's ROOT layout before
  render and activates the exact captured candidate in the accepted answer
  history commit. It uses the agent already selected for the answer, not a
  second lookup or the payer. The caller's stored layout does not set chat
  sizing, but its content read authority and HTTP TURN path are unchanged.
  The agent stages its layout through the native POST with its credential.
- Queued Continue/Retry uses the same answering agent selected once for its
  board, answer and records. Its pending layout projects before admission.
  The accepted history commit derives the terminal TURN from the actual
  saved MESSAGE's `PartOf` edge; no preselected TURN or attempt label is used.
  For a reused prefix, this board belongs only to the fallback call: its
  candidate activates only when that fallback actually answered. A prefix
  answered without the fallback leaves pending state unchanged. Existing
  native/no-slip, refused, held, omitted, empty and unsaved paths remain.
- A newly registered native attenuated fork copies the actual source
  definition actor's TASKS state in its creation transaction. It uses the
  requested source, which need not be the delegation parent's target.
  Retried registration of an existing fork never recopies the row.
- Native run-board refreshes and keyed describes read their actual run actor's
  live TASKS budget. They never project or activate pending. Section projection
  and the run's final keyframe share the same existing harness-cap request.
- Explicit per-request `tasks_budget_tok` still wins for that render and
  never consumes pending.
- Existing 5426 renderer (`render_with_token_budget`), metadata
  (`TasksRowBudget`), hook-pin/tag (`pin_hook_tasks`/`tag_hook_pins`) and
  global SHED order remain.

Explicitly OPEN (full 12570 PART):

- MCP connector layout projection and run/program next-turn application of
  pending layouts. The supported run-board read is live-only.
- Eager copies for other fork families, and fork pending-layout application
  beyond the supported HTTP/native chat paths. An inherited row alone does
  not prove that a particular pumped run projected it.
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
- A hydration without TURN and without a chat layout actor reads LIVE only
  and never activates pending; a native chat turn projects its answering
  agent's pending when present else live.
- Staging needs `core:write` plus an entity principal and declared actor
  class. Reading needs `core:read`; without an entity identity it returns
  an empty state without reading storage. An identified HTTP caller reads
  or stages only its own actor's row. A native chat turn projects its
  answering agent's row for sizing only; content still reads as the caller.

## Overrides

- Explicit per-request `tasks_budget_tok: Some` uses its exact requested
  budget for that render (validated against the SAME effective board cap
  before ANY retrieval, FIX 14248) and never selects or consumes pending.
  This slice ignores pending entirely then: no candidate. Newer staged
  writes wait for a later actual TURN that uses the stored layout. Chat
  sends none today.
- Explicit TURN with no per-request override projects the SELECTED pending
  snapshot NOW before render (pending when present, else live), clamped to
  the SAME resolved global board cap the final frame renders under. The SAME
  accepted history transaction then activates the exact candidate.
- A native chat turn with no per-request override projects its answering
  agent's SELECTED pending snapshot NOW before render (pending when
  present, else live), clamped to the SAME resolved global board cap the
  final frame renders under. The SAME accepted answer-history commit then
  activates the exact candidate. Omitted or unadmitted boards, a mismatched
  MEMORIES capture, session-only turns, and empty or unsaved answers activate
  nothing: the existing gates discard the capture or skip its records.
- No-turn reads without a chat layout actor never activate, even when
  pending exists.

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
- A native chat turn inherits the SAME activation semantics: a concurrent
  HTTP TURN advancing agent live between chat capture and chat commit skips
  silently (rendered bytes stand, live keeps newer); a pending-revision
  move alone still activates the exact rendered candidate while retaining
  the newer pending batch; erased/ABA rows never resurrect or activate. No
  new refusal, retry, timer, or gate.
- Chat keeps NO idempotency cache (a fresh answer TURN per turn; once-only
  per TURN holds). A refused/unanswered/unboarded turn commits nothing;
  pending stays pending.

## Live-only run boards

- The run host's actual agent `WriteActor` selects its own live TASKS budget
  before the existing renderer. No payer, session label or caller-supplied
  actor becomes the layout actor.
- The native run board has no caller budget or explicit override. Projection
  resolves the exact same request as its final keyframe: the existing
  `MCP_BOARD_BUDGET_TOK` harness cap, with both optional limits absent.
  One shared request constructor keeps these two uses aligned. Refreshes
  keep their existing final SHED behavior; keyed expands use the same
  budgeted TASKS section. Connector setup's separate budget options are unchanged.
- Stored live `None` keeps the original 100-row renderer; `Some(0)` is literal
  zero; positive values use the existing token-budget renderer clamped to
  that harness cap. Hook pins and their receipts keep their original order.
- This path has no qualified accepted TURN/history writer. It selects with
  `has_turn=false`, returns no candidate and never consumes pending. A staged
  write waits for a supported accepted TURN; a board refresh or subscription
  is not fabricated into that proof. Program pending activation remains open.
- Actor read lanes, source-row tracking, hook delivery, stream state and
  the existing rendered-state epoch calculation are unchanged.

## Fork snapshots

- Only the brand-new AGENT_DEF branch of native attenuated-fork registration
  copies state. The source read, child row write, definition write and
  delegation binding share the accepted writer, so they commit or roll back
  together. The existing occupied-id and deterministic-reuse paths are unchanged.
- The child gets the source's current live value, pending batch and revision
  counters, but a fresh row incarnation under its own actual fork actor id.
  Pending remains pending until the child's own accepted TURN activates it;
  copying never consumes or activates the source's pending batch.
- An absent source row becomes an explicit native default (`live: None`,
  no pending, zero counters). There is no lazy parent lookup. Later source
  stages cannot change the child, and child stages cannot change the source.
- A retry never overwrites child customizations. Existing actor-bound staging,
  candidate ownership, global-cap clamping and history activation still apply.

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
