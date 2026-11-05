# The agent's own context board layout (BOARD-LAYOUT)

Owner ruling BOARD-LAYOUT = A (2026-11-03 20:25), with its add-ons (20:29
fold summary, 20:31 keep, filters, shares, next-turn batches). The owner or
harness sets the board cap; the agent lays its board out inside it.

## What a layout holds

One layout per actor (`context_board.layout.v1:`, keyed by the actor id). It
names sections by their layout key: the first word of the section's name,
lower case (`tasks`, `memories`, `worlds`, `skills`, `inbox`, `scratchpad`,
`readers`, `packs`, `room`, `people` for the prefix roster, or a plugin
section's first name word). Every world's
MEMORIES section shares the one `memories` layout.

Each section may have:

- `share_pct`: the percent of the board cap the section may fill (0-100).
  All shares together stay within 100. `0` is a literal zero: the section
  shows its count line. A section without a share renders as before.
- `fold`: the section renders as one line, built by the engine from live
  typed state every render (no model call): its total and its change since
  the fold, its counts by status with their changes, the rows that need
  attention, the open command, and the agent's note. Kept rows (`keep`)
  stay open under the line.
- `filter`: which rows the section shows, by `who` (`mine`, one `actor`,
  one actor `class`, or one `group`: a project's roster) and by `status`.

A pinned section (VERBS, ROOM) takes no layout. A section's own pinned rows
(PINNED MEMORIES, loaded SKILLS) and the legend never fold. A fold is a view
setting: the section stays live, `describe` still opens it in full, and the
fold line counts every admitted row, so a filter or a window never hides a
failure from it. A filter narrows rows the reader already reads; a group
roster is read only when the reader reads the project.

The canonical shed order still runs over the laid-out board (ARCH-0067 §3).

## Verbs

All six are the actor's own: the engine keys the layout by the handle's
actor. They need an unrestricted record scope.

| Verb | What it does |
|----|----|
| `self.board.layout` | Reads the live layout and the pending batch. |
| `self.board.fold({section, note?, keep?})` | Folds one section. Folding again restarts its count of changes. |
| `self.board.unfold({section})` | Unfolds one section. |
| `self.board.size({section, share_pct?})` | Sets or clears one section's share. |
| `self.board.filter({section, filter?})` | Sets or clears one section's filter. |
| `self.board.replace({layout})` | Replaces the whole pending batch. |

Limits: a note is at most 512 bytes; a fold keeps at most 64 rows; a layout
names at most 32 sections; a filter names at most 8 statuses.

## When a change applies

Every verb edits ONE pending batch, so the board changes once per batch and
the prompt cache breaks at most once (ARCH-0067 §2.2).

- HTTP hydration with a `turn` projects the pending batch, and the same
  accepted TURN commit makes it live. Without a `turn`, the live layout
  renders and nothing changes.
- A native chat answer projects the answering agent's pending batch, and the
  answer's accepted history commit makes it live. Omitted, refused or
  unsaved answers apply nothing.
- A native code-mode run's board projects the agent's pending batch at its
  next render (a refresh, a keyed `describe`, or setup), and that render
  makes it live. An MCP connector's board does the same for its actor.
- A batch that drifted (the row was erased, recreated, or another turn
  already applied a batch) applies nothing and never refuses the board. A
  newer pending batch survives the activation of an older one.
- A fold that applies records the section's counts as its baseline, so the
  fold line counts changes from that turn.

## The owner's settings

`GET|POST /v1/owner/settings/board-layout` (the owner only) reads and sets
three things, each absent until set:

- `cap_tok`: the board cap every harness renders under in place of its own
  default (the MCP and run boards' 1200 tokens; the HTTP board's, when no
  standing block reserves its budget). A caller may still ask for less, and
  an explicit override is still honoured and recorded. `null` clears it.
- `default_layout`: the layout an agent's board renders under until the
  agent lays out its own. An agent's first layout verb starts from it.
- `override_layout`: sections whose layout the owner sets for every agent.
  Each wins over the agent's own layout of that section; when the
  override's shares and the agent's other shares pass the cap together,
  the agent's shares give way. `self.board.layout` shows the override as
  `owner_override`.

Each change records the owner's act (`settings.board_layout`) with the
settings it replaces, as the other owner policy settings do.

## Persistence and forks

The layout persists across sessions. A new native attenuated fork copies its
source actor's live and pending layout once, in its creation transaction,
with a fresh row incarnation; the fork's later changes never reach the
parent. An actor with no layout of its own renders under the owner's
default layout, else the engine's own sizing of every section.

## Sizes that follow a share

- TASKS: a share sets the concrete task rows' token allotment in place of
  the 100-row cap. An explicit per-request `tasks_budget_tok` still wins.
- WORLDS and INBOX: a share lifts their 16-row producer caps to the share's
  token count; the frame then fits the rows to the share exactly.
- TASKS fan-out rows: a TASKS share lifts their 8-row cap the same way.
- ROOM: ROOM is pinned and takes no fold or fit, but a `room` share lifts
  the `invite?:` hint's 5-person cap.
- PEOPLE: the cached prefix's people roster, 512 tokens by default, takes a
  `people` share of the cap. The prefix re-lays out only at an epoch
  boundary (turn one or a fold of the self brief), so a `people` change
  waits for the next boundary and never breaks the cached prefix between.
- Every other section: the frame fits its rows to the share, ending with an
  additive `+N more` row.

The response's `board_budget.folded` and `board_budget.fitted` name the
sections the layout folded or fitted.

An MCP connector's board lays TASKS out from the rows its scope admits
(`mcp_scoped_task_rows`), so its fold line, filter, share and kept rows see
exactly what the connector may see.

## Not built yet

- An owner override of one agent's layout alone (the override applies to
  every agent).
- MEMORIES filters: a memory row names no author yet, so `who` cannot
  narrow it. TASKS filters by `who` and `status`; INBOX filters by `who`
  (the sender).

