# The agent's own context board layout (BOARD-LAYOUT)

Owner ruling BOARD-LAYOUT = A (2026-11-03 20:25), with its add-ons (20:29
fold summary, 20:31 keep, filters, shares, next-turn batches). The owner or
harness sets the board cap; the agent lays its board out inside it.

## What a layout holds

One layout per actor (`context_board.layout.v1:`, keyed by the actor id). It
names sections by their layout key: the first word of the section's name,
lower case (`tasks`, `memories`, `worlds`, `skills`, `inbox`, `scratchpad`,
`readers`, `packs`, or a plugin section's first name word). Every world's
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

## Persistence and forks

The layout persists across sessions. A new native attenuated fork copies its
source actor's live and pending layout once, in its creation transaction,
with a fresh row incarnation; the fork's later changes never reach the
parent. An actor with no layout of its own renders under the default
layout (the engine's own sizing of every section).

## Sizes that follow a share

- TASKS: a share sets the concrete task rows' token allotment in place of
  the 100-row cap. An explicit per-request `tasks_budget_tok` still wins.
- WORLDS and INBOX: a share lifts their 16-row producer caps to the share's
  token count; the frame then fits the rows to the share exactly.
- Every other section: the frame fits its rows to the share, ending with an
  additive `+N more` row.

The response's `board_budget.folded` and `board_budget.fitted` name the
sections the layout folded or fitted.

## Not built yet

- The owner's board cap and default layout as a vault setting, and the
  owner's override of one agent's layout.
- Share-driven sizes for the ROOM invite hints, the TASKS fan-out rows and
  the PEOPLE prefix roster (the prefix re-lays out at the epoch boundary).
- Filters beyond TASKS, and the connector board's TASKS share, filter and
  full fold counts (its fold line counts its scoped rows only).
