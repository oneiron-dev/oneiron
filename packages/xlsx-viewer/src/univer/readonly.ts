/**
 * Read-only enforcement for the viewer (OF-368 D8: view-only, edits round-trip
 * agent-side). The mount registers a `beforeCommandExecuted` interceptor that
 * throws when a command would mutate the workbook; this module holds the pure,
 * testable predicate that decides which command ids are edits.
 *
 * Deliberately a denylist of MUTATING command tokens — navigation, selection,
 * scroll, zoom, and active-sheet switching (which the viewer needs) are NOT
 * matched, so read-only never breaks viewing.
 */
const EDIT_COMMAND_TOKENS: readonly string[] = [
  "set-range-values",
  "set-range-formatted",
  "set-style",
  "set-range-style",
  "insert-row",
  "insert-col",
  "insert-range",
  "remove-row",
  "remove-col",
  "delete-range",
  "move-range",
  "move-rows",
  "move-cols",
  "clear-selection-content",
  "clear-range",
  "add-worksheet-merge",
  "remove-worksheet-merge",
  "set-worksheet-name",
  "set-worksheet-row",
  "set-worksheet-col",
  "set-worksheet-order",
  "set-tab-color",
  "insert-sheet",
  "remove-sheet",
  "append-row",
  "paste",
  // Entering the cell editor / typing text is an edit for a view-only grid.
  "set-cell-edit-visible",
  "insert-text",
  "delete-text",
];

/** True when a Univer command id represents a workbook edit (must be blocked). */
export function isEditCommandId(id: string): boolean {
  return EDIT_COMMAND_TOKENS.some((token) => id.includes(token));
}
