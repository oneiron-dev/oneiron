/* How wide a pane beside the room is. A pane for a list (an outline, the
   tasks) is 340 px. A pane for one thing takes what the messages column
   leaves, between 380 and 680 px. A work area too narrow for the column
   and the pane's floor takes either pane over the room instead. Pure, and
   the same rule as the CSS track the split draws before anything is
   measured. */

export type PaneKind = 'list' | 'thing'

export const LIST_PANE_PX = 340
export const THING_PANE_MIN_PX = 380
export const THING_PANE_MAX_PX = 680
/* What the messages column needs beside its own width: the work area's
   two side paddings (28 px each), the 24 px portrait gutter and the 12 px
   gap before the column. */
export const COLUMN_ROOM_PX = 92
/* The messages column (--sl-col). */
export const COLUMN_PX = 620
/* The edge between the room and the pane: a 1 px grid track. */
export const SPLIT_EDGE_PX = 1

/* The widths the person can drag a pane to. */
export function paneBounds(kind: PaneKind): { min: number; max: number } {
  return kind === 'list' ? { min: LIST_PANE_PX, max: THING_PANE_MAX_PX } : { min: THING_PANE_MIN_PX, max: THING_PANE_MAX_PX }
}

/* The pane's width in a split `containerWidth` wide, of which a sidebar
   takes `sidebarWidth` (0 when the split holds only the work area). The
   1 px edge is left to the room too, so the column keeps its full width. */
export function paneWidth(kind: PaneKind, containerWidth: number, sidebarWidth = 0, column = COLUMN_PX): number {
  if (kind === 'list') return LIST_PANE_PX
  const left = containerWidth - sidebarWidth - (column + COLUMN_ROOM_PX) - SPLIT_EDGE_PX
  return Math.min(THING_PANE_MAX_PX, Math.max(THING_PANE_MIN_PX, left))
}

/* What a pane over a narrow room leaves of the work area at its left. */
export const PANE_OVER_GUTTER_PX = 56

/* The narrowest a pane beside the room may be: a list's 340 px, one
   thing's 380 px. */
export function paneFloor(kind: PaneKind): number {
  return kind === 'list' ? LIST_PANE_PX : THING_PANE_MIN_PX
}

/* When the work area is narrower than the messages column, its gutter and
   the pane's floor together, the pane lies over the room instead of
   beside it, and the room keeps its column. */
export function paneLiesOver(kind: PaneKind, containerWidth: number, sidebarWidth = 0, column = COLUMN_PX): boolean {
  return containerWidth - sidebarWidth - (column + COLUMN_ROOM_PX) - SPLIT_EDGE_PX < paneFloor(kind)
}

/* The width of a pane over the room: a list's 340 px, one thing's 680 px
   at most; never wider than the work area less 56 px. */
export function paneOverWidth(kind: PaneKind, containerWidth: number, sidebarWidth = 0): number {
  const most = kind === 'list' ? LIST_PANE_PX : THING_PANE_MAX_PX
  return Math.max(0, Math.min(most, containerWidth - sidebarWidth - PANE_OVER_GUTTER_PX))
}

/* The same rule as a CSS grid track, for the first paint. */
export function paneTrack(kind: PaneKind, sidebarWidth = 0): string {
  if (kind === 'list') return `${LIST_PANE_PX}px`
  return `clamp(${THING_PANE_MIN_PX}px, calc(100% - ${sidebarWidth}px - (var(--sl-col, ${COLUMN_PX}px) + ${COLUMN_ROOM_PX}px) - ${SPLIT_EDGE_PX}px), ${THING_PANE_MAX_PX}px)`
}

/* The placeholder of the write box under one thing: before its thread
   starts, and after. */
export function thingPlaceholder(hasThread: boolean): string {
  return hasThread ? 'Reply' : 'Write about this'
}
