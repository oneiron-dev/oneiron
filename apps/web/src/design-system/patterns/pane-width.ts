/* How wide a pane beside the room is. A pane for a list (an outline, the
   tasks) is 340 px. A pane for one thing takes what the messages column
   leaves, between 380 and 680 px. Pure, and the same rule as the CSS
   track the split draws before anything is measured. */

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

/* The widths the person can drag a pane to. */
export function paneBounds(kind: PaneKind): { min: number; max: number } {
  return kind === 'list' ? { min: LIST_PANE_PX, max: THING_PANE_MAX_PX } : { min: THING_PANE_MIN_PX, max: THING_PANE_MAX_PX }
}

/* The pane's width in a split `containerWidth` wide, of which a sidebar
   takes `sidebarWidth` (0 when the split holds only the work area). */
export function paneWidth(kind: PaneKind, containerWidth: number, sidebarWidth = 0, column = COLUMN_PX): number {
  if (kind === 'list') return LIST_PANE_PX
  const left = containerWidth - sidebarWidth - (column + COLUMN_ROOM_PX)
  return Math.min(THING_PANE_MAX_PX, Math.max(THING_PANE_MIN_PX, left))
}

/* The same rule as a CSS grid track, for the first paint. */
export function paneTrack(kind: PaneKind, sidebarWidth = 0): string {
  if (kind === 'list') return `${LIST_PANE_PX}px`
  return `clamp(${THING_PANE_MIN_PX}px, calc(100% - ${sidebarWidth}px - (var(--sl-col, ${COLUMN_PX}px) + ${COLUMN_ROOM_PX}px)), ${THING_PANE_MAX_PX}px)`
}

/* The placeholder of the write box under one thing: before its thread
   starts, and after. */
export function thingPlaceholder(hasThread: boolean): string {
  return hasThread ? 'Reply' : 'Write about this'
}
