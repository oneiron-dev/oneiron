/* The sidebar tree, as numbers: how many of a row's child rows show and
   how many fold behind `show more`. Pure, so it is tested without a DOM. */

/* A row shows this many child rows; the rest fold. */
export const SIDEBAR_CHILD_ROWS_SHOWN = 5

export interface ChildRowSplit {
  /* Child rows always on screen. */
  shown: number
  /* Child rows behind `show more`; 0 when they all fit. */
  folded: number
}

export function splitChildRows(count: number, limit: number = SIDEBAR_CHILD_ROWS_SHOWN): ChildRowSplit {
  const total = Math.max(0, Math.floor(count))
  const keep = Math.max(0, Math.floor(limit))
  return total > keep ? { shown: keep, folded: total - keep } : { shown: total, folded: 0 }
}
