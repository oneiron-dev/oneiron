/* Roving focus: a composite (a toolbar) is one tab stop, and keys move
   focus between its items. The stop is the item focused last, or the
   first. Pure apart from the `focus` and `tabIndex` of the items it is
   handed, so it is tested on stand-in items without a DOM. */

export type RovingMove = 'next' | 'previous' | 'first' | 'last'

export interface RovingItem {
  tabIndex: number
  focus: () => void
}

/* The move a key makes in a horizontal composite; null for any other key. */
export function rovingMoveForKey(key: string): RovingMove | null {
  switch (key) {
    case 'ArrowRight':
      return 'next'
    case 'ArrowLeft':
      return 'previous'
    case 'Home':
      return 'first'
    case 'End':
      return 'last'
    default:
      return null
  }
}

/* The index a move lands on among `count` items, from `index`. Next and
   previous wrap at the ends. */
export function rovingTarget(move: RovingMove, index: number, count: number): number {
  if (count <= 0) return -1
  switch (move) {
    case 'first':
      return 0
    case 'last':
      return count - 1
    case 'next':
      return index < 0 ? 0 : (index + 1) % count
    case 'previous':
      return index < 0 ? count - 1 : (index - 1 + count) % count
  }
}

/* Makes the item at `stop` the one tab stop (0) and the others reachable
   only by the keys (-1). A stop outside the list falls back to the first. */
export function setRovingStop(items: readonly RovingItem[], stop: number): void {
  const at = stop >= 0 && stop < items.length ? stop : 0
  items.forEach((item, i) => {
    const want = i === at ? 0 : -1
    if (item.tabIndex !== want) item.tabIndex = want
  })
}
