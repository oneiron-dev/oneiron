/* Reordering a list, as data: where an item goes and how far its
   neighbours shift while it is dragged. Pure, so it is tested without a
   DOM. */

/* A copy of the list with the item at `from` moved to `to` (clamped to
   the list). An index outside the list returns an unchanged copy. */
export function moveItem<T>(list: readonly T[], from: number, to: number): T[] {
  const out = list.slice()
  if (!Number.isInteger(from) || from < 0 || from >= out.length) return out
  const target = Math.max(0, Math.min(out.length - 1, Math.trunc(to)))
  if (target === from) return out
  const [item] = out.splice(from, 1)
  out.splice(target, 0, item)
  return out
}

/* Where a dragged item lands: the count of the other items whose resting
   midpoint lies before `edge`, the dragged item's leading edge (its top
   while it moves up, its bottom while it moves down). A neighbour gives way
   once the edge passes half of it, whatever the two items' heights. */
export function dropIndex(midpoints: readonly number[], from: number, edge: number): number {
  let index = 0
  for (let j = 0; j < midpoints.length; j++) {
    if (j !== from && midpoints[j] < edge) index++
  }
  return index
}

/* The leading edge of an item `size` tall, resting with its midpoint at
   `midpoint`, moved by `dy`. */
export function leadingEdge(midpoint: number, size: number, dy: number): number {
  return dy < 0 ? midpoint - size / 2 + dy : dy > 0 ? midpoint + size / 2 + dy : midpoint
}

/* How far item `j` moves while item `from` is held over slot `to`: the
   items between close the gap the dragged item leaves (`size`: its extent
   plus the gap after it). The dragged item itself follows the pointer. */
export function shiftFor(j: number, from: number, to: number, size: number): number {
  if (j === from) return 0
  if (from < to && j > from && j <= to) return -size
  if (to < from && j >= to && j < from) return size
  return 0
}
