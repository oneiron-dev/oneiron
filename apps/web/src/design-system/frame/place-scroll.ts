/* Where a place's body scrolls when its content or its own height
   changes. Pure, so it is tested without a DOM. */

/* Within this many pixels of the end, the body counts as at the end. */
export const PLACE_END_SLACK_PX = 24

export interface ScrollBox {
  scrollTop: number
  clientHeight: number
  scrollHeight: number
}

/* The person sees the end of the content (or near it). */
export function atScrollEnd(box: ScrollBox, slack = PLACE_END_SLACK_PX): boolean {
  return box.scrollHeight - box.clientHeight - box.scrollTop <= slack
}

/* After a change: the scroll position that keeps the end in view when the
   body was at the end before; null keeps the position the person scrolled
   to. */
export function followScrollEnd(wasAtEnd: boolean, box: ScrollBox): number | null {
  return wasAtEnd ? Math.max(0, box.scrollHeight - box.clientHeight) : null
}

/* Whether the body is at its end after a scroll event. A scroll event is
   read a frame after the scroll that caused it, so its geometry can be
   newer than the scroll: the body sets its own scrollTop to the end, the
   content then grows (a chart that measures its width, a pane that lies
   over the room and widens the column), and the event reads a gap under
   the content that no person made. Only a scroll on unchanged geometry
   that moved the position is the person's; any other keeps what the body
   knew. `measured` is the geometry the body last read or set. */
export function endAfterScroll(wasAtEnd: boolean, box: ScrollBox, measured: ScrollBox | null, slack = PLACE_END_SLACK_PX): boolean {
  if (measured) {
    const layoutChanged = box.scrollHeight !== measured.scrollHeight || box.clientHeight !== measured.clientHeight
    const moved = Math.abs(box.scrollTop - measured.scrollTop) >= 1
    if (layoutChanged || !moved) return wasAtEnd
  }
  return atScrollEnd(box, slack)
}

/* The three numbers of a box, copied. */
export function readScrollBox(box: ScrollBox): ScrollBox {
  return { scrollTop: box.scrollTop, clientHeight: box.clientHeight, scrollHeight: box.scrollHeight }
}
