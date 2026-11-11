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
