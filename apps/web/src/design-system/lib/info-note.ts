/* Where the note of an information mark goes. To the right of the block
   the mark sits in when there is room there; otherwise under the mark,
   its right edge on the mark's right edge. Pure: callers measure, this
   computes. */

/* The resting delay before the note shows. */
export const INFO_NOTE_DELAY_MS = 160
/* Beside the block: the gap to the block and the note's width. */
export const INFO_NOTE_SIDE_GAP_PX = 20
export const INFO_NOTE_SIDE_WIDTH_PX = 300
/* The free width beside the block the note needs to sit there. */
export const INFO_NOTE_SIDE_ROOM_PX = 350
/* Under the mark: the gap to the mark and the note's width. */
export const INFO_NOTE_UNDER_GAP_PX = 4
export const INFO_NOTE_UNDER_WIDTH_PX = 340
/* The note keeps this far from the viewport's edges while its mark is in view. */
const MARGIN_PX = 8

export interface NoteRect {
  left: number
  top: number
  width: number
  height: number
}

export interface InfoNotePlacement {
  side: 'right' | 'under'
  left: number
  top: number
  width: number
}

/* `mark` and `block` are viewport rects; `boundsRight` is the right edge
   of the area the block sits in (its scrolling area, or the viewport).
   `noteHeight` and `viewport` keep the note inside the viewport. */
export function placeInfoNote(
  mark: NoteRect,
  block: NoteRect,
  boundsRight: number,
  noteHeight = 0,
  viewport?: { width: number; height: number },
): InfoNotePlacement {
  const blockRight = block.left + block.width
  const free = boundsRight - blockRight
  let placement: InfoNotePlacement
  if (free >= INFO_NOTE_SIDE_ROOM_PX) {
    placement = { side: 'right', left: blockRight + INFO_NOTE_SIDE_GAP_PX, top: mark.top, width: INFO_NOTE_SIDE_WIDTH_PX }
  } else {
    placement = {
      side: 'under',
      left: mark.left + mark.width - INFO_NOTE_UNDER_WIDTH_PX,
      top: mark.top + mark.height + INFO_NOTE_UNDER_GAP_PX,
      width: INFO_NOTE_UNDER_WIDTH_PX,
    }
  }
  if (viewport) {
    const markInView = mark.top + mark.height > 0 && mark.top < viewport.height
    placement.left = Math.max(MARGIN_PX, Math.min(placement.left, viewport.width - MARGIN_PX - placement.width))
    if (markInView && noteHeight > 0) {
      placement.top = Math.max(MARGIN_PX, Math.min(placement.top, viewport.height - MARGIN_PX - noteHeight))
    }
  }
  placement.left = Math.round(placement.left)
  placement.top = Math.round(placement.top)
  return placement
}
