/* Measured placement for floating layers (popovers, menus, tooltips). The
   layer sits on one side of its anchor, aligned along the other axis, and
   flips to the opposite side when that side has more room.

   While the anchor is in the viewport the layer is also clamped inside the
   viewport margin. Once the anchor has left the viewport the layer is not
   clamped: it keeps its place against the anchor and leaves the viewport
   with it, so it never floats over unrelated content. Pure: callers
   measure, this computes. */

export type Side = 'top' | 'bottom' | 'left' | 'right'
export type Align = 'start' | 'center' | 'end'

export interface AnchorRect {
  top: number
  left: number
  width: number
  height: number
}

export interface Size {
  width: number
  height: number
}

export interface PlacementOptions {
  side?: Side
  align?: Align
  /* Gap between anchor and layer. */
  offset?: number
  /* Minimum distance kept from the viewport edges while the anchor is in view. */
  margin?: number
}

export interface Placement {
  top: number
  left: number
  side: Side
  /* The anchor-facing corner or edge the layer grows from. */
  transformOrigin: string
  /* False when the anchor is outside the viewport and the layer follows it out. */
  anchorInView: boolean
}

const OPPOSITE: Record<Side, Side> = { top: 'bottom', bottom: 'top', left: 'right', right: 'left' }

function room(side: Side, a: AnchorRect, viewport: Size, offset: number, margin: number): number {
  switch (side) {
    case 'bottom':
      return viewport.height - margin - (a.top + a.height + offset)
    case 'top':
      return a.top - offset - margin
    case 'right':
      return viewport.width - margin - (a.left + a.width + offset)
    case 'left':
      return a.left - offset - margin
  }
}

function clamp(value: number, min: number, max: number): number {
  return max < min ? min : Math.min(max, Math.max(min, value))
}

/* True when some part of the anchor lies inside the viewport. */
export function anchorInViewport(a: AnchorRect, viewport: Size): boolean {
  return a.top + a.height > 0 && a.top < viewport.height && a.left + a.width > 0 && a.left < viewport.width
}

export function placeFloating(
  anchor: AnchorRect,
  layer: Size,
  viewport: Size,
  options: PlacementOptions = {},
): Placement {
  const offset = options.offset ?? 8
  const margin = options.margin ?? 8
  const align = options.align ?? 'start'
  let side = options.side ?? 'bottom'
  const inView = anchorInViewport(anchor, viewport)

  const vertical = side === 'top' || side === 'bottom'
  const need = vertical ? layer.height : layer.width
  if (room(side, anchor, viewport, offset, margin) < need) {
    const flipped = OPPOSITE[side]
    if (room(flipped, anchor, viewport, offset, margin) > room(side, anchor, viewport, offset, margin)) side = flipped
  }

  let top: number
  let left: number
  if (side === 'top' || side === 'bottom') {
    top = side === 'bottom' ? anchor.top + anchor.height + offset : anchor.top - offset - layer.height
    left =
      align === 'start'
        ? anchor.left
        : align === 'end'
          ? anchor.left + anchor.width - layer.width
          : anchor.left + anchor.width / 2 - layer.width / 2
  } else {
    left = side === 'right' ? anchor.left + anchor.width + offset : anchor.left - offset - layer.width
    top =
      align === 'start'
        ? anchor.top
        : align === 'end'
          ? anchor.top + anchor.height - layer.height
          : anchor.top + anchor.height / 2 - layer.height / 2
  }
  if (inView) {
    left = clamp(left, margin, viewport.width - margin - layer.width)
    top = clamp(top, margin, viewport.height - margin - layer.height)
  }

  const cross = (horizontalAxis: boolean) =>
    align === 'center' ? 'center' : horizontalAxis ? (align === 'start' ? 'left' : 'right') : align === 'start' ? 'top' : 'bottom'
  const transformOrigin =
    side === 'bottom'
      ? `top ${cross(true)}`
      : side === 'top'
        ? `bottom ${cross(true)}`
        : side === 'right'
          ? `left ${cross(false)}`
          : `right ${cross(false)}`

  return { top: Math.round(top), left: Math.round(left), side, transformOrigin, anchorInView: inView }
}
