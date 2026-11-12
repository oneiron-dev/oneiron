import { placeFloating, type Align, type Side } from './placement'

/* Floating layers use the native popover attribute (manual mode) for the
   top layer and are placed by measurement. These helpers keep the calls
   guarded: a layer may already be in the state asked for. */

export function showLayer(el: HTMLElement) {
  if (typeof el.showPopover !== 'function') return
  try {
    if (!el.matches(':popover-open')) el.showPopover()
  } catch {
    /* detached or not a popover: nothing to show */
  }
}

export function hideLayer(el: HTMLElement) {
  if (typeof el.hidePopover !== 'function') return
  try {
    if (el.matches(':popover-open')) el.hidePopover()
  } catch {
    /* already gone */
  }
}

/* Measures anchor and layer and writes the layer's position and growth
   origin. Returns the side actually used (after a flip). */
export function placeLayer(
  layer: HTMLElement,
  anchor: Element,
  options: { side?: Side; align?: Align; offset?: number; margin?: number },
): Side {
  const a = anchor.getBoundingClientRect()
  const placement = placeFloating(
    { top: a.top, left: a.left, width: a.width, height: a.height },
    { width: layer.offsetWidth, height: layer.offsetHeight },
    { width: document.documentElement.clientWidth || innerWidth, height: innerHeight },
    options,
  )
  layer.style.top = `${placement.top}px`
  layer.style.left = `${placement.left}px`
  layer.style.transformOrigin = placement.transformOrigin
  layer.dataset.side = placement.side
  return placement.side
}

/* Open layers, newest last: Escape closes only the newest. Each layer
   records the element it was opened from (its trigger), so a surface can
   ask whether a layer opened from inside it is still open. */
interface OpenLayer {
  token: symbol
  origin: Node | null
}

const openLayers: OpenLayer[] = []
const listeners = new Set<() => void>()

function notify() {
  for (const listener of [...listeners]) listener()
}

/* Registers an open layer; `origin` is the element it was opened from. */
export function pushLayer(origin: Node | null = null): symbol {
  const token = Symbol('layer')
  openLayers.push({ token, origin })
  notify()
  return token
}

export function removeLayer(token: symbol) {
  const i = openLayers.findIndex((layer) => layer.token === token)
  if (i < 0) return
  openLayers.splice(i, 1)
  notify()
}

export function isTopLayer(token: symbol): boolean {
  return openLayers[openLayers.length - 1]?.token === token
}

/* A layer opened from inside `container` (its origin is the container or a
   descendant of it) is open. */
export function layerOpenFrom(container: Pick<Node, 'contains'> | null | undefined): boolean {
  if (!container) return false
  return openLayers.some((layer) => layer.origin !== null && container.contains(layer.origin))
}

/* Calls `listener` after any layer opens or closes. Returns the
   unsubscribe. */
export function onLayersChange(listener: () => void): () => void {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

const FOCUSABLE =
  'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

export function firstFocusable(root: HTMLElement, selector = FOCUSABLE): HTMLElement | null {
  return root.querySelector<HTMLElement>(selector)
}
