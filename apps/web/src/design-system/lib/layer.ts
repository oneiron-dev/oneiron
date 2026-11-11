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

/* Open layers, newest last: Escape closes only the newest. */
const openLayers: symbol[] = []

export function pushLayer(): symbol {
  const token = Symbol('layer')
  openLayers.push(token)
  return token
}

export function removeLayer(token: symbol) {
  const i = openLayers.indexOf(token)
  if (i >= 0) openLayers.splice(i, 1)
}

export function isTopLayer(token: symbol): boolean {
  return openLayers[openLayers.length - 1] === token
}

const FOCUSABLE =
  'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

export function firstFocusable(root: HTMLElement, selector = FOCUSABLE): HTMLElement | null {
  return root.querySelector<HTMLElement>(selector)
}
