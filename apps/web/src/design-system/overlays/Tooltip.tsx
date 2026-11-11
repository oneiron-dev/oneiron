import * as React from 'react'
import { hideLayer, placeLayer, showLayer } from '../lib/layer'
import type { Align, Side } from '../lib/placement'
import { Slot, useControllableState, useIsomorphicLayoutEffect, useSafeId } from '../lib/react-utils'

/* Hover waits this long before a tooltip shows. */
export const TOOLTIP_DELAY_MS = 420
/* Within this long of a tooltip closing, the next one shows at once. */
export const TOOLTIP_WARM_MS = 400

let openTooltips = 0
let lastHiddenAt = 0

export interface TooltipProps {
  /* The name: the first line, or the whole hint. */
  label: string
  /* One caption line under the name. */
  caption?: string
  side?: Side
  align?: Align
  open?: boolean
  defaultOpen?: boolean
  onOpenChange?: (open: boolean) => void
  /* One element that takes a ref and pointer and focus handlers. */
  children: React.ReactElement
}

/* A delayed hint on its anchor: shows after a hover delay (at once when
   another tooltip was just up, or on keyboard focus), hides at once on
   leave, press, blur, Escape or scroll. Two forms: a name with one caption
   line, or a plain hint. */
export function Tooltip({
  label,
  caption,
  side = 'bottom',
  align = 'center',
  open: openProp,
  defaultOpen = false,
  onOpenChange,
  children,
}: TooltipProps) {
  const [open, setOpen] = useControllableState(openProp, defaultOpen, onOpenChange)
  const anchorRef = React.useRef<HTMLElement | null>(null)
  const layerRef = React.useRef<HTMLSpanElement | null>(null)
  const timer = React.useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const id = useSafeId('sl-tooltip')

  const show = React.useCallback(() => {
    clearTimeout(timer.current)
    setOpen(true)
  }, [setOpen])

  const hide = React.useCallback(() => {
    clearTimeout(timer.current)
    setOpen(false)
  }, [setOpen])

  const scheduleShow = React.useCallback(() => {
    clearTimeout(timer.current)
    if (openTooltips > 0 || Date.now() - lastHiddenAt < TOOLTIP_WARM_MS) show()
    else timer.current = setTimeout(show, TOOLTIP_DELAY_MS)
  }, [show])

  React.useEffect(() => () => clearTimeout(timer.current), [])

  useIsomorphicLayoutEffect(() => {
    const layer = layerRef.current
    const anchor = anchorRef.current
    if (!open || !layer || !anchor) return
    showLayer(layer)
    const offset = side === 'left' || side === 'right' ? 10 : 8
    const place = () => placeLayer(layer, anchor, { side, align, offset })
    place()
    openTooltips++
    let alive = true
    document.fonts?.ready.then(() => alive && place())
    const onScroll = () => hide()
    addEventListener('scroll', onScroll, { capture: true, passive: true })
    addEventListener('resize', place)
    return () => {
      alive = false
      openTooltips--
      lastHiddenAt = Date.now()
      removeEventListener('scroll', onScroll, { capture: true })
      removeEventListener('resize', place)
      hideLayer(layer)
    }
  }, [open, side, align, hide])

  const captionId = caption ? `${id}-caption` : undefined

  return (
    <>
      <Slot
        ref={anchorRef}
        onPointerEnter={(event: React.PointerEvent) => {
          if (event.pointerType !== 'touch') scheduleShow()
        }}
        onPointerLeave={hide}
        onPointerDown={hide}
        onFocus={(event: React.FocusEvent<HTMLElement>) => {
          if (event.currentTarget.matches(':focus-visible')) show()
        }}
        onBlur={hide}
        onKeyDown={(event: React.KeyboardEvent) => {
          if (event.key === 'Escape') hide()
        }}
        aria-describedby={captionId}
      >
        {children}
      </Slot>
      <span ref={layerRef} id={id} popover="manual" role="tooltip" className="sl-tooltip">
        <span className="sl-tooltip-label">{label}</span>
        {caption ? (
          <span id={captionId} className="sl-tooltip-caption">
            {caption}
          </span>
        ) : null}
      </span>
    </>
  )
}
