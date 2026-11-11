import * as React from 'react'
import { firstFocusable, hideLayer, isTopLayer, placeLayer, pushLayer, removeLayer, showLayer } from '../lib/layer'
import type { Align, Side } from '../lib/placement'
import {
  Slot,
  cx,
  mergeRefs,
  useControllableState,
  useIsomorphicLayoutEffect,
  useSafeId,
} from '../lib/react-utils'

interface PopoverContextValue {
  open: boolean
  /* Opens or closes. `returnFocus` sends focus back to the trigger on close;
     `focusContent` moves focus into the layer on open. */
  setOpen: (open: boolean, options?: { returnFocus?: boolean; focusContent?: boolean }) => void
  triggerRef: React.RefObject<HTMLElement | null>
  contentId: string
  hasPopup: 'dialog' | 'menu'
  /* Read by the content when it opens or closes. */
  intent: React.RefObject<{ returnFocus: boolean; focusContent: boolean }>
}

const PopoverContext = React.createContext<PopoverContextValue | null>(null)

export function usePopoverContext(part: string): PopoverContextValue {
  const ctx = React.useContext(PopoverContext)
  if (!ctx) throw new Error(`${part} must be inside a Popover`)
  return ctx
}

export interface PopoverProps {
  open?: boolean
  defaultOpen?: boolean
  onOpenChange?: (open: boolean) => void
  children?: React.ReactNode
}

interface PopoverRootProps extends PopoverProps {
  hasPopup?: 'dialog' | 'menu'
}

/* Holds the open state shared by the trigger and the content. Renders no
   element of its own. */
export function PopoverRoot({ open: openProp, defaultOpen = false, onOpenChange, hasPopup = 'dialog', children }: PopoverRootProps) {
  const [open, setOpenState] = useControllableState(openProp, defaultOpen, onOpenChange)
  const triggerRef = React.useRef<HTMLElement | null>(null)
  const contentId = useSafeId('sl-popover')
  const intent = React.useRef({ returnFocus: false, focusContent: false })
  const setOpen = React.useCallback<PopoverContextValue['setOpen']>(
    (next, options = {}) => {
      intent.current = { returnFocus: !!options.returnFocus, focusContent: !!options.focusContent }
      setOpenState(next)
    },
    [setOpenState],
  )
  const value = React.useMemo(
    () => ({ open, setOpen, triggerRef, contentId, hasPopup, intent }),
    [open, setOpen, contentId, hasPopup],
  )
  return <PopoverContext.Provider value={value}>{children}</PopoverContext.Provider>
}

export interface PopoverTriggerProps extends React.ComponentPropsWithRef<'button'> {
  /* Render the single child element as the trigger (a Verb, an IconAction). */
  asChild?: boolean
}

/* The control that opens and closes the layer. */
export function PopoverTrigger({ ref, asChild, type = 'button', className, onClick, children, ...props }: PopoverTriggerProps) {
  const ctx = usePopoverContext('Popover.Trigger')
  const triggerProps = {
    ref: mergeRefs(ref, ctx.triggerRef as React.Ref<HTMLButtonElement>),
    'aria-haspopup': ctx.hasPopup,
    'aria-expanded': ctx.open,
    'aria-controls': ctx.contentId,
    'data-state': ctx.open ? 'open' : 'closed',
    onClick: (event: React.MouseEvent<HTMLButtonElement>) => {
      onClick?.(event)
      if (event.defaultPrevented) return
      ctx.setOpen(!ctx.open, { focusContent: true, returnFocus: true })
    },
    ...props,
  }
  if (asChild) return <Slot {...triggerProps} className={className}>{children}</Slot>
  return (
    <button type={type} className={cx('sl-popover-trigger', className)} {...triggerProps}>
      {children}
    </button>
  )
}

export interface PopoverContentProps extends React.ComponentPropsWithRef<'div'> {
  side?: Side
  align?: Align
  /* Gap to the trigger in CSS pixels. */
  offset?: number
  /* Where focus goes on open; defaults to the first focusable element. */
  initialFocus?: string
}

/* The floating layer: in the top layer through the native popover
   attribute, placed by measurement under (or over) the trigger, growing
   from the trigger's corner. Escape and a press outside close it; focus
   goes back to the trigger. */
export function PopoverContent({
  ref,
  side = 'bottom',
  align = 'start',
  offset = 8,
  initialFocus,
  className,
  role = 'dialog',
  children,
  ...props
}: PopoverContentProps) {
  const ctx = usePopoverContext('Popover.Content')
  const layerRef = React.useRef<HTMLDivElement | null>(null)
  const { open, setOpen, triggerRef, intent } = ctx

  useIsomorphicLayoutEffect(() => {
    const layer = layerRef.current
    if (!layer || !open) return
    const trigger = triggerRef.current
    showLayer(layer)
    const place = () => {
      if (trigger?.isConnected) placeLayer(layer, trigger, { side, align, offset })
    }
    place()

    const token = pushLayer()
    let alive = true
    let frame = 0
    const schedulePlace = () => {
      cancelAnimationFrame(frame)
      frame = requestAnimationFrame(place)
    }
    document.fonts?.ready.then(() => alive && place())
    const resize = new ResizeObserver(schedulePlace)
    resize.observe(layer)
    resize.observe(document.documentElement)

    const onPointerDown = (event: PointerEvent) => {
      const target = event.target as Node | null
      if (!target || layer.contains(target) || trigger?.contains(target)) return
      removeLayer(token)
      setOpen(false, { returnFocus: false })
      /* Focus comes back to the trigger unless the press landed on
         something that takes focus itself. */
      setTimeout(() => {
        const active = document.activeElement
        if (!active || active === document.body || layer.contains(active)) trigger?.focus({ preventScroll: true })
      }, 0)
    }
    const onKeyDown = (event: KeyboardEvent) => {
      /* A part inside the layer may take Escape first (an undo window). */
      if (event.key !== 'Escape' || event.defaultPrevented || !isTopLayer(token)) return
      event.preventDefault()
      removeLayer(token)
      setOpen(false, { returnFocus: true })
    }
    document.addEventListener('pointerdown', onPointerDown, true)
    document.addEventListener('keydown', onKeyDown)
    /* The layer follows its trigger: scroll places it in the same frame. */
    addEventListener('resize', schedulePlace)
    addEventListener('scroll', place, { capture: true, passive: true })

    if (intent.current.focusContent) {
      const target = (initialFocus && layer.querySelector<HTMLElement>(initialFocus)) || firstFocusable(layer) || layer
      target.focus({ preventScroll: true })
    }

    return () => {
      alive = false
      cancelAnimationFrame(frame)
      removeLayer(token)
      resize.disconnect()
      document.removeEventListener('pointerdown', onPointerDown, true)
      document.removeEventListener('keydown', onKeyDown)
      removeEventListener('resize', schedulePlace)
      removeEventListener('scroll', place, { capture: true })
      const focusInside = layer.contains(document.activeElement)
      hideLayer(layer)
      if (intent.current.returnFocus || focusInside) trigger?.focus({ preventScroll: true })
    }
  }, [open, side, align, offset])

  return (
    <div
      ref={mergeRefs(ref, layerRef)}
      id={ctx.contentId}
      popover="manual"
      role={role}
      tabIndex={-1}
      className={cx('sl-popover', className)}
      data-state={open ? 'open' : 'closed'}
      {...props}
    >
      {children}
    </div>
  )
}

/* Compound parts: Popover, Popover.Trigger, Popover.Content. */
export const Popover = Object.assign(
  function Popover(props: PopoverProps) {
    return <PopoverRoot {...props} />
  },
  { Trigger: PopoverTrigger, Content: PopoverContent },
)
