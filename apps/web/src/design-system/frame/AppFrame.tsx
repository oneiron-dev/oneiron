import * as React from 'react'
import { Icon } from '../primitives/Icon'
import { IconAction, type IconActionProps } from '../primitives/IconAction'
import { WindowGround } from '../ground/WindowGround'
import { firstFocusable, isTopLayer, layerOpenFrom, onLayersChange, pushLayer, removeLayer } from '../lib/layer'
import { cx, useControllableState, useIsomorphicLayoutEffect } from '../lib/react-utils'
import { AppFrameContext, type AppFrameContextValue } from './app-frame-context'
import { PEEK_CLOSED, PEEK_DELAY_MS, PEEK_WARM_MS, peekReducer } from './frame-peek'

/* The `[` key folds and opens one frame: the one the person last pressed
   or focused in (the first mounted until then). */
const frames: symbol[] = []
let activeFrame: symbol | null = null

function readStored(key: string | undefined): boolean | undefined {
  if (!key || typeof localStorage === 'undefined') return undefined
  try {
    const v = localStorage.getItem(key)
    return v === 'open' ? true : v === 'folded' ? false : undefined
  } catch {
    return undefined
  }
}

/* Typing a `[` into a field is text, never a command. */
function isTextEntry(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false
  return target.isContentEditable || !!target.closest('input, textarea, select, [contenteditable="true"]')
}

/* Inside a layer in the top layer (a menu opened from the overlay). */
function inOpenLayer(node: Node | null): boolean {
  const el = node instanceof Element ? node : node?.parentElement
  try {
    return !!el?.closest(':popover-open')
  } catch {
    return false
  }
}

export interface AppFrameProps extends React.ComponentPropsWithRef<'div'> {
  /* The strip at the far left: a MicroSidebar. It never hides. */
  microSidebar: React.ReactNode
  /* The current place's sidebar, or null when the place has none. */
  sidebar: React.ReactNode | null
  /* The sidebar of a microsidebar item, shown over the work area while the
     sidebar is folded; null for an item that has none. */
  peek?: (itemId: string) => React.ReactNode | null
  sidebarOpen?: boolean
  defaultSidebarOpen?: boolean
  onSidebarOpenChange?: (open: boolean) => void
  /* Remembers open or folded on this machine under this key. */
  storageKey?: string
}

/* The frame of the app. The window ground (the root's theme) fills it;
   on it, at the left, the microsidebar; then the sheet, one surface inset
   from the window's top, right and bottom, holding the sidebar and the
   work area (the children) side by side. The sidebar folds with
   AppFrame.Fold in its head or the `[` key; the work area then fills the
   sheet. While it is folded, resting the pointer on a microsidebar item
   shows that item's sidebar raised over the sheet after a short delay.
   The peek previews the place under the pointer: moving to another item
   switches it at once (the delay applies to the first show only); an item
   without a sidebar shows its tooltip and no peek. It hides at once when
   the pointer leaves the items and the peek, and on Escape. A menu or
   popover opened from inside the peek holds it open while that layer is
   open; when the layer closes the peek follows the pointer. ArrowRight
   on a focused item opens it with focus inside; on a touch screen a tap on
   the item opens it and a tap outside closes it. */
function AppFrameRoot({
  microSidebar,
  sidebar,
  peek,
  sidebarOpen: openProp,
  defaultSidebarOpen = true,
  onSidebarOpenChange,
  storageKey,
  className,
  children,
  onPointerDownCapture,
  onFocusCapture,
  ...props
}: AppFrameProps) {
  const [open, setOpenState] = useControllableState(openProp, defaultSidebarOpen, onSidebarOpenChange)
  const [peekState, dispatch] = React.useReducer(peekReducer, PEEK_CLOSED)
  /* The sidebar fades in when the person opens it, never on load. */
  const [reopened, setReopened] = React.useState(false)
  const token = React.useRef<symbol>(Symbol('frame'))
  const microRef = React.useRef<HTMLDivElement | null>(null)
  const overlayRef = React.useRef<HTMLDivElement | null>(null)
  const focusOnShow = React.useRef(false)
  /* The pointer's last position over the page, while a peek shows. */
  const pointer = React.useRef<{ x: number; y: number } | null>(null)

  const hasSidebar = sidebar !== null && sidebar !== undefined
  const sidebarShown = hasSidebar && open
  const folded = !sidebarShown

  /* A remembered state replaces the default once the page is on the client. */
  useIsomorphicLayoutEffect(() => {
    if (openProp !== undefined) return
    const stored = readStored(storageKey)
    if (stored !== undefined) setOpenState(stored)
  }, [storageKey])

  const setOpen = React.useCallback(
    (next: boolean) => {
      setOpenState(next)
      if (next) setReopened(true)
      if (!storageKey) return
      try {
        localStorage.setItem(storageKey, next ? 'open' : 'folded')
      } catch {
        /* storage full or blocked: the state is simply not remembered */
      }
    },
    [setOpenState, storageKey],
  )

  const latest = React.useRef({ folded, peek, open, setOpen, hasSidebar })
  useIsomorphicLayoutEffect(() => {
    latest.current = { folded, peek, open, setOpen, hasSidebar }
  })
  const canPeek = React.useCallback((id: string) => {
    const { folded: isFolded, peek: peekFor } = latest.current
    return isFolded && !!peekFor && peekFor(id) != null
  }, [])

  /* The sidebar unfolding ends any peek. */
  React.useEffect(() => {
    if (!folded) dispatch({ type: 'close' })
  }, [folded])

  /* The resting delay. */
  React.useEffect(() => {
    const id = peekState.waitingId
    if (id === null) return
    const timer = setTimeout(() => dispatch({ type: 'elapsed', id }), PEEK_DELAY_MS)
    return () => clearTimeout(timer)
  }, [peekState.waitingId])

  /* The warm window after a peek hid. */
  React.useEffect(() => {
    if (!peekState.warm) return
    const timer = setTimeout(() => dispatch({ type: 'cool' }), PEEK_WARM_MS)
    return () => clearTimeout(timer)
  }, [peekState.warm])

  /* The `[` key, for the active frame only. */
  React.useEffect(() => {
    const me = token.current
    frames.push(me)
    if (activeFrame === null) activeFrame = me
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== '[' || event.defaultPrevented || event.isComposing || activeFrame !== me) return
      if (event.metaKey || (event.ctrlKey && !event.altKey) || isTextEntry(event.target)) return
      const { open: isOpen, setOpen: set, hasSidebar: has } = latest.current
      if (!has) return
      event.preventDefault()
      set(!isOpen)
    }
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      frames.splice(frames.indexOf(me), 1)
      if (activeFrame === me) activeFrame = frames[0] ?? null
    }
  }, [])

  const shownId = peekState.shownId !== null && folded ? peekState.shownId : null
  const overlay = shownId !== null && peek ? peek(shownId) : null

  const itemControl = React.useCallback((id: string) => {
    const item = microRef.current?.querySelector<HTMLElement>(`[data-micro-sidebar-id="${CSS.escape(id)}"]`)
    return item ? firstFocusable(item) : null
  }, [])

  /* While the overlay shows: Escape closes it (unless a layer opened from
     it is on top), a press outside closes it, and keyboard focus goes in
     when it was opened from the keyboard. */
  React.useEffect(() => {
    if (shownId === null) return
    const layer = pushLayer()
    const overlayEl = overlayRef.current
    if (focusOnShow.current && overlayEl) {
      focusOnShow.current = false
      const target = overlayEl.querySelector<HTMLElement>('[aria-current="page"]') ?? firstFocusable(overlayEl)
      target?.focus({ preventScroll: true })
    }
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape' || event.defaultPrevented || !isTopLayer(layer)) return
      event.preventDefault()
      const focusInside = !!overlayRef.current?.contains(document.activeElement)
      dispatch({ type: 'close' })
      if (focusInside) itemControl(shownId)?.focus({ preventScroll: true })
    }
    const onPointerDown = (event: PointerEvent) => {
      const target = event.target as Node | null
      if (!target || microRef.current?.contains(target) || inOpenLayer(target)) return
      dispatch({ type: 'close' })
    }
    const onPointerMove = (event: PointerEvent) => {
      if (event.pointerType !== 'touch') pointer.current = { x: event.clientX, y: event.clientY }
    }
    /* A layer that held the peek closed: the peek now follows the pointer
       (it stays over the peek, switches on another item, hides elsewhere).
       Read after the frame, once the closed layer is off the page. */
    let frame = 0
    const recheck = () => {
      const overlayEl = overlayRef.current
      const at = pointer.current
      if (!overlayEl || !at || layerOpenFrom(overlayEl)) return
      const under = document.elementFromPoint(at.x, at.y)
      if (under && overlayEl.contains(under)) return
      const item = under && microRef.current?.contains(under) ? under.closest<HTMLElement>('[data-micro-sidebar-id]') : null
      const focusInside = overlayEl.contains(document.activeElement)
      if (item?.dataset.microSidebarId) {
        const id = item.dataset.microSidebarId
        dispatch({ type: 'enter', id, canPeek: canPeek(id) })
        if (focusInside && !canPeek(id)) itemControl(shownId)?.focus({ preventScroll: true })
        return
      }
      dispatch({ type: 'leave', to: 'outside' })
      if (focusInside) itemControl(shownId)?.focus({ preventScroll: true })
    }
    const stopLayers = onLayersChange(() => {
      cancelAnimationFrame(frame)
      frame = requestAnimationFrame(recheck)
    })
    document.addEventListener('keydown', onKeyDown)
    document.addEventListener('pointerdown', onPointerDown, true)
    document.addEventListener('pointermove', onPointerMove, { capture: true, passive: true })
    return () => {
      cancelAnimationFrame(frame)
      stopLayers()
      removeLayer(layer)
      document.removeEventListener('keydown', onKeyDown)
      document.removeEventListener('pointerdown', onPointerDown, true)
      document.removeEventListener('pointermove', onPointerMove, { capture: true })
    }
  }, [shownId, itemControl, canPeek])

  /* Where the pointer went when it left an item or the overlay. */
  const leftFor = React.useCallback((event: React.PointerEvent<HTMLElement>): 'overlay' | 'item' | 'outside' => {
    const to = event.relatedTarget as Node | null
    if (to && overlayRef.current?.contains(to)) return 'overlay'
    const el = to instanceof Element ? to : to?.parentElement
    if (el && microRef.current?.contains(el) && el.closest('[data-micro-sidebar-id]')) return 'item'
    return 'outside'
  }, [])

  /* A menu or popover opened from inside the overlay is open: the peek
     stays while it is. */
  const held = React.useCallback(() => layerOpenFrom(overlayRef.current), [])

  const ctx = React.useMemo<AppFrameContextValue>(
    () => ({
      sidebarShown,
      hasSidebar,
      setSidebarOpen: setOpen,
      peekId: shownId,
      itemPointerEnter: (id, event) => {
        if (event.pointerType === 'touch' || event.buttons !== 0) return
        pointer.current = { x: event.clientX, y: event.clientY }
        dispatch({ type: 'enter', id, canPeek: canPeek(id), held: held() })
      },
      itemPointerLeave: (_id, event) => {
        if (event.pointerType === 'touch') return
        dispatch({ type: 'leave', to: leftFor(event), held: held() })
      },
      itemPointerDown: (id, event) => {
        if (event.pointerType === 'touch') dispatch({ type: 'open', id, canPeek: canPeek(id) })
        else dispatch({ type: 'press' })
      },
      itemKeyDown: (id, event) => {
        if (event.key !== 'ArrowRight' || !canPeek(id)) return
        event.preventDefault()
        focusOnShow.current = true
        dispatch({ type: 'open', id, canPeek: true })
        /* Shown already: the effect will not run again, so move focus here. */
        if (peekState.shownId === id && overlayRef.current) {
          focusOnShow.current = false
          const target =
            overlayRef.current.querySelector<HTMLElement>('[aria-current="page"]') ?? firstFocusable(overlayRef.current)
          target?.focus({ preventScroll: true })
        }
      },
    }),
    [sidebarShown, hasSidebar, setOpen, shownId, canPeek, leftFor, held, peekState.shownId],
  )

  const state = !hasSidebar ? 'none' : open ? 'open' : 'folded'

  return (
    <AppFrameContext.Provider value={ctx}>
      <div
        className={cx('sl-app-frame', className)}
        data-sidebar={state}
        data-reopened={reopened ? '' : undefined}
        onPointerDownCapture={(event) => {
          onPointerDownCapture?.(event)
          activeFrame = token.current
        }}
        onFocusCapture={(event) => {
          onFocusCapture?.(event)
          activeFrame = token.current
        }}
        {...props}
      >
        <WindowGround />
        <div
          ref={microRef}
          className="sl-app-frame-micro"
          onBlur={(event) => {
            /* Keyboard focus leaving the strip and the overlay ends a peek. */
            const to = event.relatedTarget as Node | null
            if (shownId === null || !overlayRef.current?.contains(event.target as Node)) return
            if (to && (microRef.current?.contains(to) || inOpenLayer(to))) return
            dispatch({ type: 'close' })
          }}
        >
          {microSidebar}
          {overlay != null ? (
            <div
              ref={overlayRef}
              className="sl-app-frame-peek"
              data-peek-id={shownId}
              onPointerLeave={(event) => {
                if (event.pointerType === 'touch') return
                dispatch({ type: 'leave', to: leftFor(event), held: held() })
              }}
            >
              {overlay}
            </div>
          ) : null}
        </div>
        <div className="sl-app-frame-sheet">
          {hasSidebar ? <div className="sl-app-frame-side">{sidebar}</div> : null}
          <div className="sl-app-frame-work">{children}</div>
        </div>
      </div>
    </AppFrameContext.Provider>
  )
}

/* ── the fold control ───────────────────────────────────────────────────── */

export interface AppFrameFoldProps extends Omit<IconActionProps, 'label' | 'children'> {}

/* The control that folds the sidebar (in the sidebar's head) and opens it
   again (placed in the microsidebar, where it shows only while the sidebar
   is folded). Inside a peek it does not show. */
function AppFrameFold({ className, onClick, ...props }: AppFrameFoldProps) {
  const frame = React.useContext(AppFrameContext)
  if (!frame) throw new Error('AppFrame.Fold must be inside an AppFrame')
  const shown = frame.sidebarShown
  return (
    <IconAction
      label={shown ? 'Fold the sidebar' : 'Open the sidebar'}
      caption="press ["
      className={cx('sl-app-frame-fold', className)}
      onClick={(event) => {
        onClick?.(event)
        if (!event.defaultPrevented) frame.setSidebarOpen(!shown)
      }}
      {...props}
    >
      <Icon name="sidebar" />
    </IconAction>
  )
}

/* Compound parts: AppFrame, AppFrame.Fold. */
export const AppFrame = Object.assign(AppFrameRoot, { Fold: AppFrameFold })
