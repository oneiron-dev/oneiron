import * as React from 'react'
import { Icon } from '../primitives/Icon'
import { IconAction } from '../primitives/IconAction'
import { cx, mergeRefs, useControllableState, useIsomorphicLayoutEffect } from '../lib/react-utils'
import { Composer } from './Composer'
import { paneBounds, paneTrack, paneWidth, thingLiesOver, thingOverWidth, thingPlaceholder, type PaneKind } from './pane-width'
import { SPLIT_MAGNETS, SPLIT_MAGNET_PULL_PX, snapToMagnet } from './snap-to-magnet'

/* Keyboard steps in CSS pixels; Shift takes the long step. */
const KEY_STEP_PX = 16
const KEY_LONG_STEP_PX = 64

interface SplitContextValue {
  /* The edge's position as the handle reports it: the first pane's share
     in percent, or the second pane's width in pixels for a pane beside
     the room. */
  position: { now: number; min: number; max: number; text: string }
  /* Moves the edge to a fraction of the width; `snap` applies the magnets
     (shares only). */
  moveTo: (fraction: number, options?: { snap?: boolean; pointerY?: number }) => void
  /* Moves the edge by a number of pixels; positive is to the right. */
  nudge: (px: number) => void
  /* Moves the edge to its left or right limit. */
  toLimit: (edge: 'left' | 'right') => void
  commit: () => void
  reset: () => void
  setDragging: (dragging: boolean) => void
  rootRef: React.RefObject<HTMLDivElement | null>
  /* The pane for one thing lies over the room (the work area is too
     narrow for the column and the pane side by side). */
  over: boolean
}

const SplitContext = React.createContext<SplitContextValue | null>(null)

function useSplit(part: string): SplitContextValue {
  const ctx = React.useContext(SplitContext)
  if (!ctx) throw new Error(`${part} must be inside SplitPane`)
  return ctx
}

const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v))

/* A remembered share (0 to 1) or pane width (in pixels, within bounds). */
function readStored(key: string | undefined, accept: (v: number) => boolean): number | undefined {
  if (!key || typeof localStorage === 'undefined') return undefined
  try {
    const raw = localStorage.getItem(key)
    const v = raw === null ? NaN : Number(raw)
    return Number.isFinite(v) && accept(v) ? v : undefined
  } catch {
    return undefined
  }
}

function writeStored(key: string | undefined, v: number | null) {
  if (!key) return
  try {
    if (v === null) localStorage.removeItem(key)
    else localStorage.setItem(key, String(Math.round(v * 10000) / 10000))
  } catch {
    /* storage full or blocked: the width is simply not remembered */
  }
}

export interface SplitPaneProps extends Omit<React.ComponentPropsWithRef<'div'>, 'defaultValue' | 'onChange'> {
  /* The first pane's share of the width, 0 to 1 (two panes that share). */
  value?: number
  defaultValue?: number
  onValueChange?: (value: number) => void
  min?: number
  max?: number
  /* Fractions the edge leans toward while dragged. */
  magnets?: readonly number[]
  /* How near, in CSS pixels, a magnet starts to pull. */
  magnetPull?: number
  /* A pane beside the room: the second pane is sized in pixels by the
     width rule (`list` 340 px; `thing` what the messages column leaves,
     380 to 680 px), and the edge drags inside those bounds. */
  pane?: PaneKind
  /* The second pane's width once dragged, in pixels; null keeps the rule. */
  paneWidth?: number | null
  defaultPaneWidth?: number | null
  onPaneWidthChange?: (width: number | null) => void
  /* A sidebar inside the split's box that the width rule leaves out, in
     pixels; 0 when the split holds only the work area. */
  sidebarWidth?: number
  /* Remembers the width on this machine under this key. */
  storageKey?: string
}

/* Two panes and the edge between them (SplitPane.Pane, SplitPane.Handle,
   SplitPane.Pane, or SplitPane.Thing as the second). Two panes that share
   the width: the edge drags free inside min and max, leans softly toward
   the magnets and shows the magnet's percentage while it is on one. A
   pane beside the room (`pane`): the room keeps the rest, the pane keeps
   its width rule until dragged. Double-click resets; arrow keys move the
   focused edge. */
function SplitPaneRoot({
  ref,
  value: valueProp,
  defaultValue = 0.5,
  onValueChange,
  min = 0.2,
  max = 0.8,
  magnets = SPLIT_MAGNETS,
  magnetPull = SPLIT_MAGNET_PULL_PX,
  pane,
  paneWidth: paneWidthProp,
  defaultPaneWidth = null,
  onPaneWidthChange,
  sidebarWidth = 0,
  storageKey,
  className,
  style,
  children,
  ...props
}: SplitPaneProps) {
  const [value, setValue] = useControllableState(valueProp, defaultValue, onValueChange)
  const [dragged, setDragged] = useControllableState<number | null>(paneWidthProp, defaultPaneWidth, onPaneWidthChange)
  const [tag, setTag] = React.useState<{ magnet: number; y: number } | null>(null)
  const [dragging, setDragging] = React.useState(false)
  const [rootWidth, setRootWidth] = React.useState(0)
  const rootRef = React.useRef<HTMLDivElement | null>(null)
  const bounds = pane ? paneBounds(pane) : null
  const current = React.useRef({ value, dragged })
  current.current = { value, dragged }

  /* Too narrow for the column beside a pane for one thing: the pane lies
     over the room, from the right edge, and the edge does not drag. */
  const over = pane === 'thing' && rootWidth > 0 && thingLiesOver(rootWidth, sidebarWidth)

  /* The pane's width now: the dragged width, else the rule on the
     measured width (the CSS track draws the same rule before measuring). */
  const width = pane && bounds ? clamp(dragged ?? paneWidth(pane, rootWidth, sidebarWidth), bounds.min, bounds.max) : 0
  const widthRef = React.useRef(width)
  widthRef.current = width

  useIsomorphicLayoutEffect(() => {
    const root = rootRef.current
    if (!pane || !root || typeof ResizeObserver === 'undefined') return
    setRootWidth(root.clientWidth)
    const observer = new ResizeObserver(() => setRootWidth(root.clientWidth))
    observer.observe(root)
    return () => observer.disconnect()
  }, [pane])

  /* A remembered width replaces the default once the page is on the client. */
  useIsomorphicLayoutEffect(() => {
    if (pane && bounds) {
      if (paneWidthProp !== undefined) return
      const stored = readStored(storageKey, (v) => v >= bounds.min && v <= bounds.max)
      if (stored !== undefined) setDragged(stored)
      return
    }
    if (valueProp !== undefined) return
    const stored = readStored(storageKey, (v) => v > 0 && v < 1)
    if (stored !== undefined) setValue(clamp(stored, min, max))
  }, [storageKey, pane])

  /* Setters that also update what commit reads in the same event. */
  const setShare = React.useCallback(
    (v: number) => {
      current.current = { ...current.current, value: v }
      setValue(v)
    },
    [setValue],
  )
  const setPaneW = React.useCallback(
    (w: number) => {
      current.current = { ...current.current, dragged: w }
      setDragged(w)
    },
    [setDragged],
  )
  const moveTo = React.useCallback<SplitContextValue['moveTo']>(
    (fraction, options = {}) => {
      const total = rootRef.current?.clientWidth ?? 0
      if (pane && bounds) {
        if (!total) return
        setPaneW(Math.round(clamp((1 - fraction) * total, bounds.min, bounds.max)))
        return
      }
      let next = fraction
      let magnet: number | null = null
      if (options.snap) ({ fraction: next, magnet } = snapToMagnet(fraction, total, magnets, magnetPull))
      next = clamp(next, min, max)
      setShare(next)
      setTag(magnet !== null && options.pointerY !== undefined ? { magnet, y: options.pointerY } : null)
    },
    [pane, bounds?.min, bounds?.max, magnets, magnetPull, min, max, setShare, setPaneW],
  )
  const nudge = React.useCallback(
    (px: number) => {
      if (pane && bounds) {
        setPaneW(clamp(widthRef.current - px, bounds.min, bounds.max))
        return
      }
      const total = rootRef.current?.clientWidth || 1
      setShare(clamp(current.current.value + px / total, min, max))
    },
    [pane, bounds?.min, bounds?.max, min, max, setShare, setPaneW],
  )
  const toLimit = React.useCallback(
    (edge: 'left' | 'right') => {
      if (pane && bounds) setPaneW(edge === 'left' ? bounds.max : bounds.min)
      else setShare(edge === 'left' ? min : max)
    },
    [pane, bounds?.min, bounds?.max, min, max, setShare, setPaneW],
  )
  const commit = React.useCallback(() => {
    setTag(null)
    writeStored(storageKey, pane ? current.current.dragged : current.current.value)
  }, [storageKey, pane])
  const reset = React.useCallback(() => {
    if (pane) {
      setDragged(null)
      writeStored(storageKey, null)
      return
    }
    const next = clamp(defaultValue, min, max)
    setValue(next)
    writeStored(storageKey, next)
  }, [pane, defaultValue, min, max, setValue, setDragged, storageKey])

  const position = React.useMemo(
    () =>
      pane && bounds
        ? { now: Math.round(width), min: bounds.min, max: bounds.max, text: `pane ${Math.round(width)} pixels wide` }
        : {
            now: Math.round(value * 100),
            min: Math.round(min * 100),
            max: Math.round(max * 100),
            text: `${Math.round(value * 100)} percent`,
          },
    [pane, bounds?.min, bounds?.max, width, value, min, max],
  )

  const ctx = React.useMemo(
    () => ({ position, moveTo, nudge, toLimit, commit, reset, setDragging, rootRef, over }),
    [position, moveTo, nudge, toLimit, commit, reset, over],
  )
  const height = rootRef.current?.clientHeight ?? 0
  const columns = over
    ? 'minmax(0, 1fr)'
    : pane
      ? `minmax(0, 1fr) 1px ${dragged === null ? paneTrack(pane, sidebarWidth) : `${width}px`}`
      : `minmax(0, ${value}fr) 1px minmax(0, ${1 - value}fr)`
  const overStyle = over ? ({ '--sl-thing-over-width': `${thingOverWidth(rootWidth, sidebarWidth)}px` } as React.CSSProperties) : undefined

  return (
    <SplitContext.Provider value={ctx}>
      <div
        ref={mergeRefs(ref, rootRef)}
        className={cx('sl-split-pane', className)}
        data-pane={pane}
        data-over={over ? '' : undefined}
        data-dragging={dragging ? '' : undefined}
        style={{ gridTemplateColumns: columns, ...overStyle, ...style }}
        {...props}
      >
        {children}
        {tag ? (
          <span
            className="sl-split-tag"
            aria-hidden="true"
            style={{ left: `calc(${value * 100}% - 12px)`, top: clamp(tag.y - 12, 8, Math.max(8, height - 30)) }}
          >
            {Math.round(tag.magnet * 100)}%
          </span>
        ) : null}
      </div>
    </SplitContext.Provider>
  )
}

export interface SplitPanePaneProps extends React.ComponentPropsWithRef<'div'> {}

function SplitPanePane({ className, ...props }: SplitPanePaneProps) {
  return <div className={cx('sl-split-pane-pane', className)} {...props} />
}

export interface SplitPaneHandleProps extends React.ComponentPropsWithRef<'div'> {}

/* The edge: drag it, double-click it to reset, or focus it and use the
   arrow keys (Shift for long steps, Home and End for the limits). */
function SplitPaneHandle({ className, onPointerDown, onKeyDown, onDoubleClick, 'aria-label': ariaLabel = 'resize', ...props }: SplitPaneHandleProps) {
  const split = useSplit('SplitPane.Handle')
  const drag = React.useRef<{ left: number; width: number } | null>(null)
  const end = (event: React.PointerEvent<HTMLDivElement>) => {
    if (!drag.current) return
    drag.current = null
    split.setDragging(false)
    try {
      event.currentTarget.releasePointerCapture(event.pointerId)
    } catch {
      /* already released */
    }
    split.commit()
  }
  return (
    <div
      role="separator"
      aria-orientation="vertical"
      aria-label={ariaLabel}
      aria-valuemin={split.position.min}
      aria-valuemax={split.position.max}
      aria-valuenow={split.position.now}
      aria-valuetext={split.position.text}
      tabIndex={0}
      className={cx('sl-split-handle', className)}
      onPointerDown={(event) => {
        onPointerDown?.(event)
        if (event.defaultPrevented || event.button !== 0) return
        const rect = split.rootRef.current?.getBoundingClientRect()
        if (!rect || !rect.width) return
        event.preventDefault()
        try {
          event.currentTarget.setPointerCapture(event.pointerId)
        } catch {
          /* capture unavailable: the drag still follows moves over the handle */
        }
        drag.current = { left: rect.left, width: rect.width }
        split.setDragging(true)
      }}
      onPointerMove={(event) => {
        const d = drag.current
        if (!d) return
        const rootTop = split.rootRef.current?.getBoundingClientRect().top ?? 0
        split.moveTo((event.clientX - d.left) / d.width, { snap: true, pointerY: event.clientY - rootTop })
      }}
      onPointerUp={end}
      onPointerCancel={end}
      onDoubleClick={(event) => {
        onDoubleClick?.(event)
        if (!event.defaultPrevented) split.reset()
      }}
      onKeyDown={(event) => {
        onKeyDown?.(event)
        if (event.defaultPrevented) return
        const step = event.shiftKey ? KEY_LONG_STEP_PX : KEY_STEP_PX
        if (event.key === 'ArrowLeft') split.nudge(-step)
        else if (event.key === 'ArrowRight') split.nudge(step)
        else if (event.key === 'Home') split.toLimit('left')
        else if (event.key === 'End') split.toLimit('right')
        else return
        event.preventDefault()
        split.commit()
      }}
      {...props}
    />
  )
}

export interface SplitPaneHeadProps extends Omit<React.ComponentPropsWithRef<'div'>, 'title'> {
  /* The pane's title, at the section size; past its lines it truncates. */
  title: React.ReactNode
  /* How many lines the title may take. */
  titleLines?: 1 | 2
  /* IconActions before the close control. */
  actions?: React.ReactNode
  /* Shows the close control (tooltip `Close`); Escape closes too while
     focus is in the pane. The caller puts focus back where the pane was
     opened from. */
  onClose?: () => void
  closeLabel?: string
}

/* The head line of a pane: its title, its actions, and the close control.
   Place it first in a SplitPane.Pane. Escape in the pane closes it unless
   another part took the key first (an undo window) or focus is in a menu
   or popover opened from the pane. */
function SplitPaneHead({ ref, title, titleLines = 1, actions, onClose, closeLabel = 'Close', className, ...props }: SplitPaneHeadProps) {
  const headRef = React.useRef<HTMLDivElement | null>(null)
  const latest = React.useRef(onClose)
  useIsomorphicLayoutEffect(() => {
    latest.current = onClose
  })
  const closes = !!onClose
  const split = React.useContext(SplitContext)
  const over = !!split?.over

  React.useEffect(() => {
    const head = headRef.current
    /* Over the room, Escape anywhere in the split closes the pane; beside
       it, Escape in the pane does. */
    const pane = (over ? head?.closest<HTMLElement>('.sl-split-pane') : null) ?? head?.closest<HTMLElement>('.sl-split-pane-pane') ?? head?.parentElement
    if (!closes || !pane) return
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape' || event.defaultPrevented || event.isComposing) return
      const target = event.target instanceof Element ? event.target : null
      if (target?.closest(':popover-open')) return
      event.preventDefault()
      latest.current?.()
    }
    pane.addEventListener('keydown', onKeyDown)
    return () => pane.removeEventListener('keydown', onKeyDown)
  }, [closes, over])

  return (
    <div ref={mergeRefs(ref, headRef)} className={cx('sl-split-head', className)} data-lines={titleLines} {...props}>
      <h2 className="sl-split-head-title">{title}</h2>
      {actions !== undefined || onClose ? (
        <div className="sl-split-head-actions">
          {actions}
          {onClose ? (
            <IconAction label={closeLabel} className="sl-split-head-close" onClick={onClose}>
              <Icon name="x" />
            </IconAction>
          ) : null}
        </div>
      ) : null}
    </div>
  )
}

export interface SplitPaneThingProps extends Omit<React.ComponentPropsWithRef<'div'>, 'title'> {
  /* The thing's title: up to two lines at the section size. */
  title: React.ReactNode
  /* Shows the close control; Escape in the pane closes too. */
  onClose?: () => void
  /* The thing's note, as text under the thing. */
  note?: React.ReactNode
  /* The thread on the thing: its message rows, as an array. With none the
     write box asks to write about the thing; with some, to reply. */
  thread?: React.ReactNode
  /* The text written at the foot; the caller starts or continues the thread. */
  onSend?: (text: string) => void
  /* Further head actions before close. */
  actions?: React.ReactNode
}

/* The pane for one thing, opened beside the room: the head (the title and
   close), a scrolling body (the thing itself with no card frame, its note,
   then its thread under a hairline), and at the foot, outside the scroll,
   the small write box. Place it second in a SplitPane with pane="thing".
   In a work area too narrow for the column and the pane side by side it
   lies over the room from the right edge instead. */
function SplitPaneThing({ title, onClose, note, thread, onSend, actions, className, children, ...props }: SplitPaneThingProps) {
  const hasThread = React.Children.toArray(thread).length > 0
  const placeholder = thingPlaceholder(hasThread)
  return (
    <div className={cx('sl-split-pane-pane sl-split-thing', className)} data-thread={hasThread ? '' : undefined} {...props}>
      <SplitPaneHead title={title} titleLines={2} onClose={onClose} actions={actions} className="sl-split-thing-head" />
      <div className="sl-split-thing-body">
        <div className="sl-split-thing-item">{children}</div>
        {note !== undefined ? <div className="sl-split-thing-note">{note}</div> : null}
        {hasThread ? <div className="sl-split-thing-thread">{thread}</div> : null}
      </div>
      <Composer size="small" className="sl-split-thing-write" placeholder={placeholder} onSend={(text) => onSend?.(text)} />
    </div>
  )
}

/* Compound parts: SplitPane, .Pane, .Handle, .Head, .Thing. */
export const SplitPane = Object.assign(SplitPaneRoot, {
  Pane: SplitPanePane,
  Handle: SplitPaneHandle,
  Head: SplitPaneHead,
  Thing: SplitPaneThing,
})
