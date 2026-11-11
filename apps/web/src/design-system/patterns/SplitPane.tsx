import * as React from 'react'
import { Icon } from '../primitives/Icon'
import { IconAction } from '../primitives/IconAction'
import { cx, mergeRefs, useControllableState, useIsomorphicLayoutEffect } from '../lib/react-utils'
import { SPLIT_MAGNETS, SPLIT_MAGNET_PULL_PX, snapToMagnet } from './snap-to-magnet'

/* Keyboard steps in CSS pixels; Shift takes the long step. */
const KEY_STEP_PX = 16
const KEY_LONG_STEP_PX = 64

interface SplitContextValue {
  value: number
  min: number
  max: number
  /* Moves the edge to a fraction; `snap` applies the magnets. */
  moveTo: (fraction: number, options?: { snap?: boolean; pointerY?: number }) => void
  commit: () => void
  reset: () => void
  setDragging: (dragging: boolean) => void
  rootRef: React.RefObject<HTMLDivElement | null>
}

const SplitContext = React.createContext<SplitContextValue | null>(null)

function useSplit(part: string): SplitContextValue {
  const ctx = React.useContext(SplitContext)
  if (!ctx) throw new Error(`${part} must be inside SplitPane`)
  return ctx
}

const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v))

function readStored(key: string | undefined): number | undefined {
  if (!key || typeof localStorage === 'undefined') return undefined
  try {
    const v = Number(localStorage.getItem(key))
    return Number.isFinite(v) && v > 0 && v < 1 ? v : undefined
  } catch {
    return undefined
  }
}

export interface SplitPaneProps extends Omit<React.ComponentPropsWithRef<'div'>, 'defaultValue' | 'onChange'> {
  /* The first pane's share of the width, 0 to 1. */
  value?: number
  defaultValue?: number
  onValueChange?: (value: number) => void
  min?: number
  max?: number
  /* Fractions the edge leans toward while dragged. */
  magnets?: readonly number[]
  /* How near, in CSS pixels, a magnet starts to pull. */
  magnetPull?: number
  /* Remembers the width on this machine under this key. */
  storageKey?: string
}

/* Two panes and the edge between them (SplitPane.Pane, SplitPane.Handle,
   SplitPane.Pane). The edge drags free inside min and max, leans softly
   toward the magnets and shows the magnet's percentage while it is on
   one. Double-click resets; arrow keys move the focused edge. */
function SplitPaneRoot({
  ref,
  value: valueProp,
  defaultValue = 0.5,
  onValueChange,
  min = 0.2,
  max = 0.8,
  magnets = SPLIT_MAGNETS,
  magnetPull = SPLIT_MAGNET_PULL_PX,
  storageKey,
  className,
  style,
  children,
  ...props
}: SplitPaneProps) {
  const [value, setValue] = useControllableState(valueProp, defaultValue, onValueChange)
  const [tag, setTag] = React.useState<{ magnet: number; y: number } | null>(null)
  const [dragging, setDragging] = React.useState(false)
  const rootRef = React.useRef<HTMLDivElement | null>(null)
  const valueRef = React.useRef(value)
  valueRef.current = value

  /* A remembered width replaces the default once the page is on the client. */
  useIsomorphicLayoutEffect(() => {
    if (valueProp !== undefined) return
    const stored = readStored(storageKey)
    if (stored !== undefined) setValue(clamp(stored, min, max))
  }, [storageKey])

  const store = React.useCallback(
    (v: number) => {
      if (!storageKey) return
      try {
        localStorage.setItem(storageKey, String(Math.round(v * 10000) / 10000))
      } catch {
        /* storage full or blocked: the width is simply not remembered */
      }
    },
    [storageKey],
  )

  const moveTo = React.useCallback<SplitContextValue['moveTo']>(
    (fraction, options = {}) => {
      const width = rootRef.current?.clientWidth ?? 0
      let next = fraction
      let magnet: number | null = null
      if (options.snap) ({ fraction: next, magnet } = snapToMagnet(fraction, width, magnets, magnetPull))
      next = clamp(next, min, max)
      setValue(next)
      setTag(magnet !== null && options.pointerY !== undefined ? { magnet, y: options.pointerY } : null)
    },
    [magnets, magnetPull, min, max, setValue],
  )
  const commit = React.useCallback(() => {
    setTag(null)
    store(valueRef.current)
  }, [store])
  const reset = React.useCallback(() => {
    const next = clamp(defaultValue, min, max)
    setValue(next)
    store(next)
  }, [defaultValue, min, max, setValue, store])

  const ctx = React.useMemo(
    () => ({ value, min, max, moveTo, commit, reset, setDragging, rootRef }),
    [value, min, max, moveTo, commit, reset],
  )
  const height = rootRef.current?.clientHeight ?? 0

  return (
    <SplitContext.Provider value={ctx}>
      <div
        ref={mergeRefs(ref, rootRef)}
        className={cx('sl-split-pane', className)}
        data-dragging={dragging ? '' : undefined}
        style={{ gridTemplateColumns: `minmax(0, ${value}fr) 1px minmax(0, ${1 - value}fr)`, ...style }}
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
      aria-valuemin={Math.round(split.min * 100)}
      aria-valuemax={Math.round(split.max * 100)}
      aria-valuenow={Math.round(split.value * 100)}
      aria-valuetext={`${Math.round(split.value * 100)} percent`}
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
        const width = split.rootRef.current?.clientWidth || 1
        const step = (event.shiftKey ? KEY_LONG_STEP_PX : KEY_STEP_PX) / width
        let next: number
        if (event.key === 'ArrowLeft') next = split.value - step
        else if (event.key === 'ArrowRight') next = split.value + step
        else if (event.key === 'Home') next = split.min
        else if (event.key === 'End') next = split.max
        else return
        event.preventDefault()
        split.moveTo(next)
        split.commit()
      }}
      {...props}
    />
  )
}

export interface SplitPaneHeadProps extends Omit<React.ComponentPropsWithRef<'div'>, 'title'> {
  /* The pane's title, at the section size; it truncates, never wraps. */
  title: React.ReactNode
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
function SplitPaneHead({ ref, title, actions, onClose, closeLabel = 'Close', className, ...props }: SplitPaneHeadProps) {
  const headRef = React.useRef<HTMLDivElement | null>(null)
  const latest = React.useRef(onClose)
  useIsomorphicLayoutEffect(() => {
    latest.current = onClose
  })
  const closes = !!onClose

  React.useEffect(() => {
    const head = headRef.current
    const pane = head?.closest<HTMLElement>('.sl-split-pane-pane') ?? head?.parentElement
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
  }, [closes])

  return (
    <div ref={mergeRefs(ref, headRef)} className={cx('sl-split-head', className)} {...props}>
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

/* Compound parts: SplitPane, .Pane, .Handle, .Head. */
export const SplitPane = Object.assign(SplitPaneRoot, {
  Pane: SplitPanePane,
  Handle: SplitPaneHandle,
  Head: SplitPaneHead,
})
