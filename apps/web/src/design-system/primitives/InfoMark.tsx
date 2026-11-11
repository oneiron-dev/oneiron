import * as React from 'react'
import { Icon } from './Icon'
import { hideLayer, showLayer } from '../lib/layer'
import { INFO_NOTE_DELAY_MS, placeInfoNote } from '../lib/info-note'
import { soundPress } from '../lib/press'
import { cx, mergeRefs, useControllableState, useIsomorphicLayoutEffect, useSafeId } from '../lib/react-utils'

export interface InfoMarkProps extends Omit<React.ComponentPropsWithRef<'button'>, 'aria-label'> {
  /* The short note shown beside the block on rest or focus. */
  note: React.ReactNode
  /* Pressing the mark: the caller opens the whole thing beside the room. */
  onOpen?: () => void
  /* The mark's accessible name. */
  label?: string
  /* The note shows. */
  open?: boolean
  defaultOpen?: boolean
  onOpenChange?: (open: boolean) => void
}

/* The block a mark measures against: the nearest element marked with
   data-info-block, else the mark's parent. */
function blockOf(mark: HTMLElement): HTMLElement {
  return mark.closest<HTMLElement>('[data-info-block]') ?? mark.parentElement ?? mark
}

/* The right edge of the area the block sits in: its nearest scrolling or
   clipping ancestor, within the viewport. */
function boundsRightOf(block: HTMLElement, viewportWidth: number): number {
  for (let el = block.parentElement; el && el !== document.body; el = el.parentElement) {
    const style = getComputedStyle(el)
    if (style.overflowX !== 'visible' || style.overflowY !== 'visible') {
      return Math.min(el.getBoundingClientRect().right, viewportWidth)
    }
  }
  return viewportWidth
}

/* The letter i in a ring, at the size of an IconAction. Resting the
   pointer on it, or keyboard focus, shows a short note after a delay; the
   note hides at once on leave, blur, press and Escape. Pressing the mark
   calls onOpen. The note is a layer in the top layer, so the row never
   moves: to the right of the block the mark sits in when 350 px is free
   there, otherwise under the mark. */
export function InfoMark({
  ref,
  note,
  onOpen,
  label = 'About this',
  open: openProp,
  defaultOpen = false,
  onOpenChange,
  className,
  type = 'button',
  onClick,
  onPointerEnter,
  onPointerLeave,
  onPointerDown,
  onFocus,
  onBlur,
  onKeyDown,
  ...props
}: InfoMarkProps) {
  const [open, setOpen] = useControllableState(openProp, defaultOpen, onOpenChange)
  const markRef = React.useRef<HTMLButtonElement | null>(null)
  const noteRef = React.useRef<HTMLDivElement | null>(null)
  const timer = React.useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const noteId = useSafeId('sl-info-note')

  const schedule = () => {
    clearTimeout(timer.current)
    timer.current = setTimeout(() => setOpen(true), INFO_NOTE_DELAY_MS)
  }
  const hide = () => {
    clearTimeout(timer.current)
    setOpen(false)
  }
  React.useEffect(() => () => clearTimeout(timer.current), [])

  useIsomorphicLayoutEffect(() => {
    const layer = noteRef.current
    const mark = markRef.current
    if (!open || !layer || !mark) return
    showLayer(layer)
    const place = () => {
      const viewport = { width: document.documentElement.clientWidth || innerWidth, height: innerHeight }
      const block = blockOf(mark)
      const m = mark.getBoundingClientRect()
      const b = block.getBoundingClientRect()
      const first = placeInfoNote(m, b, boundsRightOf(block, viewport.width))
      /* Set the width first: the height follows from it. */
      layer.style.width = `${first.width}px`
      const p = placeInfoNote(m, b, boundsRightOf(block, viewport.width), layer.offsetHeight, viewport)
      layer.style.left = `${p.left}px`
      layer.style.top = `${p.top}px`
      layer.dataset.side = p.side
    }
    place()
    let alive = true
    let frame = 0
    const follow = () => {
      cancelAnimationFrame(frame)
      frame = requestAnimationFrame(place)
    }
    document.fonts?.ready.then(() => alive && place())
    addEventListener('scroll', follow, { capture: true, passive: true })
    addEventListener('resize', follow)
    return () => {
      alive = false
      cancelAnimationFrame(frame)
      removeEventListener('scroll', follow, { capture: true })
      removeEventListener('resize', follow)
      hideLayer(layer)
    }
  }, [open])

  return (
    <>
      <button
        ref={mergeRefs(ref, markRef)}
        type={type}
        aria-label={label}
        aria-describedby={open ? noteId : undefined}
        className={cx('sl-icon-action sl-info-mark', className)}
        data-size="md"
        data-tone="plain"
        data-open={open ? '' : undefined}
        onPointerEnter={(event) => {
          onPointerEnter?.(event)
          if (event.pointerType !== 'touch') schedule()
        }}
        onPointerLeave={(event) => {
          onPointerLeave?.(event)
          hide()
        }}
        onPointerDown={(event) => {
          onPointerDown?.(event)
          hide()
        }}
        onFocus={(event) => {
          onFocus?.(event)
          if (event.currentTarget.matches(':focus-visible')) schedule()
        }}
        onBlur={(event) => {
          onBlur?.(event)
          hide()
        }}
        onKeyDown={(event) => {
          onKeyDown?.(event)
          if (event.key === 'Escape' && open) hide()
        }}
        onClick={(event) => {
          onClick?.(event)
          if (event.defaultPrevented) return
          hide()
          soundPress(event)
          onOpen?.()
        }}
        {...props}
      >
        <Icon name="info" />
      </button>
      <div ref={noteRef} id={noteId} popover="manual" role="tooltip" className="sl-info-note">
        {note}
      </div>
    </>
  )
}
