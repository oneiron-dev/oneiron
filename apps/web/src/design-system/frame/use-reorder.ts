import * as React from 'react'
import { flushSync } from 'react-dom'
import { useIsomorphicLayoutEffect } from '../lib/react-utils'
import { dropIndex, leadingEdge, moveItem, shiftFor } from './reorder'

/* Pointer travel before a press becomes a drag; below it a press stays a
   click. */
const DRAG_THRESHOLD_PX = 4

export interface ReorderOptions {
  /* The attribute that marks an item (a direct child of the container) and
     holds its id. */
  itemAttribute: string
  /* Where a drag may start inside an item; the whole item when absent. A
     keyboard move also starts only from inside this part. */
  handle?: string
  /* Reordering is on only with a handler. */
  onReorder?: (ids: string[]) => void
  /* Says a move in words (for a live region). */
  announce?: (message: string) => void
}

interface Gesture {
  pointerId: number
  startY: number
  items: HTMLElement[]
  ids: string[]
  from: number
  to: number
  midpoints: number[]
  /* The dragged item's height, and its height plus the gap after it. */
  height: number
  size: number
  minDy: number
  maxDy: number
  active: boolean
}

const reducedMotion = () => typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches

function itemsOf(container: HTMLElement, attribute: string): HTMLElement[] {
  return [...container.children].filter((el): el is HTMLElement => el instanceof HTMLElement && el.hasAttribute(attribute))
}

function labelOf(item: HTMLElement): string {
  return item.dataset.reorderLabel || item.textContent?.trim() || 'item'
}

/* Lets a person reorder the items of one container: drag an item (or its
   handle) with a mouse or pen, or press Alt+ArrowUp / Alt+ArrowDown on a
   focused item. While dragging, the item itself follows the pointer by
   transform and its neighbours slide to open the gap; there is no ghost
   image. On release the new order goes to `onReorder`; the caller renders
   it. Escape cancels a drag. */
export function useReorder<T extends HTMLElement>({ itemAttribute, handle, onReorder, announce }: ReorderOptions) {
  const containerRef = React.useRef<T | null>(null)
  const gesture = React.useRef<Gesture | null>(null)
  const latest = React.useRef({ onReorder, announce })
  useIsomorphicLayoutEffect(() => {
    latest.current = { onReorder, announce }
  })
  const enabled = !!onReorder

  const clear = React.useCallback((animate: boolean) => {
    const g = gesture.current
    const container = containerRef.current
    gesture.current = null
    if (!g || !container) return
    if (!animate) delete container.dataset.reorderActive
    for (const item of g.items) {
      item.style.transform = ''
      delete item.dataset.dragging
    }
    if (animate) {
      /* Let the neighbours slide home, then drop the transition. */
      const done = () => {
        if (!gesture.current) delete container.dataset.reorderActive
      }
      if (reducedMotion()) done()
      else setTimeout(done, 160)
    }
    document.documentElement.style.removeProperty('user-select')
  }, [])

  const commit = React.useCallback(
    (ids: string[], from: number, to: number, item: HTMLElement | null) => {
      const { onReorder: report, announce: say } = latest.current
      if (!report || from === to) return
      const next = moveItem(ids, from, to)
      const focused = document.activeElement as HTMLElement | null
      /* Render the new order before the browser paints, so the cleared
         transforms never show the old one. */
      flushSync(() => report(next))
      if (focused && document.activeElement !== focused && focused.isConnected) focused.focus({ preventScroll: true })
      if (item) say?.(`${labelOf(item)}, moved to ${to + 1} of ${ids.length}`)
    },
    [],
  )

  const onPointerMove = React.useCallback((event: PointerEvent) => {
    const g = gesture.current
    if (!g || event.pointerId !== g.pointerId) return
    const raw = event.clientY - g.startY
    if (!g.active) {
      if (Math.abs(raw) < DRAG_THRESHOLD_PX) return
      g.active = true
      containerRef.current!.dataset.reorderActive = ''
      g.items[g.from].dataset.dragging = ''
      document.documentElement.style.setProperty('user-select', 'none')
      getSelection()?.removeAllRanges()
    }
    event.preventDefault()
    const dy = Math.max(g.minDy, Math.min(g.maxDy, raw))
    const dragged = g.items[g.from]
    dragged.style.transform = `translateY(${dy}px)`
    g.to = dropIndex(g.midpoints, g.from, leadingEdge(g.midpoints[g.from], g.height, dy))
    g.items.forEach((item, j) => {
      if (j === g.from) return
      const shift = shiftFor(j, g.from, g.to, g.size)
      item.style.transform = shift ? `translateY(${shift}px)` : ''
    })
  }, [])

  const stopListening = React.useRef<() => void>(() => {})

  const onPointerUp = React.useCallback(
    (event: PointerEvent) => {
      const g = gesture.current
      if (!g || event.pointerId !== g.pointerId) return
      stopListening.current()
      if (!g.active) {
        gesture.current = null
        return
      }
      /* The press that ended a drag is not a click on the item. */
      const swallow = (e: MouseEvent) => {
        e.preventDefault()
        e.stopPropagation()
      }
      window.addEventListener('click', swallow, { capture: true, once: true })
      setTimeout(() => window.removeEventListener('click', swallow, { capture: true }), 0)
      const { ids, from, to } = g
      const item = g.items[from]
      if (from === to) {
        clear(true)
        return
      }
      clear(false)
      commit(ids, from, to, item)
    },
    [clear, commit],
  )

  const onKeyCancel = React.useCallback(
    (event: KeyboardEvent) => {
      if (event.key !== 'Escape' || !gesture.current?.active) return
      event.preventDefault()
      event.stopPropagation()
      stopListening.current()
      clear(true)
    },
    [clear],
  )

  React.useEffect(() => () => stopListening.current(), [])

  const onPointerDown = React.useCallback(
    (event: React.PointerEvent<T>) => {
      const container = containerRef.current
      if (!enabled || !container || event.button !== 0 || event.pointerType === 'touch') return
      if (gesture.current) return
      const target = event.target as HTMLElement
      const items = itemsOf(container, itemAttribute)
      const item = items.find((el) => el.contains(target))
      if (!item) return
      if (handle && !target.closest(handle)) return
      /* A press on a control inside the row that is not the row itself (a
         pin) never starts a drag. */
      if (target.closest('[data-reorder-ignore]')) return
      const rects = items.map((el) => el.getBoundingClientRect())
      const from = items.indexOf(item)
      const r = rects[from]
      const next = rects[from + 1]
      const previous = rects[from - 1]
      const gap = next ? next.top - r.bottom : previous ? r.top - previous.bottom : 0
      gesture.current = {
        pointerId: event.pointerId,
        startY: event.clientY,
        items,
        ids: items.map((el) => el.getAttribute(itemAttribute) ?? ''),
        from,
        to: from,
        midpoints: rects.map((rect) => rect.top + rect.height / 2),
        height: r.height,
        size: r.height + gap,
        minDy: rects[0].top - r.top,
        maxDy: rects[rects.length - 1].bottom - r.bottom,
        active: false,
      }
      window.addEventListener('pointermove', onPointerMove, { passive: false })
      window.addEventListener('pointerup', onPointerUp)
      window.addEventListener('pointercancel', onPointerUp)
      window.addEventListener('keydown', onKeyCancel, true)
      stopListening.current = () => {
        window.removeEventListener('pointermove', onPointerMove)
        window.removeEventListener('pointerup', onPointerUp)
        window.removeEventListener('pointercancel', onPointerUp)
        window.removeEventListener('keydown', onKeyCancel, true)
        stopListening.current = () => {}
      }
    },
    [enabled, itemAttribute, handle, onPointerMove, onPointerUp, onKeyCancel],
  )

  const onKeyDown = React.useCallback(
    (event: React.KeyboardEvent<T>) => {
      const container = containerRef.current
      if (!enabled || !container || event.defaultPrevented) return
      if (!event.altKey || (event.key !== 'ArrowUp' && event.key !== 'ArrowDown')) return
      const target = event.target as HTMLElement
      if (handle && !target.closest(handle)) return
      const items = itemsOf(container, itemAttribute)
      const item = items.find((el) => el.contains(target))
      if (!item) return
      event.preventDefault()
      const from = items.indexOf(item)
      const to = Math.max(0, Math.min(items.length - 1, from + (event.key === 'ArrowUp' ? -1 : 1)))
      commit(
        items.map((el) => el.getAttribute(itemAttribute) ?? ''),
        from,
        to,
        item,
      )
    },
    [enabled, itemAttribute, handle, commit],
  )

  /* A native drag would draw a ghost image of a link; the reorder replaces it. */
  const onDragStart = React.useCallback(
    (event: React.DragEvent<T>) => {
      if (enabled) event.preventDefault()
    },
    [enabled],
  )

  return { containerRef, enabled, containerProps: { onPointerDown, onKeyDown, onDragStart } }
}
