import * as React from 'react'
import { createPortal } from 'react-dom'

/* ── select anything → one small toolbar over the words (OF-248): one atom
   for every page. the room's `quote`, the notes' `hand to` and `cite` are
   the same thing on screen; the page decides the verbs, this decides the
   place. it rides above the words, flips under them when there is no room
   over the top edge, and both edges of the viewport hold it in. ── */
export type SelPlace = { x: number; y: number; below: boolean; text: string; range: Range }

export function useSelTools(root: React.RefObject<HTMLElement | null>, opts: { min?: number } = {}) {
  const { min = 1 } = opts
  const [sel, setSel] = React.useState<SelPlace | null>(null)
  /* the page calls raise on its root's mouseup (and on keyboard picks) */
  const raise = React.useCallback(() => {
    const s = getSelection()
    const r0 = root.current
    if (!s || s.rangeCount === 0 || s.isCollapsed || !r0) return setSel(null)
    const range = s.getRangeAt(0)
    if (!r0.contains(range.commonAncestorContainer)) return setSel(null)
    const text = range.toString()
    if (text.trim().length < min) return setSel(null)
    const rect = range.getBoundingClientRect()
    /* words scrolled out of the root's box or the viewport take the toolbar with them */
    const box = r0.getBoundingClientRect()
    if (rect.bottom < Math.max(box.top, 0) || rect.top > Math.min(box.bottom, innerHeight)) return setSel(null)
    const below = rect.top < 88
    const margin = 185 /* half the toolbar, so neither edge clips it */
    setSel({
      x: Math.min(Math.max(rect.left + rect.width / 2, margin), innerWidth - margin),
      y: below ? rect.bottom : rect.top,
      below,
      text,
      range,
    })
  }, [root, min])
  /* the caret leaves → the toolbar goes; the page moves → it follows */
  React.useEffect(() => {
    if (!sel) return
    const onSel = () => {
      const s = getSelection()
      if (!s || s.isCollapsed) setSel(null)
    }
    document.addEventListener('selectionchange', onSel)
    addEventListener('scroll', raise, true)
    addEventListener('resize', raise)
    return () => {
      document.removeEventListener('selectionchange', onSel)
      removeEventListener('scroll', raise, true)
      removeEventListener('resize', raise)
    }
  }, [sel, raise])
  const clear = React.useCallback(() => {
    getSelection()?.removeAllRanges()
    setSel(null)
  }, [])
  return { sel, raise, clear, dismiss: () => setSel(null) }
}

/* the element the picked words sit in, by selector (null when the pick
   straddles two of them: a quote points at one message, never at two) */
export function selWithin(range: Range, selector: string): HTMLElement | null {
  const el = (n: Node) => (n instanceof HTMLElement ? n : n.parentElement)?.closest<HTMLElement>(selector) ?? null
  const a = el(range.startContainer)
  const b = el(range.endContainer)
  return a && a === b ? a : null
}

export function SelTools({ sel, label = 'the words you picked', children }: { sel: SelPlace; label?: string; children: React.ReactNode }) {
  return createPortal(
    <div
      className={sel.below ? 'doc-seltools below' : 'doc-seltools'}
      role="toolbar"
      aria-label={label}
      style={{ left: sel.x, top: sel.y }}
      onMouseDown={(e) => e.preventDefault() /* keep the selection */}
    >
      {children}
    </div>,
    document.body,
  )
}
