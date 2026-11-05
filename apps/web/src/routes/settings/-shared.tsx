import * as React from 'react'
import { Chevron } from '~/components/safelight/icons'
import { cue } from '~/components/safelight/hooks'

/* ── the settings area · shared bits (ruling 8) ──
   the clock and day every act settles on, the genesis seal, the folding
   section head, the pane head with its quick search + (?), the ledger
   hook (TanStack-Table-shaped column defs, hand-rolled), the fold under
   a row, and the esc ladder the layout walks. ── */

export const CLOCK = '14:07'
export const TODAY = '2026-08-15'
export const VAULT_NAME = 'antevon'

/* ── esc ladder (spec §2): the layout owns Escape. a page registers each
   thing it can have open; the layout closes the first open one, and only
   when nothing is open does it walk back to the app. ── */
export type EscLayer = { isOpen: () => boolean; close: () => void; order: () => number }
export const EscLayers = React.createContext<React.MutableRefObject<Set<EscLayer>> | null>(null)

/* the newest thing closes first: each layer stamps a tick when it opens,
   and the layout closes the highest stamp it finds open */
let escTick = 0

export function useEscLayer(isOpen: boolean, close: () => void) {
  const ref = React.useContext(EscLayers)
  const state = React.useRef({ isOpen, close })
  state.current = { isOpen, close }
  const opened = React.useRef(0)
  React.useEffect(() => {
    if (isOpen) opened.current = ++escTick
  }, [isOpen])
  React.useEffect(() => {
    if (!ref) return
    const set = ref.current
    const layer: EscLayer = {
      isOpen: () => state.current.isOpen,
      close: () => state.current.close(),
      order: () => opened.current,
    }
    set.add(layer)
    return () => {
      set.delete(layer)
    }
  }, [ref])
}

/* ── the genesis seal: a 7×7 kakuin pressed from the vault's name. mirrored
   glyph from an fnv hash of "antevon-ops", ~14% dropout as the pressure
   texture. pure, so SSR and the client press the same stamp. ── */
function fnv(s: string) {
  let h = 2166136261
  for (const c of s) {
    h ^= c.charCodeAt(0)
    h = Math.imul(h, 16777619)
  }
  return h >>> 0
}
function prng(seed: number) {
  return () => {
    seed = Math.imul(seed ^ (seed >>> 15), seed | 1)
    seed ^= seed + Math.imul(seed ^ (seed >>> 7), seed | 61)
    return ((seed ^ (seed >>> 14)) >>> 0) / 4294967296
  }
}
function sealCells(key: string): boolean[] {
  const r = prng(fnv(key))
  const G = 4
  const H = 7
  const half: boolean[] = []
  for (let i = 0; i < G * H; i++) half.push(r() > 0.34)
  const cells: boolean[] = []
  for (let y = 0; y < H; y++)
    for (let x = 0; x < 7; x++) {
      const mx = x < G ? x : 6 - x
      cells.push(half[y * G + mx] && r() > 0.14)
    }
  return cells
}
const SEAL = sealCells('antevon-ops')

export const HASH_GROUPS = ['a7f3', '9c21', '4b8e', '0d55', '6e12', '33af', '90c4', '7b1d']
export const HASH_FULL = HASH_GROUPS.join('')
export const HASH_SHORT = `${HASH_GROUPS[0]}…${HASH_GROUPS[HASH_GROUPS.length - 1]}`

export function GenesisSeal() {
  return (
    <svg
      className="seal-genesis"
      viewBox="0 0 7 7"
      width="28"
      height="28"
      shapeRendering="crispEdges"
      role="img"
      aria-label="genesis seal"
    >
      <title>genesis seal · pressed from the first block · the same stamp lands on every receipt, pack and export</title>
      {SEAL.map((on, i) =>
        on ? <rect key={i} x={i % 7} y={Math.floor(i / 7)} width="1" height="1" fill="currentColor" /> : null,
      )}
    </svg>
  )
}

/* ── a section head that folds in place (rule 10): serif 15.5/550, the
   chevron on hover, the count only when closed, no rule under it ── */
export function Sec({
  label,
  title,
  meta,
  children,
}: {
  label: string
  title: string
  meta?: React.ReactNode
  children: React.ReactNode
}) {
  const [closed, setClosed] = React.useState(false)
  const toggle = () => {
    setClosed((c) => !c)
    cue('toggle')
  }
  return (
    <section className={closed ? 'bundle closed' : 'bundle'} aria-label={label}>
      <div
        className="head"
        tabIndex={0}
        role="button"
        aria-expanded={!closed}
        onClick={(e) => {
          if ((e.target as HTMLElement).closest('a, button, input')) return
          toggle()
        }}
        onKeyDown={(e) => {
          if ((e.key === 'Enter' || e.key === ' ') && e.target === e.currentTarget) {
            e.preventDefault()
            toggle()
          }
        }}
      >
        <span className="title">{title}</span>
        <span className="fold-hint" aria-hidden="true">
          <Chevron ariaHidden={false} />
        </span>
        {meta}
      </div>
      <div className="body">{children}</div>
    </section>
  )
}

/* ── the pane head: h1 = the section name; tools right = quick search
   (only where the page has a ledger) + the (?) in plain serif ── */
export function PaneHead({
  title,
  hint,
  search,
  meta,
  tools,
  children,
}: {
  title: string
  hint: string
  search?: {
    value: string
    onChange: (v: string) => void
    onKeyDown?: React.KeyboardEventHandler<HTMLInputElement>
    placeholder?: string
  }
  meta?: React.ReactNode
  tools?: React.ReactNode
  children?: React.ReactNode
}) {
  const [open, setOpen] = React.useState(false)
  useEscLayer(open, () => setOpen(false))
  const id = `why-${title.replace(/\W+/g, '-')}`
  return (
    <>
      <div className="pane-head">
        <h1>{title.charAt(0).toUpperCase() + title.slice(1)}</h1>
        {meta}
        <span className="pane-tools">
          {tools}
          {search && (
            <input
              className="qsearch"
              type="search"
              value={search.value}
              placeholder={search.placeholder ?? 'search'}
              aria-label={`search ${title}`}
              onChange={(e) => search.onChange(e.target.value)}
              onKeyDown={search.onKeyDown}
            />
          )}
          <button
            className="hint-btn"
            aria-expanded={open}
            aria-controls={id}
            title="what this page is"
            onClick={() => {
              setOpen((o) => !o)
              cue('toggle')
            }}
          >
            ?
          </button>
        </span>
      </div>
      <div className="dial-why" id={id} hidden={!open}>
        <span className="why-voice">{hint}</span>
      </div>
      {children}
    </>
  )
}

/* ── the ledger (rule 2): TanStack-Table-shaped column defs, sorting
   asc → desc → off with a small mono arrow, quick search, ↑/↓ moves the
   selection, Enter unfolds, Esc clears. hand-rolled, no dependency. ── */
export type Col<T> = {
  id: string
  header: string
  accessor?: (row: T) => string | number
  sortingFn?: (a: T, b: T) => number
  size?: number
  align?: 'left' | 'right' | 'center'
  className?: string
  sortable?: boolean
}
export type SortState = { id: string; desc: boolean } | null

export function useLedger<T>({
  rows,
  columns,
  getId,
  searchable,
  filter,
  initialSort = null,
}: {
  rows: T[]
  columns: Col<T>[]
  getId: (row: T) => string
  searchable: (row: T) => string
  filter?: (row: T) => boolean
  initialSort?: SortState
}) {
  const [sort, setSort] = React.useState<SortState>(initialSort)
  const [query, setQuery] = React.useState('')
  const [sel, setSel] = React.useState<string | null>(null)
  const [open, setOpen] = React.useState<string | null>(null)

  const toggleSort = React.useCallback((id: string) => {
    setSort((s) => (!s || s.id !== id ? { id, desc: false } : s.desc ? null : { id, desc: true }))
    cue('toggle')
  }, [])

  const view = React.useMemo(() => {
    const q = query.trim().toLowerCase()
    let out = rows.filter((r) => (filter ? filter(r) : true) && (!q || searchable(r).toLowerCase().includes(q)))
    if (sort) {
      const col = columns.find((c) => c.id === sort.id)
      if (col) {
        const fn =
          col.sortingFn ??
          ((a: T, b: T) => {
            const av = col.accessor ? col.accessor(a) : ''
            const bv = col.accessor ? col.accessor(b) : ''
            if (typeof av === 'number' && typeof bv === 'number') return av - bv
            return String(av).localeCompare(String(bv), undefined, { numeric: true, sensitivity: 'base' })
          })
        out = [...out].sort((a, b) => (sort.desc ? -fn(a, b) : fn(a, b)))
      }
    }
    return out
  }, [rows, columns, sort, query, filter, searchable])

  /* row click = select + unfold UNDER it (rule 7). the click also hands
     the keyboard to the ledger, so ↑/↓ walk on from the row you touched */
  const clickRow = React.useCallback((id: string, e?: React.SyntheticEvent) => {
    setSel(id)
    setOpen((o) => (o === id ? null : id))
    cue('toggle')
    const wrap = (e?.currentTarget as HTMLElement | undefined)?.closest?.('.ledger-wrap') as HTMLElement | null
    if (wrap && !wrap.contains(document.activeElement)) wrap.focus({ preventScroll: true })
  }, [])

  const onKeyDown = React.useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        if (!view.length) return
        e.preventDefault()
        const ids = view.map(getId)
        const i = sel ? ids.indexOf(sel) : -1
        const next = e.key === 'ArrowDown' ? Math.min(ids.length - 1, i + 1) : Math.max(0, i < 0 ? 0 : i - 1)
        setSel(ids[next])
        cue('toggle')
      } else if (e.key === 'Enter' && sel && !(e.target as HTMLElement).closest('a, button')) {
        e.preventDefault()
        setOpen((o) => (o === sel ? null : sel))
        cue('toggle')
      }
    },
    [view, sel, getId],
  )

  const clear = React.useCallback(() => {
    setOpen(null)
    setSel(null)
  }, [])
  useEscLayer(!!open || !!sel, clear)

  return { view, sort, toggleSort, query, setQuery, sel, setSel, open, setOpen, clickRow, onKeyDown, clear }
}

/* the column heads: click sorts; the arrow shows the state */
export function LedgerHead<T>({
  columns,
  sort,
  onSort,
}: {
  columns: Col<T>[]
  sort: SortState
  onSort: (id: string) => void
}) {
  return (
    <thead>
      <tr>
        {columns.map((c) => {
          const on = sort?.id === c.id
          const sortable = c.sortable !== false && !!(c.accessor || c.sortingFn)
          const cls =
            [c.className, c.align === 'right' ? 'num' : '', c.align === 'center' ? 'ctr' : '', on ? 'sorted' : '']
              .filter(Boolean)
              .join(' ') || undefined
          return (
            <th
              key={c.id}
              className={cls}
              style={c.size ? { width: c.size } : undefined}
              aria-sort={on ? (sort.desc ? 'descending' : 'ascending') : undefined}
            >
              {sortable && c.header ? (
                <button
                  type="button"
                  className="th-sort"
                  title={
                    on
                      ? sort.desc
                        ? 'sorted, reversed · click to clear'
                        : 'sorted · click to reverse'
                      : `sort by ${c.header}`
                  }
                  onClick={() => onSort(c.id)}
                >
                  {c.header}
                  <span className="th-arrow" aria-hidden="true">
                    {on ? (sort.desc ? '↓' : '↑') : ''}
                  </span>
                </button>
              ) : (
                c.header
              )}
            </th>
          )
        })}
      </tr>
    </thead>
  )
}

/* one serif line when a filter finds nothing */
export function Empty({ cols, what }: { cols: number; what: string }) {
  return (
    <tr className="empty">
      <td colSpan={cols}>
        <span className="empty-line">{what}</span>
      </td>
    </tr>
  )
}

/* ── the fold under a row: unfolds on the 0fr track, never a modal ── */
export function Fold({
  open,
  cols,
  id,
  children,
}: {
  open: boolean
  cols: number
  id?: string
  children: React.ReactNode
}) {
  return (
    <tr className="foldrow" aria-hidden={!open}>
      <td className="foldcell" colSpan={cols}>
        <div className={open ? 'fold on' : 'fold'} id={id}>
          {/* folded = inert: nothing inside takes the tab or the reader */}
          <div className="fold-in" inert={!open}>
            <div className="fold-body">{children}</div>
          </div>
        </div>
      </td>
    </tr>
  )
}

/* receipts: time mono · what happened serif */
export function ReceiptLines({ lines }: { lines: [string, string][] }) {
  return (
    <>
      {lines.map(([time, what], i) => (
        <span className="rc-line" key={i}>
          <span className="rc-time">{time}</span>
          <span className="rc-what">{what}</span>
        </span>
      ))}
    </>
  )
}

/* the sheet: every page is main.pane.settings with the pane-body */
export function Sheet({
  page,
  ctx,
  children,
  aside,
}: {
  page: string
  ctx?: boolean
  children: React.ReactNode
  aside?: React.ReactNode
}) {
  return (
    <main className={ctx ? 'pane settings ctx-on' : 'pane settings'} id="pane" data-page={page}>
      <div className="pane-body">{children}</div>
      {aside}
    </main>
  )
}
