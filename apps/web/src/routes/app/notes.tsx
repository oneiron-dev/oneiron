import * as React from 'react'
import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { cue, markCued, openChat, useEscape } from '~/components/safelight/hooks'
import { SelTools, selWithin, useSelTools, type SelPlace } from '~/components/safelight/SelTools'
import notesCss from '~/styles/notes.css?url'

export const Route = createFileRoute('/app/notes')({
  head: () => ({
    links: [{ rel: 'stylesheet', href: notesCss }],
  }),
  component: Notes,
})

/* ════════════════════════════════════════════════════════════════════
   the DOCUMENT engine (rulings 4 · 5 · 6, 08-18). A document is a stack
   of blocks. Every block is contentEditable, plain text; Enter opens a
   new block, Backspace at the start joins it to the one above. Every
   block carries who wrote it and who last touched it; a human is a
   seal, an agent is its name in ink. An agent's edit you have not read
   yet wears the agent's ink until you click `read`. Nothing is lost:
   the history fold shows the trail. Learned from Proof (every edit is
   attributed; agents use the SAME operations as people); rebuilt native.
   briefs.tsx imports this engine from here.
   ════════════════════════════════════════════════════════════════════ */

export type Who = 'o' | 'y' | 'eiri' | 'tory' | 'antevon'
export const WHO: Record<Who, { name: string; tip: string; human: boolean }> = {
  o: { name: 'Owen', tip: 'o · Owen · owner', human: true },
  y: { name: 'Yuki', tip: 'y · Yuki · member', human: true },
  eiri: { name: 'Eiri', tip: 'Eiri · outbound companion', human: false },
  tory: { name: 'Tory', tip: 'Tory · research companion', human: false },
  antevon: { name: 'Antevon', tip: 'Antevon · the house mind', human: false },
}
export type Cite = { id: string; conf?: number; learned?: string }
export type Run = string | { text: string; cite: Cite }
export type BlockKind = 'p' | 'h3' | 'li' | 'lead' | 'label' | 'node'
export type Block = {
  id: string
  kind: BlockKind
  runs: Run[]
  node?: string /* kind 'node': a key the page renders (a table, a kv list, acts) */
  by: Who
  at: string
  editedBy?: Who
  editedAt?: string
  unread?: boolean /* an agent's touch you have not read */
}
export type Trail = { when: string; who: Who; what: string }
export type Change = { op: 'edit' | 'split' | 'join' | 'cite' | 'read'; id: string; index: number }

const EDITABLE: BlockKind[] = ['p', 'h3', 'li', 'lead']

/* the mark: a seal for a human, the name in ink for an agent (rule 15) */
export function Mark({ who, tip }: { who: Who; tip?: string }) {
  const w = WHO[who]
  if (w.human)
    return (
      <span className="seal seal-human" title={tip ?? w.tip}>
        {who}
      </span>
    )
  return (
    <span className="aname" data-agent={who} title={tip ?? w.tip}>
      {w.name}
    </span>
  )
}

export function hhmm() {
  const d = new Date()
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
}
let seq = 0
export const uid = (p = 'b') => `${p}-${Date.now().toString(36)}${(seq++).toString(36)}`

/* ── block builders (fixtures read as prose, not as objects) ── */
export const c = (text: string, id: string, conf?: number, learned?: string): Run => ({
  text,
  cite: { id, conf, learned },
})
type Draft = { kind: BlockKind; runs?: Run[]; node?: string; by?: Who; at?: string; editedBy?: Who; editedAt?: string; unread?: boolean }
export const P = (runs: Run[] | string, x: Partial<Draft> = {}): Draft => ({ kind: 'p', runs: typeof runs === 'string' ? [runs] : runs, ...x })
export const H = (t: string, x: Partial<Draft> = {}): Draft => ({ kind: 'h3', runs: [t], ...x })
export const LI = (runs: Run[] | string, x: Partial<Draft> = {}): Draft => ({ kind: 'li', runs: typeof runs === 'string' ? [runs] : runs, ...x })
export const LEAD = (runs: Run[] | string, x: Partial<Draft> = {}): Draft => ({ kind: 'lead', runs: typeof runs === 'string' ? [runs] : runs, ...x })
export const LABEL = (t: string, x: Partial<Draft> = {}): Draft => ({ kind: 'label', runs: [t], ...x })
export const NODE = (key: string, x: Partial<Draft> = {}): Draft => ({ kind: 'node', node: key, runs: [], ...x })
/* seal a draft list: every block gets the doc's author + date unless it says otherwise */
export function seal(docId: string, by: Who, at: string, drafts: Draft[]): Block[] {
  return drafts.map((d, i) => ({ id: `${docId}-${i + 1}`, by, at, ...d, runs: d.runs ?? [] }))
}

/* ── runs ⇄ text ── */
export const runText = (r: Run) => (typeof r === 'string' ? r : r.text)
export const runsText = (runs: Run[]) => runs.map(runText).join('')
const rung = (conf?: number) =>
  conf == null ? '' : conf >= 0.9 ? ' conf-1' : conf >= 0.7 ? ' conf-2' : conf >= 0.4 ? ' conf-3' : ' conf-4'
const citeTitle = (ct: Cite) =>
  ct.conf == null
    ? `${ct.id} · proposed · open the claim in the vault`
    : `${ct.id} · ${ct.conf.toFixed(2)}${ct.learned ? ` · learned ${ct.learned}` : ''} · open the claim in the vault`

/* the same runs, as React (SSR + first paint) and as DOM (after an edit) */
function runsToReact(runs: Run[]) {
  return runs.map((r, i) =>
    typeof r === 'string' ? (
      <React.Fragment key={i}>{r}</React.Fragment>
    ) : (
      <a
        key={i}
        href="/app/vault"
        className={`cite${rung(r.cite.conf)}`}
        data-cite={r.cite.id}
        data-conf={r.cite.conf}
        data-learned={r.cite.learned}
        title={citeTitle(r.cite)}
      >
        {r.text}
      </a>
    ),
  )
}
function runsToDom(runs: Run[]): Node[] {
  return runs.map((r) => {
    if (typeof r === 'string') return document.createTextNode(r)
    const a = document.createElement('a')
    a.href = '/app/vault'
    a.className = `cite${rung(r.cite.conf)}`
    a.dataset.cite = r.cite.id
    if (r.cite.conf != null) a.dataset.conf = String(r.cite.conf)
    if (r.cite.learned) a.dataset.learned = r.cite.learned
    a.title = citeTitle(r.cite)
    a.textContent = r.text
    return a
  })
}
/* read the DOM back: text nodes are text, a[data-cite] is a cite; the
   browser's stray <br>/<div> wrappers dissolve */
function serialize(el: HTMLElement): Run[] {
  const out: Run[] = []
  const pushText = (s: string) => {
    if (!s) return
    const last = out[out.length - 1]
    if (typeof last === 'string') out[out.length - 1] = last + s
    else out.push(s)
  }
  const walk = (n: Node) => {
    if (n.nodeType === Node.TEXT_NODE) pushText(n.nodeValue ?? '')
    else if (n instanceof HTMLElement) {
      if (n.dataset.cite) {
        const text = n.textContent ?? ''
        if (text)
          out.push({
            text,
            cite: {
              id: n.dataset.cite,
              conf: n.dataset.conf ? Number(n.dataset.conf) : undefined,
              learned: n.dataset.learned || undefined,
            },
          })
      } else if (n.tagName !== 'BR') n.childNodes.forEach(walk)
    }
  }
  el.childNodes.forEach(walk)
  return out
}
const same = (a: Run[], b: Run[]) => JSON.stringify(a) === JSON.stringify(b)

function splitRuns(runs: Run[], at: number): [Run[], Run[]] {
  const a: Run[] = []
  const b: Run[] = []
  let pos = 0
  for (const r of runs) {
    const t = runText(r)
    const end = pos + t.length
    if (end <= at) a.push(r)
    else if (pos >= at) b.push(r)
    else {
      const cut = at - pos
      if (typeof r === 'string') {
        a.push(r.slice(0, cut))
        b.push(r.slice(cut))
      } else {
        a.push({ text: t.slice(0, cut), cite: r.cite })
        b.push({ text: t.slice(cut), cite: r.cite })
      }
    }
    pos = end
  }
  return [a, b]
}
function joinRuns(a: Run[], b: Run[]): Run[] {
  const out = [...a]
  for (const r of b) {
    const last = out[out.length - 1]
    if (typeof r === 'string' && typeof last === 'string') out[out.length - 1] = last + r
    else out.push(r)
  }
  return out
}
/* wrap [start, end) of a block as one claim citation */
function citeRuns(runs: Run[], start: number, end: number, cite: Cite): Run[] {
  const chars: { ch: string; cite?: Cite }[] = []
  for (const r of runs)
    for (const ch of runText(r)) chars.push({ ch, cite: typeof r === 'string' ? undefined : r.cite })
  for (let i = start; i < end && i < chars.length; i++) chars[i].cite = cite
  const out: Run[] = []
  for (const x of chars) {
    const last = out[out.length - 1]
    if (!x.cite) {
      if (typeof last === 'string') out[out.length - 1] = last + x.ch
      else out.push(x.ch)
    } else if (last && typeof last !== 'string' && last.cite === x.cite) last.text += x.ch
    else out.push({ text: x.ch, cite: x.cite })
  }
  return out
}

/* ── the caret ── */
function caretOffset(el: HTMLElement): number {
  const s = getSelection()
  if (!s || s.rangeCount === 0) return 0
  const r = s.getRangeAt(0)
  const pre = r.cloneRange()
  pre.selectNodeContents(el)
  pre.setEnd(r.startContainer, r.startOffset)
  return pre.toString().length
}
function placeCaret(el: HTMLElement, offset: number, all = false) {
  el.focus({ preventScroll: true })
  const s = getSelection()
  if (!s) return
  const range = document.createRange()
  if (all) {
    range.selectNodeContents(el)
    s.removeAllRanges()
    s.addRange(range)
    return
  }
  const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT)
  let left = offset
  let node = walker.nextNode() as Text | null
  let placed = false
  while (node) {
    const len = node.nodeValue?.length ?? 0
    if (left <= len) {
      range.setStart(node, left)
      placed = true
      break
    }
    left -= len
    node = walker.nextNode() as Text | null
  }
  if (placed) range.collapse(true)
  else {
    range.selectNodeContents(el)
    range.collapse(false)
  }
  s.removeAllRanges()
  s.addRange(range)
}

/* ── one block's text: React paints it once (the children never change,
   so a re-render never touches the DOM); the browser owns it after. the
   model follows the DOM on input; the DOM follows the model only when
   they disagree (a join, a split, a cite, a read). ── */
const TAG: Record<BlockKind, keyof React.JSX.IntrinsicElements> = { p: 'p', h3: 'h3', li: 'span', lead: 'p', label: 'span', node: 'div' }
type TextProps = {
  block: Block
  onInput: (runs: Run[]) => void
  onEnter: (before: Run[], after: Run[]) => void
  onJoin: () => void
}
function BlockText({ block, onInput, onEnter, onJoin }: TextProps) {
  const ref = React.useRef<HTMLElement>(null)
  const [initial] = React.useState(() => runsToReact(block.runs))
  React.useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    if (!same(serialize(el), block.runs)) el.replaceChildren(...runsToDom(block.runs))
  }, [block.runs])
  const Tag = TAG[block.kind] as 'p'
  return (
    <Tag
      ref={ref as React.RefObject<HTMLParagraphElement>}
      className="btext"
      contentEditable
      suppressContentEditableWarning
      spellCheck={false}
      onInput={() => ref.current && onInput(serialize(ref.current))}
      onPaste={(e) => {
        /* a block holds plain words: paste arrives as text, never as
           foreign markup. line breaks fold into spaces */
        e.preventDefault()
        const text = e.clipboardData.getData('text/plain').replace(/[\r\n\t]+/g, ' ')
        if (text) document.execCommand('insertText', false, text)
        if (ref.current) onInput(serialize(ref.current))
      }}
      onKeyDown={(e) => {
        const el = ref.current
        if (!el) return
        if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) {
          e.preventDefault()
          const [a, b] = splitRuns(serialize(el), caretOffset(el))
          onEnter(a, b)
        } else if (e.key === 'Backspace') {
          const s = getSelection()
          if (s && s.isCollapsed && caretOffset(el) === 0) {
            e.preventDefault()
            onJoin()
          }
        }
      }}
    >
      {initial}
    </Tag>
  )
}

/* the side note in the left gutter: who wrote it · who last touched it.
   the same hand twice says nothing, so the second line only lands when
   another hand edited it; the full stamp stays on the hover */
function Prov({ b }: { b: Block }) {
  const wrote = `${WHO[b.by].name} wrote · ${b.at}`
  const edited = b.editedBy ? ` · ${WHO[b.editedBy].name} edited · ${b.editedAt ?? ''}` : ''
  return (
    <span className="prov" contentEditable={false} title={wrote + edited} aria-hidden="true">
      <span className="pline">
        <Mark who={b.by} />
        <span className="pverb">wrote</span>
      </span>
      {b.editedBy && b.editedBy !== b.by && (
        <span className="pline">
          <Mark who={b.editedBy} />
          <span className="pverb">edited</span>
        </span>
      )}
    </span>
  )
}

/* ── the selection toolbar (the shared atom, SelTools): hand the words to a
   companion, ask the house mind, cite, copy. the page owns the verbs. ── */
function NoteSelTools({ sel, canCite, onCite, onClose }: { sel: SelPlace; canCite: boolean; onCite: () => void; onClose: () => void }) {
  const hand = (agent: 'eiri' | 'tory' | 'ask') => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    openChat(agent)
    cue('press')
    onClose()
  }
  const copy = (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    try {
      navigator.clipboard?.writeText(sel.text).catch(() => {})
    } catch {}
    cue('success')
    onClose()
  }
  return (
    <SelTools sel={sel}>
      <a className="act" href="#" title="Eiri takes these words into a chat" onClick={hand('eiri')}>
        hand to Eiri
      </a>
      <a className="act" href="#" title="Tory takes these words into a chat" onClick={hand('tory')}>
        hand to Tory
      </a>
      <a className="act" href="#" title="Antevon answers on these words" onClick={hand('ask')}>
        ask Antevon
      </a>
      {canCite && (
        <a
          className="act"
          href="#"
          title="marks these words as a claim · a dotted door into the vault"
          onClick={(e) => {
            e.preventDefault()
            markCued(e)
            onCite()
          }}
        >
          cite
        </a>
      )}
      <a className="act" href="#" title="copies the words" onClick={copy}>
        copy
      </a>
    </SelTools>
  )
}

/* the block and the offsets the picked words sit in (one block only) */
function spanOf(range: Range): { blockId: string; start: number; end: number } | null {
  const el = selWithin(range, '.btext')
  const blockId = el?.closest<HTMLElement>('[data-blk]')?.dataset.blk
  if (!el || !blockId) return null
  const pre = range.cloneRange()
  pre.selectNodeContents(el)
  pre.setEnd(range.startContainer, range.startOffset)
  const start = pre.toString().length
  return { blockId, start, end: start + range.toString().length }
}

/* ── the document ── */
export function Doc({
  blocks,
  onChange,
  renderNode,
  focus,
}: {
  blocks: Block[]
  onChange: (next: Block[], change: Change) => void
  renderNode?: (key: string, b: Block) => React.ReactNode
  focus?: { id: string; all?: boolean } /* on mount: put the caret here */
}) {
  const root = React.useRef<HTMLDivElement>(null)
  const pending = React.useRef<{ id: string; offset: number; all?: boolean } | null>(focus ? { id: focus.id, offset: 0, all: focus.all } : null)
  const { sel, raise, clear, dismiss } = useSelTools(root)
  const navigate = useNavigate()

  /* after a structural change the caret lands where the writer expects */
  React.useLayoutEffect(() => {
    const p = pending.current
    if (!p || !root.current) return
    const el = root.current.querySelector<HTMLElement>(`[data-blk="${p.id}"] .btext`)
    if (el) placeCaret(el, p.offset, p.all)
    pending.current = null
  })

  const now = hhmm()
  const touch = (b: Block): Block => ({ ...b, editedBy: 'o', editedAt: now, unread: false })

  const edit = (i: number) => (runs: Run[]) => {
    const b = blocks[i]
    if (same(b.runs, runs)) return
    const next = blocks.slice()
    next[i] = { ...touch(b), runs }
    onChange(next, { op: 'edit', id: b.id, index: i })
  }
  const enter = (i: number) => (before: Run[], after: Run[]) => {
    const b = blocks[i]
    const next = blocks.slice()
    /* an empty list item + Enter leaves the list */
    if (b.kind === 'li' && before.length === 0 && after.length === 0) {
      next[i] = { ...touch(b), kind: 'p' }
      pending.current = { id: b.id, offset: 0 }
      onChange(next, { op: 'edit', id: b.id, index: i })
      return
    }
    const fresh: Block = { id: uid(), kind: b.kind === 'li' ? 'li' : 'p', runs: after, by: 'o', at: now }
    next.splice(i, 1, { ...(same(before, b.runs) ? b : touch(b)), runs: before }, fresh)
    pending.current = { id: fresh.id, offset: 0 }
    onChange(next, { op: 'split', id: fresh.id, index: i + 1 })
    cue('toggle')
  }
  const join = (i: number) => () => {
    const b = blocks[i]
    const j = i - 1
    const next = blocks.slice()
    if (j < 0 || !EDITABLE.includes(blocks[j].kind)) {
      /* no prose right above (the top, a label, a fixed piece): an empty
         block simply goes; words stay where they are */
      if (runsText(b.runs).length === 0 && blocks.length > 1) {
        next.splice(i, 1)
        onChange(next, { op: 'join', id: b.id, index: i })
        cue('toggle')
      }
      return
    }
    const prev = blocks[j]
    const offset = runsText(prev.runs).length
    next[j] = { ...touch(prev), runs: joinRuns(prev.runs, b.runs) }
    next.splice(i, 1)
    pending.current = { id: prev.id, offset }
    onChange(next, { op: 'join', id: prev.id, index: j })
    cue('toggle')
  }
  const read = (i: number) => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    const next = blocks.slice()
    next[i] = { ...blocks[i], unread: false }
    onChange(next, { op: 'read', id: blocks[i].id, index: i })
    cue('success')
  }

  useEscape(() => {
    dismiss()
    /* Esc leaves the writing surface, so the next Esc reaches the page */
    const el = document.activeElement
    if (el instanceof HTMLElement && el.closest('.btext')) el.blur()
  })

  const cite = () => {
    const span = sel ? spanOf(sel.range) : null
    if (!span) return
    const i = blocks.findIndex((b) => b.id === span.blockId)
    if (i < 0) return
    const b = blocks[i]
    const id = `cl_${Math.floor(Math.random() * 0xffff).toString(16).padStart(4, '0')}`
    const next = blocks.slice()
    next[i] = { ...touch(b), runs: citeRuns(b.runs, span.start, span.end, { id }) }
    clear()
    onChange(next, { op: 'cite', id: b.id, index: i })
    cue('success')
  }

  /* a cite is a door even inside an editable block: the click opens the vault */
  const onClick = (e: React.MouseEvent) => {
    const a = (e.target as HTMLElement).closest?.('a.cite')
    if (a) {
      e.preventDefault()
      navigate({ to: '/app/vault' })
    }
  }

  /* consecutive list items share one <ul> */
  const out: React.ReactNode[] = []
  let list: React.ReactNode[] = []
  const flush = () => {
    if (list.length) out.push(<ul key={`ul-${out.length}`}>{list}</ul>)
    list = []
  }
  blocks.forEach((b, i) => {
    const agentInk = b.unread ? (b.editedBy ?? b.by) : undefined
    const cls = `blk k-${b.kind}${b.unread ? ' unread' : ''}`
    const inner =
      b.kind === 'node' ? (
        <div className="btext-node">{renderNode?.(b.node ?? '', b)}</div>
      ) : b.kind === 'label' ? (
        <span className="label">{runsText(b.runs)}</span>
      ) : (
        <BlockText block={b} onInput={edit(i)} onEnter={enter(i)} onJoin={join(i)} />
      )
    const tail = b.unread && (
      <a className="act read-act" href="#" title={`${WHO[b.editedBy ?? b.by].name} touched this · read settles it`} onClick={read(i)}>
        read
      </a>
    )
    if (b.kind === 'li') {
      list.push(
        <li key={b.id} className={cls} data-blk={b.id} data-agent={agentInk}>
          <Prov b={b} />
          {inner}
          {tail}
        </li>,
      )
    } else {
      flush()
      out.push(
        <div key={b.id} className={cls} data-blk={b.id} data-agent={agentInk}>
          <Prov b={b} />
          {inner}
          {tail}
        </div>,
      )
    }
  })
  flush()

  return (
    <div
      className="doc-body"
      ref={root}
      onMouseUp={raise}
      onClick={onClick}
      /* words picked with the keyboard raise the toolbar too */
      onKeyUp={(e) => {
        if (e.shiftKey || ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'a')) raise()
      }}
    >
      {out}
      {sel && <NoteSelTools sel={sel} canCite={!!spanOf(sel.range)} onCite={cite} onClose={dismiss} />}
    </div>
  )
}

/* ── the trail: when · who · what changed. a fold under the head, ≤6 rows ── */
export function TrailFold({ rows, open, id }: { rows: Trail[]; open: boolean; id: string }) {
  return (
    <div className="trail-fold" id={id} hidden={!open}>
      {rows.slice(0, 6).map((r, i) => (
        <div className="trow" key={i}>
          <span className="twhen">{r.when}</span>
          <Mark who={r.who} />
          <span className="twhat">{r.what}</span>
        </div>
      ))}
    </div>
  )
}

/* ── share: an icon act; the click settles to a quiet line for 1.6s. the
   icon stays put while the line rests beside it, so the hand and the
   keyboard never lose the act they just used ── */
export function ShareAct() {
  const [done, setDone] = React.useState(false)
  React.useEffect(() => {
    if (!done) return
    const t = setTimeout(() => setDone(false), 1600)
    return () => clearTimeout(t)
  }, [done])
  return (
    <>
      <button
        className="icon-act"
        title="share · a link others in the vault can open"
        aria-label="share"
        onClick={(e) => {
          markCued(e)
          try {
            navigator.clipboard?.writeText(location.href).catch(() => {})
          } catch {}
          setDone(true)
          cue('success')
        }}
      >
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M6.5 9.5 9.5 6.5" />
          <path d="M7 4.75 8.6 3.15a2.6 2.6 0 0 1 3.7 3.7L10.7 8.4" />
          <path d="M9 11.25 7.4 12.85a2.6 2.6 0 0 1-3.7-3.7L5.3 7.6" />
        </svg>
      </button>
      {done && <span className="meta-line share-done">link copied</span>}
    </>
  )
}

/* ── the history door: a bare act that opens the fold ── */
export function HistoryAct({ open, onToggle, controls }: { open: boolean; onToggle: () => void; controls: string }) {
  return (
    <a
      className="act"
      href="#"
      aria-expanded={open}
      aria-controls={controls}
      title="the trail · who changed what, when"
      onClick={(e) => {
        e.preventDefault()
        markCued(e)
        onToggle()
        cue('toggle')
      }}
    >
      history
    </a>
  )
}

/* ── an index column walks with ↑ and ↓: the arrow moves the focus and
   picks the row it lands on ── */
export function rowArrows(rowSelector: string) {
  return (e: React.KeyboardEvent<HTMLElement>) => {
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return
    const rows = Array.from(e.currentTarget.querySelectorAll<HTMLButtonElement>(rowSelector))
    if (rows.length === 0) return
    const here = rows.indexOf(document.activeElement as HTMLButtonElement)
    const step = e.key === 'ArrowDown' ? 1 : -1
    const next = rows[here < 0 ? 0 : Math.min(Math.max(here + step, 0), rows.length - 1)]
    if (!next || next === document.activeElement) return
    e.preventDefault()
    next.focus()
    next.click()
  }
}

/* ════════════════════════════════════════════════════════════════════
   NOTES · the office notes (app-docs.html is content truth). humans
   stamp with seals (o · y); the house mind writes digests and handoffs
   and signs in its ink. a note is READ (rule 39): the document is the
   body of the sheet, the list is the one tinted zone.
   ════════════════════════════════════════════════════════════════════ */
type Note = {
  id: string
  title: string
  by: Who
  updated: string /* the short date, list + byline */
  when: string /* the full stamp, hover-tier */
  read: string
  pinned?: boolean
  recent?: boolean
  kind?: 'digest' | 'handoff'
  blocks: Block[]
  trail: Trail[]
}

const NOTES: Note[] = [
  {
    id: 'how-we-work',
    title: 'How we work',
    by: 'o',
    updated: 'Aug 12',
    when: '2026-08-12 · 16:40',
    read: '4 min',
    pinned: true,
    blocks: seal('how-we-work', 'o', 'Jul 02', [
      P('The first thing an agent reads before it acts in this vault. Short, current, and every load-bearing sentence carries its evidence.'),
      H('Conventions'),
      P([
        'Forecast deliverables ship as briefs, never as loose spreadsheets. ',
        c('Client-facing numbers come from the model registry, not from memory', 'cl_44b1', 0.91, '2026-06-24'),
        '.',
      ]),
      P([c('Quotes go out within two business days of the ask', 'cl_5c02', 0.94, '2026-05-30'), '. Late means we say so before they notice, not after.']),
      H('Before a client call'),
      LI('Read the org page and the last three threads.', { editedBy: 'y', editedAt: 'Aug 02 09:10' }),
      LI('Check the pipeline stage and the next step written there. The Hokuei next step now reads Thursday.', {
        editedBy: 'antevon',
        editedAt: 'Aug 12 03:12',
        unread: true,
      }),
      LI([c('Bring the latest brief; the client has already seen the one before it', 'cl_61aa', 0.88, '2026-07-02'), '.']),
      H('For agents'),
      P(
        'Read this note and the pilot scope before touching anything client-facing. Every outbound send is a human click. Edits to protected notes land as proposals; a person stamps before they commit.',
        { editedBy: 'o', editedAt: 'Aug 12 16:40' },
      ),
    ]),
    trail: [
      { when: 'Aug 12 16:40', who: 'o', what: 'edited ¶10' },
      { when: 'Aug 12 03:12', who: 'antevon', what: 'edited ¶7' },
      { when: 'Aug 02 09:10', who: 'y', what: 'edited ¶6' },
      { when: 'Jul 02 10:30', who: 'o', what: 'wrote · 10 blocks' },
    ],
  },
  {
    id: 'forecast-conventions',
    title: 'Forecast conventions',
    by: 'o',
    updated: 'Jul 19',
    when: '2026-07-19 · 11:02',
    read: '2 min',
    pinned: true,
    blocks: seal('forecast-conventions', 'o', 'Jul 19', [
      P('How a forecast leaves this office.'),
      LI('Units: pieces per week, never revenue, unless the client asks.'),
      LI('Horizons: twelve weeks for a pilot, twenty-six for a contract.'),
      LI([c('Every number carries the model version it came from', 'cl_1180', 0.93, '2026-06-10'), '.']),
      P('A forecast without its error band is a guess. Say the band.'),
    ]),
    trail: [{ when: 'Jul 19 11:02', who: 'o', what: 'wrote · 5 blocks' }],
  },
  {
    id: 'hokuei-pilot-scope',
    title: 'Hokuei pilot scope',
    by: 'y',
    updated: 'Aug 14',
    when: '2026-08-14 · 18:21',
    read: '3 min',
    recent: true,
    blocks: seal('hokuei-pilot-scope', 'y', 'Aug 01', [
      P('What the Hokuei pilot covers, and what it does not. Yuki owns this note; Antevon reads it before any Hokuei work.'),
      H('Scope'),
      LI('Three SKU families, weekly demand, a twelve-week horizon.'),
      LI('One brief every Monday before 10:00 JST.', { editedBy: 'y', editedAt: 'Aug 14 18:21' }),
      LI([c('The pilot runs to 2026-10-31', 'cl_7d20', 0.95, '2026-08-01'), '.']),
      H('Out of scope'),
      P('Supplier negotiations. Pricing advice. Anything the COO has not asked for in writing.'),
      P('Two July filings retire supplier codes at Hokuei. The supplier rumor brief has the reading; do not lead with it on the call.', {
        by: 'tory',
        at: 'Aug 14 09:40',
        unread: true,
      }),
      H('People'),
      P([c('Mika Tanaka is the day-to-day contact', 'cl_2b91', 0.86, '2026-07-22'), '; the COO joins the monthly review.']),
    ]),
    trail: [
      { when: 'Aug 14 18:21', who: 'y', what: 'edited ¶4' },
      { when: 'Aug 14 09:40', who: 'tory', what: 'added ¶8' },
      { when: 'Aug 01 15:00', who: 'y', what: 'wrote · 9 blocks' },
    ],
  },
  {
    id: 'supplier-consolidation',
    title: 'Supplier consolidation, what we know',
    by: 'antevon',
    updated: 'Aug 14',
    when: '2026-08-14 03:12',
    read: '2 min',
    recent: true,
    kind: 'digest',
    blocks: seal('supplier-consolidation', 'antevon', 'Aug 14 03:12', [
      P('What the vault holds on the Hokuei supplier question, in one place. Every sentence below is a claim you can open.'),
      H('What we know'),
      LI([c('Hokuei has been expanding its supplier base since spring', 'cl_31f0', 0.77, '2026-05-14'), '.']),
      LI([
        c('Hokuei may be consolidating suppliers this fiscal year', 'cl_9d17', 0.81, '2026-08-13'),
        '. This contradicts the line above; the newer claim waits in the inbox.',
      ]),
      LI([c('Fourteen supplier accounts are active today', 'cl_4e08', 0.9, '2026-08-06'), '.']),
      H('What we do not know'),
      P('Which accounts would go first, and whether the COO has said this out loud. Two public filings are open; neither says consolidation.'),
      H('Suggested next step'),
      P('Ask Mika Tanaka on the Thursday call. A direct answer settles both claims.'),
    ]),
    trail: [{ when: 'Aug 14 03:12', who: 'antevon', what: 'wrote · 9 blocks' }],
  },
  {
    id: 'nightly-handoff',
    title: 'Nightly handoff',
    by: 'antevon',
    updated: 'Aug 15',
    when: '2026-08-15 03:12',
    read: '1 min',
    recent: true,
    kind: 'handoff',
    blocks: seal('nightly-handoff', 'antevon', 'Aug 15 03:12', [
      P('For the next run. What the night did, in the order it did it.'),
      LI('Forty-two claims went in on their own; two wait for review.'),
      LI('The LinkedIn import paused itself at 180 writes.'),
      LI('The Hokuei brief for Thursday is compiled and cites every claim under it.'),
      P('Start with the two held claims. Then resume the import once Owen has cleared it.'),
    ]),
    trail: [{ when: 'Aug 15 03:12', who: 'antevon', what: 'wrote · 5 blocks' }],
  },
  {
    id: 'onboarding-a-client',
    title: 'Onboarding a client',
    by: 'o',
    updated: 'Jul 28',
    when: '2026-07-28 · 09:15',
    read: '3 min',
    blocks: seal('onboarding-a-client', 'o', 'Jul 28', [
      P('The first two weeks with a new client, step by step.'),
      H('Week one'),
      LI('Sign the data agreement before any file moves.'),
      LI('Get the last two years of sales, by SKU, by week.'),
      LI('Name one contact on their side. Write it in the org page.'),
      H('Week two'),
      LI('First baseline forecast, shared as a brief.'),
      LI('One call to walk the brief. Take notes into the thread.'),
    ]),
    trail: [{ when: 'Jul 28 09:15', who: 'o', what: 'wrote · 8 blocks' }],
  },
  {
    id: 'outreach-voice',
    title: 'Outreach voice',
    by: 'o',
    updated: 'Jun 30',
    when: '2026-06-30 · 22:08',
    read: '2 min',
    blocks: seal('outreach-voice', 'o', 'Jun 30', [
      P('How we sound when we reach out. Eiri drafts in this voice; a person sends.'),
      LI('Short. Two lines before the ask.'),
      LI('Plain Japanese with the client, plain English inside.'),
      LI('Name what we noticed about them, then what we offer. Never the other way round.'),
      P('Never promise a number in an intro. Numbers come from a brief.'),
    ]),
    trail: [{ when: 'Jun 30 22:08', who: 'o', what: 'wrote · 5 blocks' }],
  },
  {
    id: 'pricing-notes-2026',
    title: 'Pricing notes 2026',
    by: 'y',
    updated: 'Jul 03',
    when: '2026-07-03 · 14:47',
    read: '2 min',
    blocks: seal('pricing-notes-2026', 'y', 'Jul 03', [
      P('Working notes, not a price list. The list lives in the contract template.'),
      P([c('Pilots run at cost; the contract price starts after week twelve', 'cl_0a77', 0.74, '2026-06-28'), '. We say this in the first call.']),
      P('Do not quote from memory. Ask Yuki, or open the contract template.'),
    ]),
    trail: [{ when: 'Jul 03 14:47', who: 'y', what: 'wrote · 3 blocks' }],
  },
]

const byName = (n: Note) => WHO[n.by].name

function Sep() {
  return <span className="sep">·</span>
}

function Notes() {
  const [notes, setNotes] = React.useState<Note[]>(NOTES)
  const [sel, setSel] = React.useState<string>(NOTES[0].id)
  const [q, setQ] = React.useState('')
  const [dirty, setDirty] = React.useState<Record<string, string>>({})
  const [hintOpen, setHintOpen] = React.useState(false)
  const [histOpen, setHistOpen] = React.useState(false)
  const [empty, setEmpty] = React.useState(false)
  const [freshId, setFreshId] = React.useState<string | null>(null)
  const touched = React.useRef(new Set<string>()) /* one trail row per block per sitting */

  /* fixtures always fill the list, so ?empty previews the empty state */
  React.useEffect(() => {
    setEmpty(new URLSearchParams(location.search).has('empty'))
  }, [])

  const note = notes.find((n) => n.id === sel) ?? null

  const select = (id: string) => () => {
    if (id === sel) return
    setSel(id)
    setHistOpen(false)
    setFreshId(null) /* the caret only lands in a note the moment it is made */
    cue('toggle')
  }
  useEscape(() => {
    setHintOpen(false)
    setHistOpen(false)
    setQ('')
  })

  /* every edit lands in the note; the byline cools to "updated hh:mm";
     the trail takes one row per block per sitting (no toast, ever) */
  const change = (id: string) => (blocks: Block[], ch: Change) => {
    const t = hhmm()
    setNotes((ns) =>
      ns.map((n) => {
        if (n.id !== id) return n
        let trail = n.trail
        const key = `${id}:${ch.id}:${ch.op === 'read' ? 'read' : 'edit'}`
        const what =
          ch.op === 'read'
            ? `read ¶${ch.index + 1}`
            : ch.op === 'split'
              ? `added ¶${ch.index + 1}`
              : ch.op === 'join'
                ? `joined ¶${ch.index + 1}`
                : ch.op === 'cite'
                  ? `cited in ¶${ch.index + 1}`
                  : `edited ¶${ch.index + 1}`
        if (ch.op !== 'edit' || !touched.current.has(key)) {
          touched.current.add(key)
          trail = [{ when: `today ${t}`, who: 'o', what }, ...n.trail]
        }
        return { ...n, blocks, trail }
      }),
    )
    if (ch.op !== 'read') setDirty((d) => (d[id] === t ? d : { ...d, [id]: t }))
  }

  const newNote = (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    const id = `new-${Date.now()}`
    const t = hhmm()
    const fresh: Note = {
      id,
      title: 'Untitled',
      by: 'o',
      updated: t,
      when: `today ${t}`,
      read: '1 min',
      recent: true,
      blocks: seal(id, 'o', `today ${t}`, [P('Write here.')]),
      trail: [{ when: `today ${t}`, who: 'o', what: 'wrote · 1 block' }],
    }
    setNotes((ns) => [fresh, ...ns])
    setEmpty(false)
    setSel(id)
    setFreshId(id)
    setHistOpen(false)
    cue('toggle')
  }
  const retitle = (id: string) => (e: React.FocusEvent<HTMLHeadingElement>) => {
    const title = (e.currentTarget.textContent ?? '').trim() || 'Untitled'
    setNotes((ns) => ns.map((n) => (n.id === id && n.title !== title ? { ...n, title } : n)))
  }

  /* the filter narrows every group; a group with nothing left hides */
  const needle = q.trim().toLowerCase()
  const match = (n: Note) =>
    !needle || n.title.toLowerCase().includes(needle) || byName(n).toLowerCase().includes(needle)
  const groups = [
    { label: 'pinned', rows: notes.filter((n) => n.pinned && match(n)) },
    { label: 'recent', rows: notes.filter((n) => !n.pinned && n.recent && match(n)) },
    { label: 'earlier', rows: notes.filter((n) => !n.pinned && !n.recent && match(n)) },
  ]
  const nothing = groups.every((g) => g.rows.length === 0)

  const isAgent = note ? !WHO[note.by].human : false
  const updatedWord = (note && dirty[note.id]) || note?.updated
  const unreadCount = note ? note.blocks.filter((b) => b.unread).length : 0

  return (
    <main className="pane notes-pane">
      {/* the list · the one tinted zone */}
      <nav className="notes-list" aria-label="notes" onKeyDown={rowArrows('.nrow')}>
        {empty ? (
          <div className="notes-empty">
            <img className="spot" src="/art/spot-flock.png" width={150} alt="" />
            <span className="lead">No notes yet.</span>
            <a className="act" href="#" title="a blank note · yours" onClick={newNote}>
              + new note
            </a>
          </div>
        ) : (
          <>
            <div className="pane-head">
              <h1>Notes</h1>
            </div>
            <input
              className="notes-filter"
              type="text"
              placeholder="filter"
              aria-label="filter notes"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
            {groups.map(
              (g) =>
                g.rows.length > 0 && (
                  <div className="ngroup" key={g.label} role="group" aria-label={g.label}>
                    <span className="label">{g.label}</span>
                    {g.rows.map((n) => (
                      <button
                        key={n.id}
                        className={n.id === sel ? 'nrow sel' : 'nrow'}
                        aria-current={n.id === sel ? 'true' : undefined}
                        title={`${n.title} · ${byName(n)} · updated ${n.when}${n.kind ? ` · ${n.kind}` : ''}${
                          n.blocks.some((b) => b.unread) ? ' · an agent touched it' : ''
                        }`}
                        onClick={select(n.id)}
                      >
                        <span className="ntitle">{n.title}</span>
                        <Mark who={n.by} />
                        <span className="when">{dirty[n.id] || n.updated}</span>
                      </button>
                    ))}
                  </div>
                ),
            )}
            {nothing && <span className="nnone">Nothing matches.</span>}
            <div className="nfoot">
              <a className="act" href="#" title="a blank note · yours" onClick={newNote}>
                + new note
              </a>
            </div>
          </>
        )}
      </nav>

      {/* the document · the main read, and the place you write */}
      <div className="pane-body">
        {note && !empty && (
          <article className="doc" key={note.id} aria-label={note.title}>
            <div className="pane-head">
              {/* the list head owns the page's h1; the note's title is the
                  document's own heading, the way a brief's title is */}
              <h2
                contentEditable
                suppressContentEditableWarning
                spellCheck={false}
                aria-label="title"
                onBlur={retitle(note.id)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault()
                    ;(e.currentTarget as HTMLElement).blur()
                  }
                }}
              >
                {note.title}
              </h2>
              <span className="pane-tools">
                <HistoryAct open={histOpen} onToggle={() => setHistOpen((o) => !o)} controls="notes-trail" />
                <ShareAct />
                <button
                  className="hint-btn"
                  aria-expanded={hintOpen}
                  aria-controls="notes-why"
                  title="what this screen is"
                  onClick={() => {
                    setHintOpen((open) => !open)
                    cue('toggle')
                  }}
                >
                  ?
                </button>
              </span>
            </div>
            {/* the byline: who wrote it, when it last moved, how long the read.
                the one quiet meta-line; kind (digest · handoff) rides the title */}
            <div
              className="doc-by"
              title={isAgent ? `${WHO[note.by].name} · ${note.kind ?? 'note'} · as of ${note.when}` : `last updated ${note.when}`}
            >
              <Mark who={note.by} />
              <Sep />
              <span>{isAgent ? `as of ${note.when}` : `updated ${updatedWord}`}</span>
              <Sep />
              <span>{note.read} read</span>
              {unreadCount > 0 && (
                <>
                  <Sep />
                  <span title="an agent touched this note · the ink shows where">{unreadCount} unread</span>
                </>
              )}
            </div>
            <div className="dial-why" id="notes-why" hidden={!hintOpen}>
              <span className="why-voice">
                Your agents read these notes before they act. Click into any line to write. A dotted
                phrase rests on a claim. Hover it to see how sure the vault is. Select words to hand
                them to an agent.
              </span>
            </div>
            <TrailFold rows={note.trail} open={histOpen} id="notes-trail" />

            <Doc
              blocks={note.blocks}
              onChange={change(note.id)}
              focus={freshId === note.id ? { id: note.blocks[0].id, all: true } : undefined}
            />
          </article>
        )}
      </div>
    </main>
  )
}
