import * as React from 'react'
import { Link, createFileRoute } from '@tanstack/react-router'
import { ChanLine, ChanLinkedin, ChanMail, ChanSlack, Chevron } from '~/components/safelight/icons'
import { cue, markCued, openChat, useEscape } from '~/components/safelight/hooks'
import agentsCss from '~/styles/agents.css?url'

export const Route = createFileRoute('/app/agents')({
  head: () => ({
    links: [{ rel: 'stylesheet', href: agentsCss }],
  }),
  component: Agents,
})

/* ══ Agents · configuration first, runs behind a toggle (ruling 10) ══
   SETUP (default): the roster as a quiet configuration list; a row opens
   the AGENT SHEET in place of the roster (back door). '+ new agent' opens
   the same sheet empty. RUNS: what runs now (open → the agent line, stop
   settles in place, rule 34) · what already ran today · what waits (inbox).
   Nothing rests red here: the name in the agent's ink is the presence. */

type AgentKey = 'eiri' | 'tory' | 'antevon'
type RunKey = 'eiri' | 'tory'
type Creature = AgentKey | 'none'
type ChanId = 'slack' | 'line' | 'mail' | 'linkedin'
type Schedule = 'continuous' | 'mornings' | 'nights' | 'on ask'

type Door = { label: string; tip: string; to?: '/app/inbox' | '/app/vault'; href?: string }
type Tail = { when: string; what: string; door: Door }
type Grant = { v: string; tip: string; by: 'o' | 'y'; byTip: string; when: string; whenTip: string }

type Agent = {
  key: AgentKey
  name: string
  tip: string
  creature: { w: number; h: number; alt: string }
  charter: string
  detail: string
  model: string
  modelTip: string
  budget: string
  budgetTip: string
  budgetLadder: string[] | null
  budgetCap: string | null
  channels: ChanId[]
  schedule: Schedule
  scheduleTip: string
  voice: string
  last: string
  lastTip: string
  verbs: Grant[]
  tail: Tail[]
}

/* creatures are the ratified set (public/art/creatures), drawn at native
   pixel size; the roster shows them at 2×, the sheet at 3×, pixel-true */
const AGENTS: Agent[] = [
  {
    key: 'eiri',
    name: 'Eiri',
    tip: 'Eiri · outbound · bound to you',
    creature: { w: 30, h: 24, alt: 'Eiri, the pigeon' },
    charter: 'Reaches out and keeps the thread warm.',
    detail:
      'Eiri writes outward in your register: intros, follow-ups, the note after a call. She may draft anything and promise nothing. Every send waits for your click. The sent copy comes back into the vault as a record.',
    model: 'kimi-k2.6',
    modelTip: 'kimi-k2.6 · pinned 08-02 · the model card and what it costs',
    budget: '¥170 of ¥600',
    budgetTip: '¥170 spent today of a ¥600 day cap · the cap pauses the agent, it never bills past it',
    budgetLadder: ['¥300', '¥600', '¥1,200'],
    budgetCap: '¥600',
    channels: ['line', 'mail'],
    schedule: 'on ask',
    scheduleTip: 'wakes on your ask, an inbound message, or a click on send',
    voice:
      'Writes in Yuki’s register. Short and warm, no exclamation marks. Japanese when the contact writes Japanese.',
    last: '14:09',
    lastTip: 'the last run settled at 14:09',
    verbs: [
      { v: 'read', tip: 'clients, base · standing · never the internal world', by: 'o', byTip: 'granted by Owen', when: '08-02', whenTip: 'granted 2026-08-02 · standing' },
      { v: 'propose', tip: 'claims from what she sends and hears · they wait for you', by: 'o', byTip: 'granted by Owen', when: '08-02', whenTip: 'granted 2026-08-02 · standing' },
      { v: 'draft', tip: 'any world she can read · drafts land in the inbox', by: 'o', byTip: 'granted by Owen', when: '08-02', whenTip: 'granted 2026-08-02 · standing' },
      { v: 'send', tip: 'LINE, email · one click per send · 20 a month', by: 'y', byTip: 'granted by Yuki', when: '08-07', whenTip: 'granted 2026-08-07 · expires 2026-10-07 · 20 sends a month' },
    ],
    tail: [
      {
        when: '14:02',
        what: 'Drafted the quote reply for Mika Tanaka. It waits on you.',
        door: { label: 'open', tip: 'the draft, in the inbox', to: '/app/inbox' },
      },
      {
        when: '11:20',
        what: 'Sent the pilot scope summary and verified it in the thread.',
        door: { label: 'receipt', tip: 'run rx_8c41 · the send, its grant and its verification', href: '#' },
      },
      {
        when: '09:15',
        what: 'Turned Mika Tanaka’s message into one claim.',
        door: { label: 'receipt', tip: 'run rx_8104 · source span, confidence, world', href: '#' },
      },
    ],
  },
  {
    key: 'tory',
    name: 'Tory',
    tip: 'Tory · research',
    creature: { w: 21, h: 26, alt: 'Tory, the fox' },
    charter: 'Reads filings and rumors, brings back claims.',
    detail:
      'Tory reads outward: filings, trade press, the client’s own site. She proposes claims and grades her own evidence, so a thin source stays thin. Nothing she finds becomes a memory until someone accepts it. She has never had a write.',
    model: 'kimi-k2.6',
    modelTip: 'kimi-k2.6 · pinned 08-02 · the model card and what it costs',
    budget: '¥110 of ¥450',
    budgetTip: '¥110 spent today of a ¥450 day cap · research is the cheap half of the roster',
    budgetLadder: ['¥150', '¥450', '¥900'],
    budgetCap: '¥450',
    channels: [],
    schedule: 'continuous',
    scheduleTip: 'the filings watch wakes every four hours · reads only',
    voice: 'Reports plainly. Grades every source. Says so when she finds nothing.',
    last: '14:09',
    lastTip: 'the last run settled at 14:09',
    verbs: [
      { v: 'read', tip: 'clients, base, the open web · standing', by: 'o', byTip: 'granted by Owen', when: '08-02', whenTip: 'granted 2026-08-02 · standing' },
      { v: 'propose', tip: 'claims only · every one carries its source and its floor', by: 'o', byTip: 'granted by Owen', when: '08-02', whenTip: 'granted 2026-08-02 · standing' },
    ],
    tail: [
      {
        when: '12:48',
        what: 'Read the Kansai freight filings for anything on Hokuei.',
        door: { label: 'receipt', tip: 'run rx_9033 · four writes, none waited', href: '#' },
      },
      {
        when: '11:05',
        what: 'Found nothing new in the July filings. The absence is recorded.',
        door: { label: 'receipt', tip: 'run rx_8e77 · a silence is evidence too · nothing minted', href: '#' },
      },
      {
        when: '08:30',
        what: 'Graded the supplier rumor at 0.41, one source.',
        door: { label: 'the claim', tip: 'the claim, its confidence and its lone source', to: '/app/vault' },
      },
    ],
  },
  {
    key: 'antevon',
    name: 'Antevon',
    tip: 'Antevon · the house mind · the vault’s own voice',
    creature: { w: 30, h: 16, alt: 'Antevon, the moth' },
    charter: 'Consolidates the vault every night and speaks for the house.',
    detail:
      'Antevon is the vault’s own voice. Every night it consolidates what the day brought in, and every write carries a receipt. By day it answers for the house, in Slack and email, and cites the vault when it does. It runs on this machine, so nothing leaves it.',
    model: 'qwen3-4b',
    modelTip: 'qwen3-4b · runs on this machine · nothing leaves it',
    budget: '¥0 · local',
    budgetTip: 'local inference · no credits, no metered tokens · electricity is the whole bill',
    budgetLadder: null,
    budgetCap: null,
    channels: ['slack', 'mail'],
    schedule: 'nights',
    scheduleTip: 'the nightly pass · 02:40, every night · answers by day when asked',
    voice: 'Speaks for the house. Cites the vault. Never promises.',
    last: '03:12',
    lastTip: 'run rx_7b12 · finished 03:12 · 42 writes · every write receipted',
    verbs: [
      { v: 'read', tip: 'every world, including internal · standing', by: 'o', byTip: 'granted by Owen', when: '07-19', whenTip: 'granted 2026-07-19 · at mint · standing' },
      { v: 'consolidate', tip: 'the nightly pass · claims in, receipts out', by: 'o', byTip: 'granted by Owen', when: '07-19', whenTip: 'granted 2026-07-19 · at mint · standing' },
      { v: 'answer', tip: 'Slack, email · answers cite the vault', by: 'o', byTip: 'granted by Owen', when: '07-28', whenTip: 'granted 2026-07-28 · Slack, email' },
    ],
    tail: [
      {
        when: '14:05',
        what: 'Answered #ops on the pilot timeline and cited the scope note.',
        door: { label: 'receipt', tip: 'slack · #ops · the answer and its citation', href: '#' },
      },
      {
        when: '03:20',
        what: 'Wrote the night-shift note after the consolidation.',
        door: { label: 'open', tip: 'the note, in the inbox', to: '/app/inbox' },
      },
      {
        when: '03:12',
        what: 'Consolidated the night: 42 claims went in, two waited for you.',
        door: { label: 'receipt', tip: 'run rx_7b12 · every claim the night pass touched, with its reason', href: '#' },
      },
    ],
  },
]

/* the live runs (the agent line points here) */
const RUNS: Array<{
  agent: RunKey
  doing: string
  tip: string
  since: string
  world: string
  elapsed: string
  tokens: string
  cost: string
}> = [
  {
    agent: 'eiri',
    doing: 'Drafting the COO intro, in Yuki’s register',
    tip: 'run rx_9b20 · started 13:55 · it will queue, not send',
    since: '13:55',
    world: 'hokuei',
    elapsed: '12m',
    tokens: '3.1k',
    cost: '¥4',
  },
  {
    agent: 'tory',
    doing: 'Checking the supplier rumor against the filings',
    tip: 'run rx_9b07 · started 13:26 · read-only scope',
    since: '13:26',
    world: 'hokuei',
    elapsed: '41m',
    tokens: '18k',
    cost: '¥21',
  },
]

/* what already ran today, newest first */
const HISTORY: Array<{
  id: string
  tip: string
  ran: string
  by: AgentKey
  writes: number
  waited: number
  waitedTip: string
  receiptTip: string
  wake: string
  wakeTip: string
}> = [
  {
    id: 'rx_9033',
    tip: 'run rx_9033 · 12:41 to 12:48 · 31k tokens · ¥17',
    ran: 'Read the Kansai freight filings for anything on Hokuei',
    by: 'tory',
    writes: 4,
    waited: 0,
    waitedTip: 'nothing waited · every write cleared the floor',
    receiptTip: 'sources read, claims written, cost',
    wake: 'woke 12:41 · schedule',
    wakeTip: 'the filings watch wakes every four hours',
  },
  {
    id: 'rx_8c41',
    tip: 'run rx_8c41 · 11:14 to 11:20 · 8k tokens · ¥5',
    ran: 'Sent the pilot scope summary, then verified it in the thread',
    by: 'eiri',
    writes: 1,
    waited: 0,
    waitedTip: 'nothing waited · you had already approved the send',
    receiptTip: 'the draft you approved, the grant it sent under, the verification',
    wake: 'woke 11:14 · your click',
    wakeTip: 'your click on send woke the run',
  },
  {
    id: 'rx_8104',
    tip: 'run rx_8104 · 09:15 · 3k tokens · ¥2',
    ran: 'Turned Mika Tanaka’s LINE message into one claim',
    by: 'eiri',
    writes: 2,
    waited: 0,
    waitedTip: 'nothing waited · the claim came straight from her words',
    receiptTip: 'the thread entry the claim came from',
    wake: 'woke 09:15 · LINE',
    wakeTip: 'an inbound LINE message woke the run',
  },
  {
    id: 'rx_7b12',
    tip: 'run rx_7b12 · 02:40 to 03:12 · 76k tokens · ¥0 · local',
    ran: 'Nightly consolidation across base and clients',
    by: 'antevon',
    writes: 42,
    waited: 2,
    waitedTip: 'two claims waited for you · both accepted at 08:20 · history, not a queue',
    receiptTip: 'every claim the night pass touched, with its reason',
    wake: 'woke 02:40 · nightly',
    wakeTip: 'the nightly pass · 02:40, every night',
  },
]

const NAMES: Record<AgentKey, string> = { eiri: 'Eiri', tory: 'Tory', antevon: 'Antevon' }

/* the ledger's columns · the shape TanStack Table uses, so a real table is
   a swap, not a rewrite. a column sorts only where it has an accessor. */
type HistRow = (typeof HISTORY)[number]
type HistColId = 'ran' | 'by' | 'writes' | 'waited' | 'receipt' | 'wake'
const HIST_COLS: Array<{
  id: HistColId
  header: string
  cls?: string
  accessor?: (r: HistRow) => string | number
}> = [
  { id: 'ran', header: 'run', accessor: (r) => r.ran },
  { id: 'by', header: 'by', cls: 'c-by', accessor: (r) => NAMES[r.by] },
  { id: 'writes', header: 'writes', cls: 'c-num num', accessor: (r) => r.writes },
  { id: 'waited', header: 'waited', cls: 'c-num num', accessor: (r) => r.waited },
  { id: 'receipt', header: 'receipt', cls: 'c-rcpt' },
  { id: 'wake', header: 'wake', cls: 'c-wake', accessor: (r) => r.wake },
]
const SETTLE_AT = '14:09'

const CHANNELS: Array<{ id: ChanId; label: string; tip: string; Glyph: () => React.JSX.Element }> = [
  { id: 'slack', label: 'Slack', tip: 'Slack · the workspace connected in settings', Glyph: ChanSlack },
  { id: 'line', label: 'LINE', tip: 'LINE · the official account connected in settings', Glyph: ChanLine },
  { id: 'mail', label: 'email', tip: 'email · the house mailbox', Glyph: ChanMail },
  { id: 'linkedin', label: 'LinkedIn', tip: 'LinkedIn · Yuki’s account, reads only', Glyph: ChanLinkedin },
]
const SCHEDULES: Array<{ id: Schedule; tip: string }> = [
  { id: 'continuous', tip: 'wakes on its own watch, every few hours' },
  { id: 'mornings', tip: 'one pass every morning at 08:00' },
  { id: 'nights', tip: 'one pass every night at 02:40' },
  { id: 'on ask', tip: 'wakes only when asked, or when a message arrives' },
]
const CREATURES: Array<{ id: Creature; alt: string; w: number; h: number; tip: string }> = [
  { id: 'eiri', alt: 'the pigeon', w: 30, h: 24, tip: 'the pigeon' },
  { id: 'tory', alt: 'the fox', w: 21, h: 26, tip: 'the fox' },
  { id: 'antevon', alt: 'the moth', w: 30, h: 16, tip: 'the moth' },
  { id: 'none', alt: '', w: 24, h: 24, tip: 'no creature · the name alone' },
]

/* the editable configuration of one agent — the fixtures seed it; a new
   agent starts empty. Every change settles in place with a quiet stamp. */
type Config = {
  id: string
  ink: AgentKey | null
  creature: Creature
  name: string
  role: string
  detail: string
  channels: ChanId[]
  grants: Array<Grant & { revoked?: string }>
  schedule: Schedule | null
  cap: string | null
  voice: string
  fixture: Agent | null
}

function seed(a: Agent): Config {
  return {
    id: a.key,
    ink: a.key,
    creature: a.key,
    name: a.name,
    role: a.charter,
    detail: a.detail,
    channels: a.channels,
    grants: a.verbs.map((g) => ({ ...g })),
    schedule: a.schedule,
    cap: a.budgetCap,
    voice: a.voice,
    fixture: a,
  }
}
function blank(id: string): Config {
  return {
    id,
    ink: null,
    creature: 'none',
    name: '',
    role: '',
    detail: '',
    channels: [],
    grants: [],
    schedule: null,
    cap: null,
    voice: '',
    fixture: null,
  }
}

function now() {
  const d = new Date()
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
}

/* a door: a Link where the route exists, a plain anchor otherwise */
function DoorAct({ door, className = 'act' }: { door: Door; className?: string }) {
  if (door.to) {
    return (
      <Link className={className} to={door.to} title={door.tip}>
        {door.label}
      </Link>
    )
  }
  return (
    <a className={className} href={door.href ?? '#'} title={door.tip}>
      {door.label}
    </a>
  )
}

/* the creature img path stays one <img> per creature so a swap is a file */
function CreatureImg({ c, scale, alt }: { c: Creature; scale: 2 | 3; alt?: string }) {
  if (c === 'none') return <span className="creature-none" aria-hidden="true" />
  const spec = CREATURES.find((x) => x.id === c)!
  /* the face: one mask in the agent's ink (D); 32 in rows, 72 on the sheet */
  const px = scale === 3 ? 72 : 32
  return <span className="face" data-agent={c} role="img" aria-label={alt ?? spec.alt} style={{ width: px, height: px }} />
}

/* headings collapse in place (rule 10); the count shows only when closed */
function Section({
  label,
  title,
  meta,
  voice,
  children,
}: {
  label: string
  title: string
  meta?: React.ReactNode
  voice?: React.ReactNode
  children: React.ReactNode
}) {
  const [closed, setClosed] = React.useState(false)
  const toggle = () => {
    setClosed((c) => !c)
    cue('toggle')
  }
  return (
    <section className={closed ? 'ag-sec closed' : 'ag-sec'} aria-label={label}>
      <div
        className="ag-head"
        tabIndex={0}
        role="button"
        aria-expanded={!closed}
        onClick={(e) => {
          if ((e.target as HTMLElement).closest('a')) return
          toggle()
        }}
        onKeyDown={(e) => {
          if ((e.key === 'Enter' || e.key === ' ') && !(e.target as HTMLElement).closest('a')) {
            e.preventDefault()
            toggle()
          }
        }}
      >
        <span className="ag-title">{title}</span>
        <span className="fold-hint" aria-hidden="true">
          <Chevron ariaHidden={false} />
        </span>
        {meta}
      </div>
      {voice}
      <div className="ag-rows">{children}</div>
    </section>
  )
}

/* an editable line or paragraph: contentEditable, settles on blur */
function Editable({
  as = 'span',
  className,
  value,
  placeholder,
  onCommit,
  autoFocus,
  title,
}: {
  as?: 'span' | 'p' | 'h1'
  className?: string
  value: string
  placeholder: string
  onCommit: (next: string) => void
  autoFocus?: boolean
  title?: string
}) {
  const ref = React.useRef<HTMLElement | null>(null)
  React.useEffect(() => {
    if (autoFocus && ref.current) ref.current.focus()
  }, [autoFocus])
  const Tag = as as 'span'
  return (
    <Tag
      ref={ref as React.RefObject<HTMLSpanElement>}
      className={className ? `edit ${className}` : 'edit'}
      contentEditable
      suppressContentEditableWarning
      spellCheck={false}
      role="textbox"
      aria-label={placeholder}
      aria-multiline={as === 'p' || undefined}
      data-empty={value ? undefined : ''}
      data-placeholder={placeholder}
      title={title ?? 'click to edit · it settles when you leave'}
      onInput={(e) => {
        /* an emptied field keeps a <br>: strip it so the placeholder shows */
        const el = e.currentTarget as HTMLElement
        const empty = !(el.textContent ?? '').trim()
        if (empty && el.innerHTML) el.innerHTML = ''
        el.toggleAttribute('data-empty', empty)
      }}
      onBlur={(e) => {
        const next = (e.currentTarget.textContent ?? '').trim()
        if (next !== value) onCommit(next)
      }}
      onKeyDown={(e) => {
        if (as !== 'p' && e.key === 'Enter') {
          e.preventDefault()
          ;(e.currentTarget as HTMLElement).blur()
        }
      }}
    >
      {value}
    </Tag>
  )
}

function Agents() {
  const [hintOpen, setHintOpen] = React.useState(false)
  const [view, setView] = React.useState<'setup' | 'runs'>('setup')
  /* the roster's configuration; fixtures seed it, new agents join it */
  const [configs, setConfigs] = React.useState<Config[]>(() => AGENTS.map(seed))
  /* the sheet: which agent stands in place of the roster */
  const [sheet, setSheet] = React.useState<string | null>(null)
  /* the quiet stamps: `${id}:${section}` → hh:mm */
  const [saved, setSaved] = React.useState<Record<string, string>>({})
  /* revoke arms red, then settles on the second click */
  const [armed, setArmed] = React.useState<string | null>(null)
  /* pause parks the agent (nothing new starts; the live run finishes) */
  const [paused, setPaused] = React.useState<Record<string, string>>({})
  /* stop = the cancel signal (rule 34): the run settles midway, in place */
  const [stopped, setStopped] = React.useState<Partial<Record<RunKey, boolean>>>({})
  /* a click on a row unfolds the glance under it; `open` hands the sheet */
  const [glance, setGlance] = React.useState<string | null>(null)
  /* the ledger sorts on its heads: asc → desc → off */
  const [sort, setSort] = React.useState<{ id: HistColId; dir: 'asc' | 'desc' } | null>(null)
  const newCount = React.useRef(0)
  const rowRefs = React.useRef<Record<string, HTMLDivElement | null>>({})
  const backRef = React.useRef<HTMLButtonElement | null>(null)
  const returnTo = React.useRef<string | null>(null)

  const closeSheet = React.useCallback(() => {
    /* an unnamed new agent leaves no trace */
    if (sheet) setConfigs((cs) => cs.filter((c) => !(c.id === sheet && !c.fixture && !c.name)))
    setSheet(null)
    setArmed(null)
  }, [sheet])

  useEscape(() => {
    /* esc inside a field leaves the field first (the edit settles); the
       next esc closes the sheet */
    const el = document.activeElement as HTMLElement | null
    if (el && el.classList.contains('edit')) {
      el.blur()
      return
    }
    if (armed) {
      setArmed(null)
      return
    }
    if (sheet) {
      closeSheet()
      cue('toggle')
      return
    }
    if (glance) {
      setGlance(null)
      cue('toggle')
      return
    }
    setHintOpen(false)
  })

  const stamp = (id: string, section: string) => {
    setSaved((s) => ({ ...s, [`${id}:${section}`]: now() }))
    cue('press')
  }
  const patch = (id: string, section: string, fn: (c: Config) => Config) => {
    setConfigs((cs) => cs.map((c) => (c.id === id ? fn(c) : c)))
    stamp(id, section)
  }

  const openSheet = (id: string, from?: string) => {
    returnTo.current = from ?? null
    setSheet(id)
    cue('toggle')
  }
  const toggleGlance = (id: string) => {
    setGlance((g) => (g === id ? null : id))
    cue('toggle')
  }
  /* enter (or →) opens the setup · space unfolds the glance · ↑↓ walk the roster */
  const rowKey = (e: React.KeyboardEvent, id: string, i: number) => {
    if (e.key === 'Enter' || e.key === 'ArrowRight') {
      e.preventDefault()
      openSheet(id, id)
      return
    }
    if (e.key === ' ') {
      e.preventDefault()
      toggleGlance(id)
      return
    }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault()
      const next = configs[i + (e.key === 'ArrowDown' ? 1 : -1)]
      if (next) rowRefs.current[next.id]?.focus()
    }
  }
  /* the sheet replaces the roster, so focus has to travel with it */
  React.useEffect(() => {
    if (sheet) {
      /* a new agent focuses its name field instead */
      if (configs.find((c) => c.id === sheet)?.fixture) backRef.current?.focus()
    } else if (returnTo.current) {
      rowRefs.current[returnTo.current]?.focus()
      returnTo.current = null
    }
  }, [sheet]) // eslint-disable-line react-hooks/exhaustive-deps
  const newAgent = (e: React.MouseEvent) => {
    markCued(e)
    newCount.current += 1
    const id = `new-${newCount.current}`
    setConfigs((cs) => [...cs, blank(id)])
    setSheet(id)
    cue('toggle')
  }

  const pause = (id: string) => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setPaused((p) => ({ ...p, [id]: now() }))
    cue('press')
  }
  const resume = (id: string) => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setPaused((p) => {
      const next = { ...p }
      delete next[id]
      return next
    })
    cue('press')
  }
  const stop = (key: RunKey) => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setStopped((s) => ({ ...s, [key]: true }))
    cue('press')
  }

  /* what the roster derives from the live runs */
  const runOf = (id: string) => RUNS.find((r) => r.agent === id)
  const isLive = (id: string) => {
    const r = runOf(id)
    return !!r && !stopped[r.agent]
  }
  const stateWord = (c: Config) => {
    if (!c.fixture) return { word: 'draft', tip: 'a new agent · not yet running · name it and grant it something' }
    if (paused[c.id]) return { word: 'paused', tip: `paused ${paused[c.id]} · the live run finishes, nothing new starts` }
    if (isLive(c.id)) return { word: 'live', tip: `live now · ${runOf(c.id)?.doing ?? ''} · see runs` }
    return { word: c.schedule ?? '', tip: c.fixture.scheduleTip }
  }

  const liveCount = RUNS.filter((r) => !stopped[r.agent]).length
  const writes = HISTORY.reduce((n, h) => n + h.writes, 0)
  const waited = HISTORY.reduce((n, h) => n + h.waited, 0)

  const chatWith = (c: Config) => (c.id === 'antevon' ? ('ask' as const) : (c.id as RunKey))
  const chatWord = (c: Config) => (c.id === 'antevon' ? 'ask' : isLive(c.id) ? 'open the run' : 'chat')
  const chatTip = (c: Config) =>
    c.id === 'antevon'
      ? 'asks the house mind, in the agent line'
      : isLive(c.id)
        ? 'opens the run in the agent line'
        : 'opens a chat with the agent'

  /* the ledger sorts on its heads: asc → desc → off, the given order last */
  const cycleSort = (id: HistColId) => {
    setSort((x) => (!x || x.id !== id ? { id, dir: 'asc' } : x.dir === 'asc' ? { id, dir: 'desc' } : null))
    cue('toggle')
  }
  const histRows = React.useMemo(() => {
    const col = sort ? HIST_COLS.find((c) => c.id === sort.id) : null
    if (!sort || !col?.accessor) return HISTORY
    const get = col.accessor
    const dir = sort.dir === 'asc' ? 1 : -1
    return [...HISTORY].sort((a, b) => {
      const x = get(a)
      const y = get(b)
      return (typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y))) * dir
    })
  }, [sort])

  const current = sheet ? configs.find((c) => c.id === sheet) ?? null : null

  /* ── the agent sheet: the roster steps aside; a back door returns ── */
  const renderSheet = (c: Config) => {
    const isNew = !c.fixture
    const Saved = ({ k }: { k: string }) => {
      const t = saved[`${c.id}:${k}`]
      return t ? (
        <span className="meta-line saved" title="settled in place · nothing to confirm">
          saved · {t}
        </span>
      ) : null
    }
    return (
      <section className="sheet" aria-label={c.name || 'new agent'}>
        <div className="sheet-top">
          <button
            type="button"
            className="act back"
            ref={backRef}
            title="back · esc"
            onClick={(e) => {
              markCued(e)
              closeSheet()
              cue('toggle')
            }}
          >
            back
          </button>
          {c.fixture ? (
            <span className="meta-line">
              <span title={c.fixture.modelTip}>{c.fixture.model}</span>
              {' · '}
              <span title={c.fixture.lastTip}>last run {c.fixture.last}</span>
            </span>
          ) : null}
        </div>

        {/* identity: creature large · name · role line · state acts */}
        <div className="identity" data-agent={c.ink ?? undefined}>
          <div className={c.creature === 'none' ? 'id-creature none' : 'id-creature'} title={c.fixture?.tip}>
            <CreatureImg c={c.creature} scale={3} alt={c.fixture?.creature.alt} />
          </div>
          <div className="id-text">
            <Editable
              as="h1"
              className={c.ink ? 'id-name aname' : 'id-name'}
              value={c.name}
              placeholder="name your agent"
              autoFocus={isNew && !c.name}
              onCommit={(v) => patch(c.id, 'identity', (x) => ({ ...x, name: v }))}
            />
            <Editable
              as="span"
              className="id-role"
              value={c.role}
              placeholder="what it is for, in one line"
              onCommit={(v) => patch(c.id, 'identity', (x) => ({ ...x, role: v }))}
            />
            <div className="id-acts">
              {c.fixture ? (
                c.id === 'antevon' ? (
                  <span
                    className="always"
                    title="the house mind is the vault’s own · it wakes with the vault, it does not pause"
                  >
                    always on
                  </span>
                ) : paused[c.id] ? (
                  <>
                    <span className="meta-line" title="nothing new starts · the live run finishes">
                      paused {paused[c.id]}
                    </span>
                    <button className="act" title="verb: resume_agent" onClick={resume(c.id)}>
                      resume
                    </button>
                  </>
                ) : (
                  <button
                    className="act"
                    title="verb: pause_agent · the live run finishes, nothing new starts"
                    onClick={pause(c.id)}
                  >
                    pause
                  </button>
                )
              ) : null}
              {c.fixture ? (
                <button
                  type="button"
                  className="act"
                  title={chatTip(c)}
                  onClick={(e) => {
                    markCued(e)
                    openChat(chatWith(c))
                  }}
                >
                  {chatWord(c)}
                </button>
              ) : null}
              <Saved k="identity" />
            </div>
          </div>
        </div>

        {isNew ? (
          <div className="sec" aria-label="creature">
            <span className="label">creature</span>
            <div className="picker">
              {CREATURES.map((cr) => (
                <button
                  key={cr.id}
                  type="button"
                  className={c.creature === cr.id ? 'pick on' : 'pick'}
                  aria-pressed={c.creature === cr.id}
                  title={cr.tip}
                  onClick={(e) => {
                    markCued(e)
                    patch(c.id, 'creature', (x) => ({ ...x, creature: cr.id }))
                  }}
                >
                  {cr.id === 'none' ? <span className="pick-none">none</span> : <CreatureImg c={cr.id} scale={2} />}
                </button>
              ))}
            </div>
            <Saved k="creature" />
          </div>
        ) : null}

        <div className="sec" aria-label="what it does">
          <span className="label">what it does</span>
          <Editable
            as="p"
            className="detail"
            value={c.detail}
            placeholder="Say what it does. Short sentences. One idea each."
            onCommit={(v) => patch(c.id, 'detail', (x) => ({ ...x, detail: v }))}
          />
          <Saved k="detail" />
        </div>

        <div className="sec" aria-label="channels">
          <span className="label">channels it may use</span>
          <div className="chans">
            {CHANNELS.map((ch) => {
              const on = c.channels.includes(ch.id)
              return (
                <button
                  key={ch.id}
                  type="button"
                  className={on ? 'chan on' : 'chan'}
                  aria-pressed={on}
                  title={`${ch.tip} · ${on ? 'on · click to turn off' : 'off · click to turn on'}`}
                  onClick={(e) => {
                    markCued(e)
                    patch(c.id, 'channels', (x) => ({
                      ...x,
                      channels: on ? x.channels.filter((k) => k !== ch.id) : [...x.channels, ch.id],
                    }))
                  }}
                >
                  <span className="chan-glyph">
                    <ch.Glyph />
                  </span>
                  <span className="chan-name">{ch.label}</span>
                </button>
              )
            })}
            <Link className="act chan-door" to="/settings/connectors" title="connect a workspace, or revoke one">
              connect
            </Link>
          </div>
          <Saved k="channels" />
        </div>

        <div className="sec" aria-label="scopes">
          <span className="label">scopes · the grants it holds</span>
          {c.grants.length === 0 ? (
            <p className="empty">
              No grants yet.{' '}
              <Link className="act" to="/settings/grants" title="grants are given in settings">
                give one
              </Link>
            </p>
          ) : (
            <div className="grants">
              {c.grants.map((g) => {
                const armKey = `${c.id}:${g.v}`
                const isArmed = armed === armKey
                return (
                  <div key={g.v} className={g.revoked ? 'grant revoked' : 'grant'}>
                    <span className="g-scope" title={g.tip}>
                      {g.v}
                    </span>
                    <span className="g-what">{g.tip.split(' · ')[0]}</span>
                    <span className="seal seal-human" title={g.byTip}>
                      {g.by}
                    </span>
                    <span className="g-when" title={g.whenTip}>
                      {g.when}
                    </span>
                    {g.revoked ? (
                      <span className="g-acts">
                        <span className="meta-line" title="the grant is gone · the agent lost this verb">
                          revoked · {g.revoked}
                        </span>
                        <button
                          type="button"
                          className="act"
                          title="give the grant back"
                          onClick={(e) => {
                            markCued(e)
                            patch(c.id, 'scopes', (x) => ({
                              ...x,
                              grants: x.grants.map((h) => (h.v === g.v ? { ...h, revoked: undefined } : h)),
                            }))
                          }}
                        >
                          restore
                        </button>
                      </span>
                    ) : (
                      <span className="g-acts">
                        <button
                          type="button"
                          className={isArmed ? 'act revoke armed' : 'act revoke'}
                          title={isArmed ? 'click again to revoke · esc keeps it' : 'revoke this grant · asks once'}
                          onClick={(e) => {
                            markCued(e)
                            if (!isArmed) {
                              setArmed(armKey)
                              cue('toggle')
                              return
                            }
                            setArmed(null)
                            patch(c.id, 'scopes', (x) => ({
                              ...x,
                              grants: x.grants.map((h) => (h.v === g.v ? { ...h, revoked: now() } : h)),
                            }))
                          }}
                          onBlur={() => {
                            if (isArmed) setArmed(null)
                          }}
                        >
                          {isArmed ? 'revoke?' : 'revoke'}
                        </button>
                      </span>
                    )}
                  </div>
                )
              })}
            </div>
          )}
          <Saved k="scopes" />
        </div>

        <div className="sec" aria-label="schedule">
          <span className="label">schedule</span>
          <div className="ladder">
            {SCHEDULES.map((s) => (
              <button
                key={s.id}
                type="button"
                className={c.schedule === s.id ? 'rung on' : 'rung'}
                aria-pressed={c.schedule === s.id}
                title={s.tip}
                onClick={(e) => {
                  markCued(e)
                  patch(c.id, 'schedule', (x) => ({ ...x, schedule: s.id }))
                }}
              >
                {s.id}
              </button>
            ))}
          </div>
          <Saved k="schedule" />
        </div>

        <div className="sec" aria-label="budget">
          <span className="label">budget · a day</span>
          {c.fixture && !c.fixture.budgetLadder ? (
            <div className="ladder">
              <span className="rung local" title={c.fixture.budgetTip}>
                local · no cap
              </span>
            </div>
          ) : (
            <div className="ladder">
              {(c.fixture?.budgetLadder ?? ['¥300', '¥600', '¥1,200']).map((b) => (
                <button
                  key={b}
                  type="button"
                  className={c.cap === b ? 'rung on' : 'rung'}
                  aria-pressed={c.cap === b}
                  title={`${b} a day · the cap pauses the agent, it never bills past it`}
                  onClick={(e) => {
                    markCued(e)
                    patch(c.id, 'budget', (x) => ({ ...x, cap: b }))
                  }}
                >
                  {b}
                </button>
              ))}
              {c.fixture ? (
                <span className="spent" title={c.fixture.budgetTip}>
                  {c.fixture.budget.split(' of ')[0]} today
                </span>
              ) : null}
            </div>
          )}
          <Saved k="budget" />
        </div>

        <div className="sec" aria-label="voice">
          <span className="label">voice</span>
          <Editable
            as="p"
            className="voice"
            value={c.voice}
            placeholder="How it speaks. Register, length, language."
            onCommit={(v) => patch(c.id, 'voice', (x) => ({ ...x, voice: v }))}
          />
          <Saved k="voice" />
        </div>

        {c.fixture ? (
          <div className="sec" aria-label="recent">
            <span className="label">recent</span>
            <div className="rd-tail">
              {c.fixture.tail.map((t) => (
                <div key={t.when + t.what} className="tl">
                  <span className="when">{t.when}</span>
                  <span className="what">{t.what}</span>
                  <DoorAct door={t.door} />
                </div>
              ))}
            </div>
          </div>
        ) : null}
      </section>
    )
  }

  return (
    <main className="pane" id="pane">
      <div className="pane-body">
        {current ? (
          renderSheet(current)
        ) : (
          <>
            <div className="pane-head">
              <h1>Agents</h1>
              <span className="views" role="group" aria-label="view">
                <button
                  type="button"
                  className="act"
                  aria-pressed={view === 'setup'}
                  title="who works here and how each is set up"
                  onClick={(e) => {
                    markCued(e)
                    setView('setup')
                    cue('toggle')
                  }}
                >
                  setup
                </button>
                <span className="sep" aria-hidden="true">
                  ·
                </span>
                <button
                  type="button"
                  className="act"
                  aria-pressed={view === 'runs'}
                  title="what runs now and what already ran today"
                  onClick={(e) => {
                    markCued(e)
                    setView('runs')
                    cue('toggle')
                  }}
                >
                  runs
                </button>
              </span>
              <span className="pane-tools">
                {view === 'runs' ? (
                  <span className="meta-line" title="what the roster spent today · as of 14:07">
                    ¥280 today · as of 14:07
                  </span>
                ) : (
                  <button
                    type="button"
                    className="act"
                    title="a new agent · name it, pick a creature, grant it something"
                    onClick={newAgent}
                  >
                    + new agent
                  </button>
                )}
                <button
                  className="hint-btn"
                  aria-expanded={hintOpen}
                  aria-controls="agents-why"
                  title="what this screen is"
                  onClick={() => {
                    setHintOpen((o) => !o)
                    cue('toggle')
                  }}
                >
                  ?
                </button>
              </span>
            </div>
            <div className="dial-why" id="agents-why" hidden={!hintOpen}>
              <span className="why-voice">
                {view === 'setup'
                  ? 'Who works in this vault. Click a row for the glance. Open it to change how it works.'
                  : 'What runs now and what already ran today. Every run ends in a receipt. What waits for you lives in the inbox.'}
              </span>
            </div>

            {view === 'setup' ? (
              /* ══ SETUP · the roster as a quiet configuration list. a click
                 unfolds the glance under the row (what it holds, what it
                 spends, when it last ran); `open` or enter hands the whole
                 sheet, and only then does the roster step aside. ══ */
              <section className="roster" aria-label="roster">
                {configs.map((c, i) => {
                  const st = stateWord(c)
                  const open = glance === c.id
                  const held = c.grants.filter((g) => !g.revoked).map((g) => g.v)
                  return (
                    <div key={c.id} className={open ? 'rrow open' : 'rrow'}>
                      <div
                        className={c.fixture ? 'rline' : 'rline draft'}
                        data-agent={c.ink ?? undefined}
                        role="button"
                        tabIndex={0}
                        aria-expanded={open}
                        ref={(el) => {
                          rowRefs.current[c.id] = el
                        }}
                        title={`${c.name || 'the new agent'} · click for the glance · enter opens the setup`}
                        onClick={(e) => {
                          if ((e.target as HTMLElement).closest('a, button')) return
                          toggleGlance(c.id)
                        }}
                        onKeyDown={(e) => rowKey(e, c.id, i)}
                      >
                        <span className="rcreature">
                          <CreatureImg c={c.creature} scale={2} alt={c.fixture?.creature.alt} />
                        </span>
                        <span className={c.ink ? 'rname aname' : 'rname'} title={c.fixture?.tip}>
                          {c.name || <span className="unnamed">unnamed</span>}
                        </span>
                        <span className="rcharter">{c.role || 'Nothing yet.'}</span>
                        <span className="rchans" aria-label="channels">
                          {CHANNELS.filter((ch) => c.channels.includes(ch.id)).map((ch) => (
                            <span key={ch.id} className="rchan" title={ch.label}>
                              <ch.Glyph />
                            </span>
                          ))}
                        </span>
                        <span className="rstate" title={st.tip}>
                          {st.word}
                        </span>
                      </div>
                      <div className="rdetail">
                        <div className="rd-inner">
                          <div className="rd-facts">
                            {held.length ? (
                              <>
                                <span className="label">holds</span>
                                <span className="rd-val" title="the verbs it holds · change them in its setup">
                                  {held.join(' · ')}
                                </span>
                              </>
                            ) : (
                              <span className="rd-none">No grants yet.</span>
                            )}
                            {c.fixture ? (
                              <>
                                <span className="label">today</span>
                                <span className="rd-val" title={c.fixture.budgetTip}>
                                  {c.cap
                                    ? `${c.fixture.budget.split(' of ')[0]} of ${c.cap}`
                                    : 'local · no cap'}
                                </span>
                                <span className="label">last run</span>
                                <span className="rd-val" title={c.fixture.lastTip}>
                                  {c.fixture.last}
                                </span>
                              </>
                            ) : null}
                          </div>
                          <div className="rd-acts">
                            <button
                              type="button"
                              className="act"
                              title={`everything about ${c.name || 'this agent'} · enter`}
                              onClick={(e) => {
                                markCued(e)
                                openSheet(c.id, c.id)
                              }}
                            >
                              set up
                            </button>
                            {c.fixture ? (
                              <button
                                type="button"
                                className="act"
                                title={chatTip(c)}
                                onClick={(e) => {
                                  markCued(e)
                                  openChat(chatWith(c))
                                }}
                              >
                                {chatWord(c)}
                              </button>
                            ) : null}
                            {c.fixture && c.id !== 'antevon' ? (
                              paused[c.id] ? (
                                <button className="act" title="verb: resume_agent" onClick={resume(c.id)}>
                                  resume
                                </button>
                              ) : (
                                <button
                                  className="act"
                                  title="verb: pause_agent · the live run finishes, nothing new starts"
                                  onClick={pause(c.id)}
                                >
                                  pause
                                </button>
                              )
                            ) : null}
                          </div>
                        </div>
                      </div>
                    </div>
                  )
                })}
              </section>
            ) : (
              <>
                {/* ══ NOW · the live runs. the name in ink is the presence; the
                    doing-text shimmers while live. stop settles the row in place:
                    still + dimmed, what landed stays (rule 34). ══ */}
                <Section
                  label="now"
                  title="Now"
                  meta={
                    <span className="meta-line" title="both runs are Hokuei work">
                      {liveCount} live
                    </span>
                  }
                >
                  <div className="now">
                    <div className="nhead" aria-hidden="true">
                      <span className="label">run</span>
                      <span className="label">world</span>
                      <span className="label h-num">elapsed</span>
                      <span className="label h-num">tokens</span>
                      <span className="label h-num">cost</span>
                      <span></span>
                    </div>
                    {RUNS.map((r) => {
                      const still = !!stopped[r.agent]
                      return (
                        <div key={r.agent} className={still ? 'nrow still' : 'nrow live'} data-agent={r.agent}>
                          <div className="nline">
                            <span className="nwho">
                              <span className="aname withface" title={r.tip}>
                                <span className="face mark" data-agent={r.agent} aria-hidden="true" />
                                {NAMES[r.agent]}
                              </span>
                              <span className="ndoing" title={still ? 'stopped · what landed stays' : r.doing}>
                                {r.doing}
                              </span>
                            </span>
                            <span className="ncell" title="world: hokuei · the pilot client">
                              {r.world}
                            </span>
                            <span
                              className="ncell n-num"
                              title={still ? `ran ${r.elapsed}, then stopped` : `running ${r.elapsed}`}
                            >
                              {r.elapsed}
                            </span>
                            <span className="ncell n-num" title="tokens so far">
                              {r.tokens}
                            </span>
                            <span className="ncell n-num" title="cost so far">
                              {r.cost}
                            </span>
                            <span className="nacts">
                              {still ? (
                                <span className="meta-line" title="stopped at its next breakpoint">
                                  stopped {SETTLE_AT}
                                </span>
                              ) : (
                                <>
                                  <button
                                    type="button"
                                    className="act"
                                    title="opens the run in the agent line"
                                    onClick={(e) => {
                                      markCued(e)
                                      openChat(r.agent)
                                    }}
                                  >
                                    open
                                  </button>
                                  <button
                                    className="act"
                                    title="settles at the next breakpoint · what landed stays"
                                    onClick={stop(r.agent)}
                                  >
                                    stop
                                  </button>
                                </>
                              )}
                            </span>
                          </div>
                          {still ? <p className="nreceipt">What landed stays. The thread stays open.</p> : null}
                        </div>
                      )
                    })}
                  </div>
                </Section>

                {/* ══ EARLIER TODAY · the run ledger; each row ends in a receipt
                    and names what woke it ══ */}
                <Section
                  label="earlier today"
                  title="Earlier today"
                  meta={
                    <span className="meta-line" title="today’s runs, all receipted">
                      {HISTORY.length} runs · {writes} writes · {waited} waited
                    </span>
                  }
                  voice={
                    <div className="ag-voice">
                      <span className="aname" data-agent="antevon" title="Antevon · the house mind · as of 14:07">
                        Antevon
                      </span>
                      <span>
                        Today was mostly Eiri. Nothing left the building without you. Tory’s supplier rumor
                        still rests on one source, so it stays a proposal.
                      </span>
                    </div>
                  }
                >
                  <div className="hist-wrap">
                    <table className="ledger hist">
                      <thead>
                        <tr>
                          {HIST_COLS.map((col) => {
                            const dir = sort?.id === col.id ? sort.dir : null
                            return (
                              <th
                                key={col.id}
                                className={dir ? `${col.cls ?? ''} sorted`.trim() : col.cls}
                                aria-sort={
                                  col.accessor
                                    ? dir === 'asc'
                                      ? 'ascending'
                                      : dir === 'desc'
                                        ? 'descending'
                                        : 'none'
                                    : undefined
                                }
                              >
                                {col.accessor ? (
                                  <span className="th-in">
                                    <button
                                      type="button"
                                      className="th-sort"
                                      title={`sort by ${col.header}`}
                                      onClick={(e) => {
                                        markCued(e)
                                        cycleSort(col.id)
                                      }}
                                    >
                                      {col.header}
                                      <span className="arrow" aria-hidden="true">
                                        {dir === 'asc' ? '↑' : dir === 'desc' ? '↓' : ''}
                                      </span>
                                    </button>
                                  </span>
                                ) : (
                                  col.header
                                )}
                              </th>
                            )
                          })}
                        </tr>
                      </thead>
                      <tbody>
                        {histRows.map((h) => (
                          <tr key={h.id}>
                            <td>
                              <span className="ran" title={h.tip}>
                                {h.ran}
                              </span>
                            </td>
                            <td>
                              <button
                                type="button"
                                className="aname withface"
                                data-agent={h.by}
                                title={`${NAMES[h.by]} · a door: its setup`}
                                onClick={(e) => {
                                  markCued(e)
                                  openSheet(h.by)
                                }}
                              >
                                <span className="face mark" data-agent={h.by} aria-hidden="true" />
                                {NAMES[h.by]}
                              </button>
                            </td>
                            <td className="num">
                              <span className="cnt">{h.writes}</span>
                            </td>
                            <td className="num">
                              {h.waited > 0 ? (
                                <a className="cnt" href="#" title={h.waitedTip}>
                                  {h.waited}
                                </a>
                              ) : (
                                <span className="cnt none" title={h.waitedTip}>
                                  {h.waited}
                                </span>
                              )}
                            </td>
                            <td>
                              <a className="act" href="#" title={h.receiptTip}>
                                open
                              </a>
                            </td>
                            <td>
                              <span className="wake" title={h.wakeTip}>
                                {h.wake}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Section>

                {/* what waits for you lives in the inbox — one home per item */}
                <div className="ag-quiet">
                  <span className="digest">
                    Two things wait for you, both from Eiri: a draft to send and a consent ask.
                  </span>
                  <Link className="act" to="/app/inbox" title="the queue lives in the inbox">
                    open the inbox
                  </Link>
                </div>
              </>
            )}
          </>
        )}
      </div>
    </main>
  )
}
