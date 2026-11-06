import * as React from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { cue, markCued, useDocumentEvent, useEscape } from '~/components/safelight/hooks'
import vaultCss from '~/styles/vault.css?url'

export const Route = createFileRoute('/app/vault')({
  head: () => ({
    links: [{ rel: 'stylesheet', href: vaultCss }],
  }),
  component: Vault,
})

/* ══ fixtures ══ */
type ActorKey = 'o' | 'y' | 'm' | 'e' | 't' | 'a' | 'cc' | 's'
type Status = 'approved' | 'auto' | 'proposed' | 'rejected'
type State = 'active' | 'superseded' | 'retracted'
type World = 'base' | 'work' | 'health'
type Source = 'LINE' | 'email' | 'slack' | 'meeting' | 'registry'

type Claim = {
  id: string
  entity: string
  text: string
  pred: string
  occurred: string
  learned: string
  by: ActorKey
  conf: number
  status: Status
  state: State
  world: World
  source: Source
  quote: string
  meta: string
  critical?: boolean
  successor?: string
  note?: { text: string; by: 'eiri' | 'tory' | 'antevon'; when: string }
}

const ACTORS: Record<ActorKey, { mark: string; name: string; cls: string; title: string }> = {
  o: { mark: 'o', name: 'Owen', cls: 'seal-human', title: 'o · Owen · owner' },
  y: { mark: 'y', name: 'Yuki', cls: 'seal-human', title: 'y · Yuki' },
  m: { mark: 'm', name: 'Mika Tanaka', cls: 'seal-human', title: 'm · Mika Tanaka · contact' },
  e: { mark: 'e', name: 'eiri', cls: 'seal-agent', title: 'e · eiri · agent · via kimi-k2.6' },
  t: { mark: 't', name: 'tory', cls: 'seal-agent', title: 't · tory · agent · research' },
  a: { mark: 'a', name: 'antevon', cls: 'seal-agent', title: 'a · antevon · the house mind' },
  cc: { mark: 'cc', name: 'claude code', cls: 'seal-agent', title: 'cc · claude code · agent · mcp' },
  s: { mark: 's', name: 'importer', cls: 'seal-system', title: 'sys · importer · system · connector' },
}
const STATUS_DOT: Record<Status, { cls: string; title: string }> = {
  approved: { cls: 'dot-approved', title: 'approved' },
  auto: { cls: 'dot-auto', title: 'auto · trusted, unreviewed' },
  proposed: { cls: 'dot-proposed', title: 'proposed · awaiting review' },
  rejected: { cls: 'dot-rejected', title: 'rejected' },
}

const CLAIMS: Claim[] = [
  {
    id: 'cl_9f27c3', entity: 'Sasha O.', text: 'Sasha moved from Berlin to Lisbon', pred: 'person.location',
    occurred: '2026-05-30', learned: '2026-06-24', by: 'o', conf: 0.97, status: 'approved', state: 'active',
    world: 'base', source: 'meeting',
    quote: '…by the way, Sasha finally did it. She’s been in Lisbon since the end of May, the Berlin flat is gone.',
    meta: 'turn 2026-06-24 · meeting · first-party',
    note: { text: 'likely permanent; she signed a year lease.', by: 'eiri', when: '06-24' },
  },
  {
    id: 'cl_a41b02', entity: 'Yuki', text: 'Yuki prefers async reviews over live calls', pred: 'person.preference',
    occurred: '2026-06-18', learned: '2026-06-18', by: 'e', conf: 0.94, status: 'auto', state: 'active',
    world: 'work', source: 'slack',
    quote: 'can we do this one async? a doc + comments beats a call for me.',
    meta: 'message 2026-06-18 · slack · first-party',
  },
  {
    id: 'cl_b77e19', entity: 'Hokuei Foods', text: 'Antevon pilot decision expected by July 18', pred: 'commitment.deadline',
    occurred: '2026-07-02', learned: '2026-07-03', by: 'e', conf: 0.88, status: 'auto', state: 'superseded',
    world: 'work', source: 'email', successor: 'cl_d3a201',
    quote: 'we should have an answer on the pilot by the 18th.',
    meta: 'email 2026-07-03 · Mika Tanaka · first-party',
  },
  {
    id: 'cl_c1e845', entity: 'Owen', text: 'Prefers briefing digests merged, not one ping per item', pred: 'person.preference',
    occurred: '2026-06-29', learned: '2026-06-29', by: 'cc', conf: 0.79, status: 'approved', state: 'active',
    world: 'base', source: 'slack',
    quote: 'batch these. one digest in the morning, not eleven pings.',
    meta: 'session 2026-06-29 · slack · first-party',
  },
  {
    id: 'cl_e90f4a', entity: 'Owen', text: 'May be allergic to shellfish', pred: 'health.allergy',
    occurred: '2026-04-11', learned: '2026-04-11', by: 'e', conf: 0.52, status: 'proposed', state: 'active',
    world: 'health', source: 'LINE', critical: true,
    quote: 'skipped the prawns again, felt off last time.',
    meta: 'message 2026-04-11 · LINE · first-party',
  },
  {
    id: 'cl_0d2c77', entity: 'Antevon', text: 'Office lease renews in March', pred: 'org.lease',
    occurred: '2025-03-14', learned: '2025-03-14', by: 'o', conf: 0.8, status: 'approved', state: 'superseded',
    world: 'work', source: 'email', successor: 'cl_0d2c78',
    quote: 'lease renewal falls in March each year.',
    meta: 'email 2025-03-14 · landlord · second-party',
  },
  {
    id: 'cl_0d2c78', entity: 'Antevon', text: 'Office lease renews in April from 2026', pred: 'org.lease',
    occurred: '2026-02-10', learned: '2026-02-10', by: 'o', conf: 0.9, status: 'approved', state: 'active',
    world: 'work', source: 'email',
    quote: 'from next year the renewal date moves to April 1.',
    meta: 'email 2026-02-10 · landlord · second-party',
  },
  {
    id: 'cl_f61a3b', entity: 'Owen', text: 'Flight back on the 12th', pred: 'travel.flight',
    occurred: '2026-06-12', learned: '2026-05-28', by: 's', conf: 0.44, status: 'rejected', state: 'retracted',
    world: 'base', source: 'email',
    quote: 'Booking confirmation · NRT · 12 Jun · 1 adult',
    meta: 'calendar import 2026-05-28 · email · connector',
  },
  {
    id: 'cl_7b8e50', entity: 'Owen', text: 'Runs the weather book on Polymarket with a hard daily loss cap', pred: 'project.constraint',
    occurred: '2026-06-05', learned: '2026-06-05', by: 'o', conf: 0.92, status: 'approved', state: 'active',
    world: 'base', source: 'slack',
    quote: 'daily loss cap stays. no exceptions, no override flag.',
    meta: 'message 2026-06-05 · slack · first-party',
  },
  {
    id: 'cl_11a9d4', entity: 'Mika Tanaka', text: 'Mika Tanaka leads procurement at Hokuei Foods', pred: 'person.role',
    occurred: '2026-08-09', learned: '2026-08-09', by: 'e', conf: 0.95, status: 'approved', state: 'active',
    world: 'work', source: 'LINE',
    quote: '田中です。北栄フーズの調達を担当しています。',
    meta: 'message 2026-08-09 · LINE · first-party',
  },
  {
    id: 'cl_12c0e1', entity: 'Mika Tanaka', text: 'Mika Tanaka prefers LINE for quick questions', pred: 'person.preference',
    occurred: '2026-08-09', learned: '2026-08-09', by: 'e', conf: 0.9, status: 'auto', state: 'active',
    world: 'work', source: 'LINE',
    quote: '急ぎの件はLINEでお願いします。',
    meta: 'message 2026-08-09 · LINE · first-party',
  },
  {
    id: 'cl_13f7aa', entity: 'Hokuei Foods', text: 'Hokuei may be consolidating suppliers this fiscal year', pred: 'org.intent',
    occurred: '2026-08-11', learned: '2026-08-12', by: 't', conf: 0.61, status: 'proposed', state: 'active',
    world: 'work', source: 'email',
    quote: 'the COO mentioned fewer vendors next year, cost reasons.',
    meta: 'email 2026-08-12 · Yuki · second-hand',
    note: { text: 'contradicts the May claim; accept and the older one supersedes.', by: 'tory', when: '08-12' },
  },
  {
    id: 'cl_14b2c9', entity: 'Hokuei Foods', text: 'Hokuei is expanding the supplier base', pred: 'org.intent',
    occurred: '2026-05-20', learned: '2026-05-22', by: 'e', conf: 0.77, status: 'auto', state: 'superseded',
    world: 'work', source: 'meeting', successor: 'cl_13f7aa',
    quote: 'they are adding two regional suppliers this spring.',
    meta: 'meeting 2026-05-22 · Yuki · second-hand',
  },
  {
    id: 'cl_15d8e0', entity: 'Hokuei Foods', text: 'Hokuei pilot call set for Thursday 10:00', pred: 'commitment.meeting',
    occurred: '2026-08-13', learned: '2026-08-12', by: 'o', conf: 0.98, status: 'approved', state: 'active',
    world: 'work', source: 'email',
    quote: 'Thursday 10:00 works for us. Mika will join.',
    meta: 'email 2026-08-12 · Hokuei COO · first-party',
  },
  {
    id: 'cl_d3a201', entity: 'Hokuei Foods', text: 'Hokuei pilot decision expected by August 21', pred: 'commitment.deadline',
    occurred: '2026-08-12', learned: '2026-08-12', by: 'a', conf: 0.84, status: 'auto', state: 'active',
    world: 'work', source: 'email',
    quote: 'we will confirm after the Thursday call, by the 21st.',
    meta: 'email 2026-08-12 · Hokuei COO · first-party',
  },
  {
    id: 'cl_16e4f2', entity: 'Nishi Trading', text: 'Nishi is the managing director of Nishi Trading', pred: 'person.role',
    occurred: '2026-08-11', learned: '2026-08-11', by: 'o', conf: 0.96, status: 'approved', state: 'active',
    world: 'work', source: 'meeting',
    quote: 'met Nishi-san, managing director, at the Yokohama supplier day.',
    meta: 'meeting 2026-08-11 · first-party',
  },
  {
    id: 'cl_17a6b3', entity: 'Nishi Trading', text: 'Nishi asked for a forecasting quote by end of month', pred: 'commitment.request',
    occurred: '2026-08-09', learned: '2026-08-09', by: 'e', conf: 0.86, status: 'auto', state: 'active',
    world: 'work', source: 'email',
    quote: 'could you send a rough quote before the end of August?',
    meta: 'email 2026-08-09 · Nishi · first-party',
  },
  {
    id: 'cl_18c9d1', entity: 'Nishi Trading', text: 'Nishi Trading runs three warehouses in Saitama', pred: 'org.fact',
    occurred: '2026-08-11', learned: '2026-08-11', by: 't', conf: 0.72, status: 'auto', state: 'active',
    world: 'work', source: 'meeting',
    quote: 'three sites, all Saitama, the Kawaguchi one is the largest.',
    meta: 'meeting 2026-08-11 · Nishi · first-party',
  },
  {
    id: 'cl_19f0e7', entity: 'Sakura Retail', text: 'Sakura Retail moved its head office to Yokohama', pred: 'org.location',
    occurred: '2026-07-30', learned: '2026-08-04', by: 't', conf: 0.68, status: 'proposed', state: 'active',
    world: 'work', source: 'registry',
    quote: 'Registered office: Nishi-ku, Yokohama · filed 2026-07-30',
    meta: 'registry 2026-08-04 · corporate registry · public record',
  },
  {
    id: 'cl_20b1a8', entity: 'Sakura Retail', text: 'Sakura Retail buyer wants monthly, not weekly, forecasts', pred: 'person.preference',
    occurred: '2026-08-06', learned: '2026-08-06', by: 'e', conf: 0.74, status: 'auto', state: 'active',
    world: 'work', source: 'slack',
    quote: 'their buyer said weekly is noise, monthly is what they plan on.',
    meta: 'message 2026-08-06 · slack · Yuki · second-hand',
  },
  {
    id: 'cl_21d5c2', entity: 'Kanto Logistics', text: 'Kanto Logistics changed its registered address', pred: 'org.location',
    occurred: '2026-08-01', learned: '2026-08-05', by: 's', conf: 0.93, status: 'approved', state: 'active',
    world: 'work', source: 'registry',
    quote: 'Change of registered address · Koto-ku, Tokyo · effective 2026-08-01',
    meta: 'registry 2026-08-05 · corporate registry · public record',
  },
  {
    id: 'cl_22e7f9', entity: 'Kanto Logistics', text: 'Kanto Logistics quote was declined in June', pred: 'deal.outcome',
    occurred: '2026-06-27', learned: '2026-06-27', by: 'y', conf: 0.9, status: 'approved', state: 'active',
    world: 'work', source: 'email',
    quote: 'we will not proceed this quarter. thank you for the proposal.',
    meta: 'email 2026-06-27 · Kanto Logistics · first-party',
  },
  {
    id: 'cl_23a2b6', entity: 'Kanto Logistics', text: 'Kanto Logistics is open to a second quote in autumn', pred: 'org.intent',
    occurred: '2026-08-10', learned: '2026-08-10', by: 'e', conf: 0.55, status: 'proposed', state: 'active',
    world: 'work', source: 'slack',
    quote: 'their ops lead hinted at revisiting in October.',
    meta: 'message 2026-08-10 · slack · Yuki · second-hand',
  },
  {
    id: 'cl_24c8d0', entity: 'Sakura Retail', text: 'Sakura Retail signed with a competitor', pred: 'deal.outcome',
    occurred: '2026-08-03', learned: '2026-08-05', by: 't', conf: 0.3, status: 'rejected', state: 'retracted',
    world: 'work', source: 'slack',
    quote: 'heard Sakura went with someone else? not sure.',
    meta: 'message 2026-08-05 · slack · third-hand',
  },
  {
    id: 'cl_25f3e4', entity: 'Yuki', text: 'Yuki is out the week of August 24', pred: 'person.availability',
    occurred: '2026-08-24', learned: '2026-08-14', by: 'y', conf: 0.97, status: 'approved', state: 'active',
    world: 'work', source: 'slack',
    quote: 'off the week of the 24th, back on the 31st.',
    meta: 'message 2026-08-14 · slack · first-party',
  },
  {
    id: 'cl_26a0b1', entity: 'Owen', text: 'Takes no calls before 10:00', pred: 'person.preference',
    occurred: '2026-03-02', learned: '2026-03-02', by: 'o', conf: 0.89, status: 'approved', state: 'active',
    world: 'base', source: 'meeting',
    quote: 'nothing before ten. mornings are for deep work.',
    meta: 'note 2026-03-02 · first-party',
  },
  {
    id: 'cl_27b4c5', entity: 'Owen', text: 'Sleeps badly after late calls', pred: 'health.pattern',
    occurred: '2026-07-20', learned: '2026-07-21', by: 'e', conf: 0.38, status: 'proposed', state: 'active',
    world: 'health', source: 'LINE',
    quote: 'that 23:00 call wrecked the night again.',
    meta: 'message 2026-07-21 · LINE · first-party',
  },
]

/* the vault's own clock. fixed, never `new Date()`: the server and the
   browser must render the same page. */
const TODAY = '2026-08-18'
const FLOOR = CLAIMS.reduce((min, c) => (c.learned < min ? c.learned : min), TODAY)

const DAY = 86400000
const toDay = (iso: string) => Math.round(Date.parse(iso) / DAY)
const toIso = (day: number) => new Date(day * DAY).toISOString().slice(0, 10)

/* what the vault believed on a past date: a claim a later claim replaced
   was still standing then. the successor's learned date is the moment it
   fell. */
function stateAt(c: Claim, asof: string): State {
  if (c.state === 'superseded' && c.successor) {
    const s = CLAIMS.find((x) => x.id === c.successor)
    if (s && s.learned > asof) return 'active'
  }
  return c.state
}

const WORLDS: { id: World | 'fiction'; title: string; fixed?: boolean; dead?: boolean }[] = [
  { id: 'base', title: 'base reality · always on', fixed: true },
  { id: 'work', title: 'world: work · in the allowed-set' },
  { id: 'health', title: 'world: health · in the allowed-set' },
  { id: 'fiction', title: 'world: fiction · archived 2026-05-12', dead: true },
]
const STATES: State[] = ['active', 'superseded', 'retracted']

/* ══ columns · mirrors TanStack Table's column-def shape so a later swap
   is cheap: { id, header, accessor, sortingFn, filterFn, size }. Nothing
   installed; the table is hand-rolled. ══ */
type Kind = 'text' | 'enum' | 'date' | 'conf'
type ColId = 'claim' | 'pred' | 'source' | 'occurred' | 'learned' | 'conf' | 'by' | 'status'
type Column = {
  id: ColId
  header: string
  kind: Kind
  size?: number
  cls?: string
  accessor: (c: Claim) => string | number
  sortingFn: (a: Claim, b: Claim) => number
  filterFn: (c: Claim, f: FilterValue) => boolean
}
type FilterValue =
  | { kind: 'text'; q: string }
  | { kind: 'enum'; on: string[] }
  | { kind: 'date'; after: string; before: string }
  | { kind: 'conf'; min: number }

const byText = (get: (c: Claim) => string) => (a: Claim, b: Claim) => get(a).localeCompare(get(b))
const enumFilter = (get: (c: Claim) => string) => (c: Claim, f: FilterValue) =>
  f.kind !== 'enum' || f.on.length === 0 || f.on.includes(get(c))
/* a date bound counts only once it is a whole day: half-typed text must
   not empty the table under the hand */
const ISO = /^\d{4}-\d{2}-\d{2}$/
const dateFilter = (get: (c: Claim) => string) => (c: Claim, f: FilterValue) => {
  if (f.kind !== 'date') return true
  const v = get(c)
  if (ISO.test(f.after) && v < f.after) return false
  if (ISO.test(f.before) && v > f.before) return false
  return true
}

const COLUMNS: Column[] = [
  {
    id: 'claim', header: 'claim', kind: 'text',
    accessor: (c) => c.text,
    sortingFn: byText((c) => c.text),
    filterFn: (c, f) => f.kind !== 'text' || !f.q || c.text.toLowerCase().includes(f.q.toLowerCase()),
  },
  {
    id: 'pred', header: 'predicate', kind: 'enum', size: 156, cls: 'c-pred',
    accessor: (c) => c.pred, sortingFn: byText((c) => c.pred), filterFn: enumFilter((c) => c.pred),
  },
  {
    id: 'source', header: 'source', kind: 'enum', size: 78, cls: 'c-src',
    accessor: (c) => c.source, sortingFn: byText((c) => c.source), filterFn: enumFilter((c) => c.source),
  },
  {
    id: 'occurred', header: 'occurred', kind: 'date', size: 96, cls: 'c-occ',
    accessor: (c) => c.occurred, sortingFn: byText((c) => c.occurred), filterFn: dateFilter((c) => c.occurred),
  },
  {
    id: 'learned', header: 'learned', kind: 'date', size: 96, cls: 'c-lrn',
    accessor: (c) => c.learned, sortingFn: byText((c) => c.learned), filterFn: dateFilter((c) => c.learned),
  },
  {
    id: 'conf', header: 'conf', kind: 'conf', size: 52, cls: 'c-conf',
    accessor: (c) => c.conf, sortingFn: (a, b) => a.conf - b.conf,
    filterFn: (c, f) => f.kind !== 'conf' || c.conf >= f.min,
  },
  {
    id: 'by', header: 'by', kind: 'enum', size: 40, cls: 'c-actor',
    accessor: (c) => ACTORS[c.by].name, sortingFn: byText((c) => ACTORS[c.by].name),
    filterFn: enumFilter((c) => ACTORS[c.by].name),
  },
  {
    id: 'status', header: '', kind: 'enum', size: 30, cls: 'c-dot',
    accessor: (c) => c.status, sortingFn: byText((c) => c.status), filterFn: enumFilter((c) => c.status),
  },
]
const CONF_LADDER = [0.3, 0.5, 0.7, 0.9]

function distinct(col: Column): string[] {
  const s = new Set<string>()
  for (const c of CLAIMS) s.add(String(col.accessor(c)))
  return [...s].sort()
}
function confClass(conf: number) {
  return conf >= 0.9 ? 'conf-1' : conf >= 0.7 ? 'conf-2' : conf >= 0.4 ? 'conf-3' : 'conf-4'
}
function daysBetween(a: string, b: string) {
  return Math.round((Date.parse(b) - Date.parse(a)) / 86400000)
}
function filterLabel(col: Column, f: FilterValue): string {
  switch (f.kind) {
    case 'text': return `${col.header} ~ ${f.q}`
    case 'enum': return `${col.header || 'status'} · ${f.on.join(', ')}`
    case 'date': {
      const bounds = [ISO.test(f.after) && `≥ ${f.after}`, ISO.test(f.before) && `≤ ${f.before}`]
      return `${col.header} ${bounds.filter(Boolean).join(' ')}`
    }
    case 'conf': return `conf ≥ ${f.min.toFixed(1)}`
  }
}
/* nothing typed at all → the filter leaves the state */
function filterBlank(f: FilterValue) {
  return (f.kind === 'text' && !f.q) || (f.kind === 'enum' && f.on.length === 0)
    || (f.kind === 'date' && !f.after && !f.before)
}
/* it changes the rows → it earns a chip in the filters row */
function filterActive(f: FilterValue) {
  if (f.kind === 'date') return ISO.test(f.after) || ISO.test(f.before)
  return !filterBlank(f)
}

const cx = (...parts: (string | false | null | undefined)[]) => parts.filter(Boolean).join(' ')
/* the receipt's clock: the moment an act settled (this is the one place a
   live clock is right — the fixture's TODAY stays fixed for the rows) */
function hhmm() {
  const d = new Date()
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
}

/* ── inline glyphs · house line, 1.5 stroke, currentColor ── */
function FilterGlyph() {
  return (
    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M4 5h16l-6 8v6l-4-2v-4z" />
    </svg>
  )
}
function ShareGlyph() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 3v12" />
      <path d="M8 7l4-4 4 4" />
      <path d="M5 13v6h14v-6" />
    </svg>
  )
}

/* ══ pane · ONE sheet: the ledger + the inspector column ══ */
function Vault() {
  const [worlds, setWorlds] = React.useState<Set<string>>(() => new Set(['base', 'work']))
  const [states, setStates] = React.useState<Set<State>>(() => new Set<State>(['active', 'superseded']))
  const [q, setQ] = React.useState('')
  const [sort, setSort] = React.useState<{ id: ColId; dir: 'asc' | 'desc' } | null>(null)
  const [filters, setFilters] = React.useState<Partial<Record<ColId, FilterValue>>>({})
  const [pop, setPop] = React.useState<ColId | null>(null)
  /* the selection is a SET (owner 09-07: bulk actions, normal table ops):
     click = this row · shift-click = the range from the anchor · ⌘-click =
     toggle · the head square = every row shown · space toggles the cursor
     row · shift+arrows extend · esc clears. an act on the selection settles
     every row in place and leaves ONE receipt line (no toast, ever). */
  const [selected, setSelected] = React.useState<Set<string>>(() => new Set())
  const [anchor, setAnchor] = React.useState<string | null>(null)
  const [cursor, setCursor] = React.useState<string | null>(null)
  const [verdicts, setVerdicts] = React.useState<Record<string, { word: string; ok: boolean; when: string }>>({})
  const [receipt, setReceipt] = React.useState<string | null>(null)
  const [moveOpen, setMoveOpen] = React.useState(false)
  const [open, setOpen] = React.useState<string>('cl_9f27c3')
  const [asof, setAsof] = React.useState<string>(TODAY)
  const searchRef = React.useRef<HTMLInputElement>(null)
  const bodyRef = React.useRef<HTMLTableSectionElement>(null)
  const popBtn = React.useRef<HTMLButtonElement | null>(null)

  /* the visible rows: as-of → chrome chips → search → column filters → sort */
  const rows = React.useMemo(() => {
    const needle = q.trim().toLowerCase()
    let out = CLAIMS.filter(
      (c) => c.learned <= asof && worlds.has(c.world) && states.has(stateAt(c, asof)),
    )
    if (needle) {
      out = out.filter((c) =>
        c.text.toLowerCase().includes(needle) || c.pred.toLowerCase().includes(needle)
        || c.source.toLowerCase().includes(needle),
      )
    }
    for (const col of COLUMNS) {
      const f = filters[col.id]
      if (f) out = out.filter((c) => col.filterFn(c, f))
    }
    if (sort) {
      const col = COLUMNS.find((c) => c.id === sort.id)!
      const dir = sort.dir === 'asc' ? 1 : -1
      out = [...out].sort((a, b) => col.sortingFn(a, b) * dir)
    }
    return out
  }, [worlds, states, q, filters, sort, asof])

  const activeFilters = COLUMNS.filter((c) => filters[c.id] && filterActive(filters[c.id]!))
  const past = asof !== TODAY
  const filtered = activeFilters.length > 0 || q.trim().length > 0 || past
  const opened = CLAIMS.find((c) => c.id === open) ?? CLAIMS[0]

  function toggleWorld(id: string) {
    setWorlds((w) => {
      const n = new Set(w)
      n.has(id) ? n.delete(id) : n.add(id)
      return n
    })
    cue('toggle')
  }
  function toggleState(id: State) {
    setStates((s) => {
      const n = new Set(s)
      n.has(id) ? n.delete(id) : n.add(id)
      return n
    })
    cue('toggle')
  }
  function cycleSort(id: ColId) {
    setSort((s) => (!s || s.id !== id ? { id, dir: 'asc' } : s.dir === 'asc' ? { id, dir: 'desc' } : null))
    cue('toggle')
  }
  function setFilter(id: ColId, f: FilterValue | null) {
    setFilters((prev) => {
      const n = { ...prev }
      if (!f || filterBlank(f)) delete n[id]
      else n[id] = f
      return n
    })
  }
  function clearFilters() {
    setFilters({})
    setQ('')
  }
  function pick(id: string, e?: { shiftKey: boolean; metaKey: boolean; ctrlKey: boolean }) {
    const toggle = !!e && (e.metaKey || e.ctrlKey)
    const range = !!e && e.shiftKey
    setSelected((s) => {
      const n = new Set(toggle || range ? s : [])
      if (range && anchor) {
        const a = rows.findIndex((r) => r.id === anchor)
        const b = rows.findIndex((r) => r.id === id)
        if (a >= 0 && b >= 0) for (let i = Math.min(a, b); i <= Math.max(a, b); i++) n.add(rows[i].id)
        else n.add(id)
      } else if (toggle) {
        if (n.has(id)) n.delete(id)
        else n.add(id)
      } else n.add(id)
      return n
    })
    if (!range) setAnchor(id)
    setCursor(id)
    /* a plain click also opens the record; a modified click only selects */
    if (!toggle && !range) setOpen(id)
    cue('toggle')
  }
  function clearSel() {
    setSelected(new Set())
    setAnchor(null)
    setMoveOpen(false)
  }
  function selectAll() {
    setSelected(new Set(rows.map((r) => r.id)))
    if (!anchor && rows[0]) setAnchor(rows[0].id)
    cue('toggle')
  }
  /* an act on the selection: every row settles in place, one receipt line lands */
  function actOn(word: string, ok: boolean) {
    const ids = [...selected]
    if (ids.length === 0) return
    const when = hhmm()
    setVerdicts((v) => {
      const n = { ...v }
      for (const id of ids) n[id] = { word, ok, when }
      return n
    })
    setReceipt(`${ids.length} ${word} · ${when}`)
    clearSel()
    cue(ok ? 'success' : 'press')
  }
  const allSel = rows.length > 0 && rows.every((r) => selected.has(r.id))
  const someSel = selected.size > 0
  /* the popover hands focus back to the head it hangs from */
  function closePop() {
    setPop(null)
    popBtn.current?.focus()
  }

  /* Esc: the popover · the selection · the filters · the as-of date */
  useEscape(() => {
    if (pop) return closePop()
    if (moveOpen) return setMoveOpen(false)
    if (selected.size > 0) return clearSel()
    if (activeFilters.length > 0 || q.trim()) return clearFilters()
    if (past) return setAsof(TODAY)
  })
  /* click outside closes the filter popover */
  useDocumentEvent('click', (e) => {
    const t = e.target as HTMLElement | null
    if (pop && !t?.closest?.('.fpop, .th-flt')) setPop(null)
  })
  /* ↑/↓ moves the selection · Enter opens it in the inspector */
  useDocumentEvent('keydown', (e) => {
    if (pop) return
    const t = e.target as HTMLElement | null
    const typing = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable)
    if (typing && t !== searchRef.current) return
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      if (rows.length === 0) return
      e.preventDefault()
      const cur = cursor ?? anchor
      const i = rows.findIndex((r) => r.id === cur)
      const j = e.key === 'ArrowDown' ? Math.min(rows.length - 1, i + 1) : Math.max(0, i < 0 ? 0 : i - 1)
      const next = rows[j].id
      if (e.shiftKey) {
        /* shift+arrow extends the selection from the anchor */
        setSelected((s) => {
          const n = new Set(s)
          n.add(next)
          return n
        })
        if (!anchor) setAnchor(next)
      } else {
        setSelected(new Set([next]))
        setAnchor(next)
      }
      setCursor(next)
      bodyRef.current?.querySelector<HTMLElement>(`[data-id="${next}"]`)?.scrollIntoView({ block: 'nearest' })
    } else if (e.key === ' ' && !typing) {
      /* space toggles the cursor row */
      if (t?.closest?.('button, a, [role="slider"]')) return
      const cur = cursor ?? anchor
      if (!cur) return
      e.preventDefault()
      setSelected((s) => {
        const n = new Set(s)
        if (n.has(cur)) n.delete(cur)
        else n.add(cur)
        return n
      })
      cue('toggle')
    } else if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'a' && !typing) {
      e.preventDefault()
      selectAll()
    } else if (e.key === 'Enter') {
      /* a focused act runs itself; Enter is the row's door only */
      if (t?.closest?.('button, a, [role="slider"]')) return
      const next = cursor ?? anchor ?? rows[0]?.id
      if (!next) return
      setSelected(new Set([next]))
      setAnchor(next)
      setCursor(next)
      setOpen(next)
      cue('toggle')
    }
  })

  return (
    <main className="pane">
      <div className="pane-body">
        <div className="pane-head">
          <h1>Vault</h1>
          <span className="meta-line" title="Antevon · as of 14:07" aria-live="polite">
            {filtered ? `${rows.length} of 12,408 claims` : '12,408 claims'} · 214 entities · last write 14:07
          </span>
          <input
            ref={searchRef}
            className="vsearch"
            type="search"
            placeholder="search claims"
            aria-label="search claims"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>

        {/* chrome: world scope + state filters (OF-293 / OF-111) + the column filters.
            while anything is selected the same row is the SELECTION LINE: the
            count and the acts that apply (owner 09-07) */}
        {someSel ? (
        <div className="filters selbar" role="group" aria-label="selection" aria-live="polite">
          <span className="meta-line" title="click = one · shift-click = a range · ⌘-click = toggle · esc clears">
            {selected.size} selected
          </span>
          <button className="act" title="verb: approve_claims · every selected claim settles approved, in place" onClick={(e) => { markCued(e); actOn('accepted', true) }}>
            accept
          </button>
          <button className="act" title="verb: reject_claims · kept, struck" onClick={(e) => { markCued(e); actOn('rejected', false) }}>
            reject
          </button>
          <span className="set" role="group" aria-label="move to a world">
            <button className="act" aria-expanded={moveOpen} title="move the selected claims to another world" onClick={(e) => { markCued(e); setMoveOpen((o) => !o); cue('toggle') }}>
              move to
            </button>
            {moveOpen && WORLDS.filter((w) => !w.dead).map((w) => (
              <button key={w.id} className="chip" title={w.title} onClick={(e) => { markCued(e); actOn(`moved to ${w.id}`, true) }}>
                {w.id}
              </button>
            ))}
          </span>
          <button className="act" title="verb: forget_claims · a deletion receipt prints; nothing pretends to forget" onClick={(e) => { markCued(e); actOn('forgotten', false) }}>
            forget
          </button>
          <button className="act" title="an export slip · everything you selected, itemized" onClick={(e) => { markCued(e); actOn('exported', true) }}>
            export
          </button>
          <button className="act" title="clear the selection · esc" onClick={(e) => { markCued(e); clearSel(); cue('toggle') }}>
            clear
          </button>
        </div>
        ) : (
        <div className="filters">
          <span className="set" role="group" aria-label="worlds">
            <span className="label">worlds</span>
            {WORLDS.map((w) => (
              <button
                key={w.id}
                className={`chip${worlds.has(w.id) ? ' on' : ''}${w.dead ? ' dead' : ''}`}
                title={w.title}
                aria-pressed={worlds.has(w.id)}
                disabled={w.fixed || w.dead}
                onClick={(e) => { markCued(e); toggleWorld(w.id) }}
              >
                {w.id}
              </button>
            ))}
          </span>
          <span className="set" role="group" aria-label="state">
            <span className="label">show</span>
            {STATES.map((s) => (
              <button
                key={s}
                className={`chip${states.has(s) ? ' on' : ''}`}
                aria-pressed={states.has(s)}
                onClick={(e) => { markCued(e); toggleState(s) }}
              >
                {s}
              </button>
            ))}
          </span>
          {activeFilters.length > 0 && (
            <span className="set" role="group" aria-label="column filters">
              <span className="label">where</span>
              {activeFilters.map((col) => (
                <button
                  key={col.id}
                  className="chip on fchip"
                  title="remove this filter"
                  onClick={(e) => { markCued(e); setFilter(col.id, null); cue('toggle') }}
                >
                  {filterLabel(col, filters[col.id]!)}
                  <span className="x" aria-hidden="true">×</span>
                </button>
              ))}
              <button className="act" onClick={clearFilters}>clear</button>
            </span>
          )}
          {/* the outcome of the last act on a selection IS the receipt line,
              where the acts stood — never a toast (08-14) */}
          {receipt && (
            <span className="meta-line selreceipt" aria-live="polite" title="what the last act on a selection did">
              {receipt}
            </span>
          )}
        </div>
        )}

        {/* chrome: the as-of scrubber — what did the vault believe then (OF-082) */}
        <AsOf value={asof} onChange={setAsof} />

        <div className={someSel ? 'ledger-wrap has-sel' : 'ledger-wrap'}>
          <table className="ledger" role="grid" aria-multiselectable="true">
            <thead>
              <tr>
                <th className="c-sel" scope="col">
                  <button
                    type="button"
                    className={cx('selbox', allSel && 'on', someSel && !allSel && 'some')}
                    aria-pressed={allSel}
                    aria-label={allSel ? 'clear the selection' : 'select every row shown'}
                    title={allSel ? 'clear · esc' : 'select every row shown · ⌘A'}
                    onClick={(e) => { markCued(e); if (allSel) clearSel(); else selectAll() }}
                  />
                </th>
                {COLUMNS.map((col) => {
                  const f = filters[col.id]
                  const sorted = sort?.id === col.id ? sort.dir : null
                  const name = col.header || 'status'
                  return (
                    <th
                      key={col.id}
                      scope="col"
                      className={cx(col.cls, sorted && 'sorted', f && filterActive(f) && 'filtered', pop === col.id && 'popped')}
                      style={col.size ? { width: col.size } : undefined}
                      aria-sort={sorted === 'asc' ? 'ascending' : sorted === 'desc' ? 'descending' : 'none'}
                    >
                      <span className="th-in">
                        <button
                          className="th-sort"
                          title={`sort by ${name}`}
                          aria-label={`sort by ${name}`}
                          onClick={(e) => { markCued(e); cycleSort(col.id) }}
                        >
                          {col.header}
                          <span className="arrow" aria-hidden="true">{sorted === 'asc' ? '↑' : sorted === 'desc' ? '↓' : ''}</span>
                        </button>
                        <button
                          className="th-flt"
                          title={`filter ${name}`}
                          aria-label={`filter ${name}`}
                          aria-expanded={pop === col.id}
                          onClick={(e) => {
                            markCued(e)
                            popBtn.current = e.currentTarget
                            setPop((p) => (p === col.id ? null : col.id))
                            cue('toggle')
                          }}
                        >
                          <FilterGlyph />
                        </button>
                      </span>
                      {pop === col.id && (
                        <FilterPop col={col} value={f} onChange={(v) => setFilter(col.id, v)} />
                      )}
                    </th>
                  )
                })}
              </tr>
            </thead>
            <tbody ref={bodyRef}>
              {rows.map((c) => {
                const state = stateAt(c, asof)
                const isSel = selected.has(c.id)
                const v = verdicts[c.id]
                /* a settled verdict takes the dot and the text treatment (approved
                   fills, rejected/forgotten strike); an export leaves the record as it was */
                const dotCls = v && v.word !== 'exported' ? (v.ok ? 'dot-approved' : 'dot-rejected') : STATUS_DOT[c.status].cls
                const dotTitle = v ? `${v.word} · ${v.when}` : STATUS_DOT[c.status].title
                return (
                <tr
                  key={c.id}
                  data-id={c.id}
                  className={cx(isSel && 'selected', open === c.id && 'open', state === 'superseded' && 'superseded')}
                  aria-selected={isSel}
                  onMouseDown={(e) => {
                    /* a modified click selects rows, never text: the browser
                       would otherwise drag a text selection across the range */
                    if (e.shiftKey || e.metaKey || e.ctrlKey) e.preventDefault()
                  }}
                  onClick={(e) => { markCued(e); pick(c.id, e) }}
                >
                  <td className="c-sel">
                    <button
                      type="button"
                      className={isSel ? 'selbox on' : 'selbox'}
                      aria-pressed={isSel}
                      aria-label={isSel ? 'deselect this claim' : 'select this claim'}
                      title={isSel ? 'selected · click to drop' : 'select · shift-click for a range'}
                      onClick={(e) => { e.stopPropagation(); markCued(e); pick(c.id, { shiftKey: e.shiftKey, metaKey: !e.shiftKey, ctrlKey: false }) }}
                    />
                  </td>
                  <td>
                    <span
                      className={cx('claim', confClass(c.conf), (state === 'retracted' || (v && !v.ok)) && 'retracted')}
                      title={`confidence ${c.conf.toFixed(2)}${c.critical ? ' · critical predicate · never renders below muted ink' : ''}${v ? ` · ${v.word} ${v.when}` : ''}`}
                    >
                      {c.text}
                    </span>
                    {c.critical && c.conf < 0.7 && (
                      <span className="unverified" title="critical claim, low confidence · marked, never faded out">
                        unverified
                      </span>
                    )}
                    {state === 'superseded' && c.successor && (
                      <a
                        className="succ"
                        href="#"
                        title="open the successor"
                        onClick={(e) => { e.preventDefault(); e.stopPropagation(); pick(c.successor!) }}
                      >
                        → successor
                      </a>
                    )}
                  </td>
                  <td>
                    <a className="pred" href="#" title={`predicate ${c.pred} · registry`} onClick={(e) => e.preventDefault()}>
                      {c.pred}
                    </a>
                  </td>
                  <td><span className="src">{c.source}</span></td>
                  <td><span className="clk">{c.occurred}</span></td>
                  <td><span className="clk hollow">{c.learned}</span></td>
                  <td className="c-conf"><span className="confn">{c.conf.toFixed(2)}</span></td>
                  <td className="c-actor">
                    <span className={`seal ${ACTORS[c.by].cls}`} title={ACTORS[c.by].title}>
                      {ACTORS[c.by].mark}
                    </span>
                  </td>
                  <td className="c-dot">
                    <span className={`dot ${dotCls}`} title={dotTitle}></span>
                  </td>
                </tr>
                )
              })}
            </tbody>
          </table>
          {rows.length === 0 && <p className="empty">No claim matches this.</p>}
        </div>

        {/* on this day (OF-249) */}
        <div className="otd">
          <span className="label">on this day</span>
          <span className="claim">2025 · first note about the Antevon forecasting pilot.</span>
          <a className="act" href="#" onClick={(e) => e.preventDefault()}>open</a>
        </div>
      </div>

      {/* inspector (OF-235): the opened claim's record — work, so it
          rides inside the sheet as its right column (owner 08-14 eve) */}
      <Inspector c={opened} onOpen={pick} />
    </main>
  )
}

/* ══ the as-of scrubber (OF-082) · drag the vault back to a past day:
   claims learned after it are gone, and a claim its successor had not
   yet replaced stands again. pointer + arrow keys. ══ */
function AsOf({ value, onChange }: { value: string; onChange: (d: string) => void }) {
  const trackRef = React.useRef<HTMLDivElement>(null)
  const lo = toDay(FLOOR)
  const hi = toDay(TODAY)
  const day = toDay(value)
  const pct = ((day - lo) / (hi - lo)) * 100
  const past = value !== TODAY

  function fromX(clientX: number) {
    const box = trackRef.current?.getBoundingClientRect()
    if (!box || box.width === 0) return
    const t = Math.min(1, Math.max(0, (clientX - box.left) / box.width))
    onChange(toIso(Math.round(lo + t * (hi - lo))))
  }
  function step(days: number) {
    onChange(toIso(Math.min(hi, Math.max(lo, day + days))))
    cue('toggle')
  }

  return (
    <div className="asof">
      <span className="label">as of</span>
      <div
        ref={trackRef}
        className="track"
        role="slider"
        tabIndex={0}
        aria-label="as of"
        aria-valuemin={lo}
        aria-valuemax={hi}
        aria-valuenow={day}
        aria-valuetext={value}
        onPointerDown={(e) => {
          e.currentTarget.setPointerCapture(e.pointerId)
          fromX(e.clientX)
        }}
        onPointerMove={(e) => {
          if (e.currentTarget.hasPointerCapture(e.pointerId)) fromX(e.clientX)
        }}
        onKeyDown={(e) => {
          const by = e.key === 'ArrowLeft' ? -1 : e.key === 'ArrowRight' ? 1 : 0
          if (by) { e.preventDefault(); step(by * (e.shiftKey ? 30 : 1)); return }
          if (e.key === 'Home') { e.preventDefault(); onChange(FLOOR) }
          if (e.key === 'End') { e.preventDefault(); onChange(TODAY) }
        }}
      >
        <span className="handle" style={{ left: `${pct}%` }}></span>
      </div>
      <span className="date">{past ? value : `today · ${TODAY}`}</span>
      {/* .act presses its own cue through useCuePress; never ring it twice */}
      {past && <button className="act" onClick={() => onChange(TODAY)}>today</button>}
    </div>
  )
}

/* ══ the filter popover · radius 8, --shadow-pop; one shape per kind ══ */
function FilterPop({ col, value, onChange }: { col: Column; value?: FilterValue; onChange: (v: FilterValue | null) => void }) {
  const first = React.useRef<HTMLInputElement>(null)
  React.useEffect(() => { first.current?.focus() }, [])
  if (col.kind === 'enum') {
    const on = value?.kind === 'enum' ? value.on : []
    return (
      <div className="fpop" role="group" aria-label={`filter ${col.header || 'status'}`}>
        <span className="label">{col.header || 'status'} is</span>
        <div className="fchips">
          {distinct(col).map((v) => (
            <button
              key={v}
              className={`chip${on.includes(v) ? ' on' : ''}`}
              aria-pressed={on.includes(v)}
              onClick={(e) => {
                markCued(e); cue('toggle')
                onChange({ kind: 'enum', on: on.includes(v) ? on.filter((x) => x !== v) : [...on, v] })
              }}
            >
              {v}
            </button>
          ))}
        </div>
      </div>
    )
  }
  if (col.kind === 'text') {
    const q = value?.kind === 'text' ? value.q : ''
    return (
      <div className="fpop">
        <span className="label">{col.header} contains</span>
        <input ref={first} className="fin" value={q} placeholder="a word" onChange={(e) => onChange({ kind: 'text', q: e.target.value })} />
      </div>
    )
  }
  if (col.kind === 'date') {
    const v = value?.kind === 'date' ? value : { kind: 'date' as const, after: '', before: '' }
    return (
      <div className="fpop">
        <span className="label">{col.header}</span>
        <label className="frow"><span>after</span>
          <input ref={first} className="fin" value={v.after} placeholder="2026-08-01" onChange={(e) => onChange({ ...v, after: e.target.value.trim() })} />
        </label>
        <label className="frow"><span>before</span>
          <input className="fin" value={v.before} placeholder="2026-08-31" onChange={(e) => onChange({ ...v, before: e.target.value.trim() })} />
        </label>
      </div>
    )
  }
  const min = value?.kind === 'conf' ? value.min : 0
  return (
    <div className="fpop" role="group" aria-label="minimum confidence">
      <span className="label">at least</span>
      <div className="fchips">
        {CONF_LADDER.map((n) => (
          <button
            key={n}
            className={`chip${min === n ? ' on' : ''}`}
            aria-pressed={min === n}
            onClick={(e) => { markCued(e); cue('toggle'); onChange(min === n ? null : { kind: 'conf', min: n }) }}
          >
            {n.toFixed(1)}
          </button>
        ))}
      </div>
    </div>
  )
}

/* ══ the inspector · the record you READ ══ */
function Inspector({ c, onOpen }: { c: Claim; onOpen: (id: string) => void }) {
  const gap = daysBetween(c.occurred, c.learned)
  const gapLine = gap === 0 ? 'learned the same day' : gap > 0 ? `learned ${gap} days later` : `learned ${-gap} days ahead`
  const actor = ACTORS[c.by]
  return (
    <aside className="inspector" aria-label="inspector">
      <div className="trail">
        <a href="#" onClick={(e) => e.preventDefault()}>vault</a>
        <span className="sep">›</span>
        <a href="#" title="entity · dossier" onClick={(e) => e.preventDefault()}>{c.entity}</a>
        <span className="sep">›</span>
        <a href="#" className="here" title={`claim ${c.id}`} onClick={(e) => e.preventDefault()}>claim</a>
        <button className="ibtn share" title="share a snapshot of this claim" aria-label="share a snapshot">
          <ShareGlyph />
        </button>
      </div>

      <div className={`insp-title${c.state === 'retracted' ? ' retracted' : ''}`}>{c.text}</div>

      <div className="insp-sec">
        <div className="kv">
          <span className="k">predicate</span>
          <span className="v"><a href="#" title="registry" onClick={(e) => e.preventDefault()}>{c.pred}</a></span>
        </div>
        <div className="kv">
          <span className="k">confidence</span>
          <span className="v">{c.conf.toFixed(2)}</span>
        </div>
        <div className="kv">
          <span className="k">status</span>
          <span className="v inline">
            <span className={`dot ${STATUS_DOT[c.status].cls}`}></span> {c.status} · {c.state}
            {c.successor && (
              <a href="#" className="succ" onClick={(e) => { e.preventDefault(); onOpen(c.successor!) }}>→ successor</a>
            )}
          </span>
        </div>
        <div className="kv">
          <span className="k">worlds</span>
          <span className="v"><a href="#" onClick={(e) => e.preventDefault()}>{c.world}</a></span>
        </div>
        <div className="kv">
          <span className="k">by</span>
          <span className="v inline">
            <span className={`seal ${actor.cls}`} title={actor.title}>{actor.mark}</span> {actor.name} · {c.source}
          </span>
        </div>
      </div>

      <div className="insp-sec">
        <span className="label">two clocks</span>
        <div className="twoclocks">
          <div className="tc-row">
            <span className="tc-dot"></span>
            <span className="when">{c.occurred}</span>
            <span className="what">occurred</span>
          </div>
          <div className="tc-gap">
            <span className="meta-line">{gapLine}</span>
          </div>
          <div className="tc-row">
            <span className="tc-dot hollow"></span>
            <span className="when">{c.learned}</span>
            <span className="what">learned</span>
          </div>
        </div>
      </div>

      <div className="insp-sec evidence">
        <span className="label">evidence</span>
        <div className="quote">“{c.quote}”</div>
        <span className="meta-line" title={`claim ${c.id} · source: ${c.source}`}>{c.meta}</span>
        <a className="act" href="#" title="context receipt · persona compile, activated memories, board ref, substrate (OF-369)" onClick={(e) => e.preventDefault()}>
          context receipt
        </a>
      </div>

      {c.note && (
        <div className="insp-sec">
          <span className="label">notes on record</span>
          <div className="aside-note">
            <span className="claim">{c.note.text}</span>
            <a className="byline aname" data-agent={c.note.by} href="#" title={`${c.note.by} · agent · noted ${c.note.when}`} onClick={(e) => e.preventDefault()}>
              {c.note.by} · {c.note.when}
            </a>
          </div>
        </div>
      )}

      <div className="insp-actions">
        <a className="act" href="#" title="verb: supersede_claim" onClick={(e) => e.preventDefault()}>supersede</a>
        <a className="act" href="#" title="verb: retract_claim" onClick={(e) => e.preventDefault()}>retract</a>
      </div>
    </aside>
  )
}
