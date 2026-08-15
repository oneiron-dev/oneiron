import * as React from 'react'
import { Link, createFileRoute } from '@tanstack/react-router'
import { cue, markCued, useEscape } from '~/components/safelight/hooks'
import orgsCss from '~/styles/orgs.css?url'

export const Route = createFileRoute('/app/orgs')({
  head: () => ({
    links: [{ rel: 'stylesheet', href: orgsCss }],
  }),
  component: Orgs,
})

/* ══ fixtures · the orgs the vault knows (JP-consulting register, stages
   from the pipeline). Hokuei is the pilot client; its dossier is the
   full record, the others carry lighter ones. today = 08-15. ══ */

type Stage =
  | 'sourced'
  | 'qualified'
  | 'outreach'
  | 'replied'
  | 'call booked'
  | 'audit'
  | 'proposal'
  | 'deposit'

type Owner = 'o' | 'y'

type Person = {
  seal: string
  line: string
  conf: 1 | 2 | 3 | 4
  tip: string
  door?: { text: string; href: string; tip: string }
}

type Claim = {
  text: string
  conf: 1 | 2 | 3 | 4
  state: 'approved' | 'auto' | 'proposed'
  tip: string
}

type Entry =
  | { kind: 'human'; seal: string; cls?: boolean; tip: string; msg: string; lang?: string; conf: 1 | 2 | 3 | 4 }
  | { kind: 'agent'; agent: 'eiri' | 'tory' | 'antevon'; name: string; tip: string; msg: string; conf: 1 | 2 | 3 | 4 }

type Note = { title: string; tip: string }

type Org = {
  id: string
  name: string
  stage: Stage
  owner: Owner
  touch: { date: string; time: string; tip: string }
  claims: number
  byline: string
  people: Person[]
  know: Claim[]
  thread: Entry[]
  next: { line: string; draft?: string; book?: boolean }
  notes: Note[]
}

const OWNER_TIP: Record<Owner, string> = {
  o: 'o · Owen · owner',
  y: 'y · Yuki',
}

const TODAY = '08-15'

const ORGS: Org[] = [
  {
    id: 'hokuei-foods',
    name: 'Hokuei Foods',
    stage: 'audit',
    owner: 'y',
    touch: { date: '08-15', time: '14:02', tip: '2026-08-15 14:02 · linkedin · Yuki' },
    claims: 42,
    byline: 'pilot client · supplier-consolidation storyline · Yuki owns it',
    people: [
      {
        seal: 'm',
        line: 'Mika Tanaka · procurement',
        conf: 2,
        tip: 'm · Mika Tanaka · contact · imported via LINE OA · prefers LINE for quick questions',
      },
      {
        seal: 'k',
        line: 'the COO · budget owner, not yet met',
        conf: 3,
        tip: 'k · the COO · contact · budget owner · not yet met',
        door: {
          text: 'reach through Yuki’s account',
          href: '/app/inbox',
          tip: 'Eiri asks before it reaches · the consent waits in your inbox',
        },
      },
    ],
    know: [
      { text: 'Pilot decision expected by July 18', conf: 1, state: 'approved', tip: 'confidence 0.94 · approved · occurred 08-10' },
      { text: 'Mika Tanaka leads procurement; prefers LINE for quick questions', conf: 2, state: 'auto', tip: 'confidence 0.86 · auto · occurred 08-05' },
      { text: 'Chilled line waste sits near 8% in summer months', conf: 2, state: 'auto', tip: 'confidence 0.83 · auto · occurred 07-29' },
      { text: 'May be consolidating suppliers this fiscal year', conf: 3, state: 'proposed', tip: 'confidence 0.58 · proposed by Tory from public filings · learned 08-14 · waits in your inbox' },
    ],
    thread: [
      { kind: 'human', seal: 'y', tip: 'y · Yuki · 08-15 14:02 · linkedin · sent from his account, his click · verifying', msg: 'Thanks for the call. Sending the pilot one-pager over email now.', conf: 1 },
      { kind: 'agent', agent: 'eiri', name: 'Eiri', tip: 'Eiri · outbound · 08-15 11:48 · email · draft approved by Yuki 11:46 · verified in thread', msg: 'Pilot scope summary: 12-week chilled-line forecast, weekly re-fit, waste target under 5%.', conf: 2 },
      { kind: 'human', seal: 'm', cls: true, tip: 'm · Mika Tanaka · 08-12 09:15 · LINE', msg: '見積もりの件、来週の火曜までにお願いできますか。', lang: 'ja', conf: 2 },
    ],
    next: { line: 'Send Mika the quote by Tuesday. Follow up on the one-pager if no reply by 08-19.', draft: 'draft the follow-up', book: true },
    notes: [
      { title: 'Pilot scope note', tip: 'note · Yuki · 08-11' },
      { title: 'Their reply pace changed after 08-09', tip: 'note · Tory · 08-14 · a competitor quote is likely on the table' },
    ],
  },
  {
    id: 'fuji-kitchens',
    name: 'Fuji Kitchens',
    stage: 'outreach',
    owner: 'y',
    touch: { date: '08-15', time: '09:40', tip: '2026-08-15 09:40 · email · Yuki' },
    claims: 31,
    byline: 'client · frozen-line forecast, 12 weeks · Yuki owns it',
    people: [
      { seal: 'r', line: 'Rina Sato · operations lead', conf: 1, tip: 'r · Rina Sato · contact · imported via email' },
    ],
    know: [
      { text: 'Deposit paid 08-10; kickoff set for 08-22', conf: 1, state: 'approved', tip: 'confidence 0.96 · approved · occurred 08-10' },
      { text: 'Frozen line runs three SKUs with weekly overs above 6%', conf: 2, state: 'auto', tip: 'confidence 0.84 · auto · occurred 08-08' },
      { text: 'Their ERP exports CSV weekly, no API', conf: 2, state: 'auto', tip: 'confidence 0.81 · auto · occurred 08-14' },
    ],
    thread: [
      { kind: 'human', seal: 'y', tip: 'y · Yuki · 08-15 09:40 · email', msg: 'Kickoff deck sent. Asked for the sales export by Friday.', conf: 1 },
      { kind: 'human', seal: 'r', cls: true, tip: 'r · Rina Sato · 08-14 17:10 · LINE', msg: 'データは金曜までにお送りします。', lang: 'ja', conf: 2 },
    ],
    next: { line: 'Confirm the export lands by Friday. Prepare the kickoff brief for 08-22.', draft: 'draft the follow-up' },
    notes: [{ title: 'Kickoff brief, 08-22', tip: 'brief · Antevon · compiles the day before' }],
  },
  {
    id: 'kanto-logistics',
    name: 'Kanto Logistics',
    stage: 'call booked',
    owner: 'o',
    touch: { date: '08-14', time: '16:20', tip: '2026-08-14 16:20 · linkedin · Owen' },
    claims: 18,
    byline: 'prospect · cold-chain routing waste · you own it',
    people: [
      { seal: 'h', line: 'Hiroshi Kondo · head of planning', conf: 2, tip: 'h · Hiroshi Kondo · contact · imported via linkedin' },
    ],
    know: [
      { text: 'Call booked for 08-18 15:00 with the head of planning', conf: 1, state: 'approved', tip: 'confidence 0.95 · approved · occurred 08-14' },
      { text: 'Runs 40 chilled trucks across Kanto; spoilage is tracked by hand', conf: 2, state: 'auto', tip: 'confidence 0.79 · auto · occurred 08-08' },
      { text: 'May be tendering a routing tool this autumn', conf: 3, state: 'proposed', tip: 'confidence 0.55 · proposed by Tory from a trade note · learned 08-13' },
    ],
    thread: [
      { kind: 'human', seal: 'o', tip: 'o · Owen · 08-14 16:20 · linkedin', msg: 'Confirmed Thursday 15:00. Sending an agenda tomorrow.', conf: 1 },
      { kind: 'human', seal: 'h', cls: true, tip: 'h · Hiroshi Kondo · 08-14 11:02 · linkedin', msg: '来週木曜15時でお願いします。', lang: 'ja', conf: 2 },
    ],
    next: { line: 'Send the agenda for 08-18. Ask for one month of route data before the call.', draft: 'draft the follow-up' },
    notes: [{ title: 'Call prep, 08-18', tip: 'brief · Antevon · compiles the day before' }],
  },
  {
    id: 'sakura-retail',
    name: 'Sakura Retail',
    stage: 'proposal',
    owner: 'y',
    touch: { date: '08-13', time: '10:15', tip: '2026-08-13 10:15 · email · Aya Mori' },
    claims: 11,
    byline: 'prospect · store-level replenishment · Yuki owns it',
    people: [
      { seal: 'a', line: 'Aya Mori · merchandising', conf: 2, tip: 'a · Aya Mori · contact · imported via email' },
    ],
    know: [
      { text: 'Replied 08-13; wants a one-page case before any call', conf: 1, state: 'approved', tip: 'confidence 0.92 · approved · occurred 08-13' },
      { text: 'Runs 120 stores; replenishment is a weekly spreadsheet', conf: 2, state: 'auto', tip: 'confidence 0.77 · auto · occurred 08-13' },
    ],
    thread: [
      { kind: 'human', seal: 'a', cls: true, tip: 'a · Aya Mori · 08-13 10:15 · email', msg: 'まず事例を1枚いただけますか。その後で相談させてください。', lang: 'ja', conf: 2 },
      { kind: 'agent', agent: 'eiri', name: 'Eiri', tip: 'Eiri · outbound · 08-11 09:30 · email · draft approved by Yuki · verified in thread', msg: 'Intro: demand forecasting for store replenishment, three lines.', conf: 2 },
    ],
    next: { line: 'Send the one-page case. Offer two call slots once it lands.', draft: 'draft the follow-up', book: true },
    notes: [],
  },
  {
    id: 'nishi-trading',
    name: 'Nishi Trading',
    stage: 'deposit',
    owner: 'o',
    touch: { date: '08-11', time: '13:00', tip: '2026-08-11 13:00 · meeting · Owen' },
    claims: 27,
    byline: 'prospect · import demand audit · you own it',
    people: [
      { seal: 't', line: 'Takeshi Nishi · managing director', conf: 1, tip: 't · Takeshi Nishi · contact · met 08-11' },
      { seal: 's', line: 'Saki Ueda · finance', conf: 2, tip: 's · Saki Ueda · contact · imported via email' },
    ],
    know: [
      { text: 'Audit under way; two years of import data received 08-09', conf: 1, state: 'approved', tip: 'confidence 0.97 · approved · occurred 08-09' },
      { text: 'Overstock on three lines ties up about ¥40M', conf: 2, state: 'auto', tip: 'confidence 0.82 · auto · occurred 08-11' },
      { text: 'Wants the audit read-out before 08-28', conf: 2, state: 'auto', tip: 'confidence 0.80 · auto · occurred 08-09' },
    ],
    thread: [
      { kind: 'human', seal: 'o', tip: 'o · Owen · 08-11 13:00 · meeting · 45 min · 9 claims extracted', msg: 'Audit kickoff, 45 minutes. Data in hand, questions sent.', conf: 1 },
      { kind: 'human', seal: 't', cls: true, tip: 't · Takeshi Nishi · 08-09 15:40 · email', msg: '7月20日までに結果を見たいです。', lang: 'ja', conf: 2 },
    ],
    next: { line: 'Finish the read-out by 08-25. Book the read-out call.', book: true },
    notes: [{ title: 'Audit working notes', tip: 'note · Owen · 08-13' }],
  },
  {
    id: 'meiji-bakeries',
    name: 'Meiji Bakeries',
    stage: 'replied',
    owner: 'y',
    touch: { date: '08-09', time: '11:20', tip: '2026-08-09 11:20 · email · Eiri' },
    claims: 6,
    byline: 'prospect · daily bake planning · Yuki owns it',
    people: [
      { seal: 'k', line: 'Kenta Ito · plant manager, not yet met', conf: 3, tip: 'k · Kenta Ito · contact · from the company site' },
    ],
    know: [
      { text: 'Intro sent 08-09; no reply yet', conf: 1, state: 'approved', tip: 'confidence 0.93 · approved · occurred 08-09' },
      { text: 'Bakes to a fixed daily plan; returns near 10%', conf: 3, state: 'auto', tip: 'confidence 0.62 · auto · a public interview, 2025' },
    ],
    thread: [
      { kind: 'agent', agent: 'eiri', name: 'Eiri', tip: 'Eiri · outbound · 08-09 11:20 · email · draft approved by Yuki · verified in thread', msg: 'Intro: daily bake planning from POS data, three lines.', conf: 2 },
    ],
    next: { line: 'Follow up on 08-16 if there is no reply.', draft: 'draft the follow-up' },
    notes: [],
  },
  {
    id: 'ohta-metals',
    name: 'Ohta Metals',
    stage: 'replied',
    owner: 'o',
    touch: { date: '08-06', time: '09:12', tip: '2026-08-06 09:12 · research · Tory' },
    claims: 4,
    byline: 'prospect · parts demand for two plants · you own it',
    people: [],
    know: [
      { text: 'Two plants in Gunma; ships to three auto suppliers', conf: 2, state: 'auto', tip: 'confidence 0.78 · auto · public filings' },
      { text: 'Fits the plant-demand profile; qualified 08-06', conf: 1, state: 'approved', tip: 'confidence 0.90 · approved · occurred 08-06' },
      { text: 'May be opening a third line in 2027', conf: 4, state: 'proposed', tip: 'confidence 0.35 · proposed by Tory from a trade note · learned 08-06' },
    ],
    thread: [
      { kind: 'agent', agent: 'tory', name: 'Tory', tip: 'Tory · research · 08-06 09:12 · reads only', msg: 'Two plants, three auto suppliers, no forecasting vendor named in the filings.', conf: 3 },
    ],
    next: { line: 'Find the planning lead. Then the intro.', draft: 'draft the intro' },
    notes: [],
  },
  {
    id: 'aoi-pharma',
    name: 'Aoi Pharma',
    stage: 'sourced',
    owner: 'o',
    touch: { date: '08-02', time: '08:05', tip: '2026-08-02 08:05 · research · Tory' },
    claims: 2,
    byline: 'sourced · OTC lines with seasonal swings · you own it',
    people: [],
    know: [
      { text: 'Sells OTC lines with strong seasonal swings', conf: 3, state: 'auto', tip: 'confidence 0.60 · auto · public filings' },
      { text: 'Sourced from a trade list 08-02', conf: 1, state: 'approved', tip: 'confidence 0.90 · approved · occurred 08-02' },
    ],
    thread: [
      { kind: 'agent', agent: 'tory', name: 'Tory', tip: 'Tory · research · 08-02 08:05 · reads only', msg: 'Sourced from the JPMA member list. Seasonal OTC lines, no vendor named.', conf: 3 },
    ],
    next: { line: 'Qualify or drop by 08-23.' },
    notes: [],
  },
]

/* watched on load: two orgs already under watch; Hokuei is not, so the
   foot act has something to do */
const WATCHED_AT_LOAD = ['kanto-logistics', 'aoi-pharma']

type Filter = 'all' | 'watched' | 'mine'

const DOT: Record<Claim['state'], { cls: string; tip: string }> = {
  approved: { cls: 'dot dot-approved', tip: 'approved' },
  auto: { cls: 'dot dot-auto', tip: 'auto · trusted, unreviewed' },
  proposed: { cls: 'dot dot-proposed', tip: 'proposed · waits in your inbox' },
}

/* ══ the page ══ */
function Orgs() {
  const [sel, setSel] = React.useState<string | null>('hokuei-foods')
  const [filter, setFilter] = React.useState<Filter>('all')
  const [hintOpen, setHintOpen] = React.useState(false)
  const [watched, setWatched] = React.useState<Set<string>>(() => new Set(WATCHED_AT_LOAD))
  /* the next-step acts settle in place, per org: the verb cools into a receipt */
  const [settled, setSettled] = React.useState<Record<string, { drafted?: boolean; booked?: boolean }>>({})

  useEscape(() => setSel(null))

  const select = (id: string) => {
    setSel((cur) => (cur === id ? null : id))
    cue('toggle')
  }
  const onRowClick = (id: string) => (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest('a, button')) return
    select(id)
  }
  const onRowKey = (id: string) => (e: React.KeyboardEvent) => {
    if ((e.key === 'Enter' || e.key === ' ') && !(e.target as HTMLElement).closest('a, button')) {
      e.preventDefault()
      select(id)
    }
  }
  const toggleWatch = (id: string) => (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    markCued(e)
    setWatched((cur) => {
      const next = new Set(cur)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
    cue(watched.has(id) ? 'press' : 'success')
  }
  const settle = (id: string, key: 'drafted' | 'booked') => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setSettled((cur) => ({ ...cur, [id]: { ...cur[id], [key]: true } }))
    cue('success')
  }
  const pick = (f: Filter) => () => {
    setFilter(f)
    cue('toggle')
  }

  const rows = ORGS.filter((o) =>
    filter === 'all' ? true : filter === 'watched' ? watched.has(o.id) : o.owner === 'o',
  )
  const org = sel ? ORGS.find((o) => o.id === sel) ?? null : null

  return (
    <main className="pane orgs" id="pane">
      <div className="pane-body">
        <div className="pane-head">
          <h1>Orgs</h1>
          <span className="pane-tools">
            <button
              className="hint-btn"
              aria-expanded={hintOpen}
              aria-controls="orgs-why"
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
        <div className="dial-why" id="orgs-why" hidden={!hintOpen}>
          <span className="why-voice">
            Every organisation the vault knows, one line each. Click a row to read its dossier.
            Watch an org and its changes land in your inbox.
          </span>
        </div>

        {/* chrome: a view filter, never a policy */}
        <div className="filters">
          <span className="set" role="group" aria-label="show">
            <span className="label">show</span>
            <button className={filter === 'all' ? 'chip on' : 'chip'} onClick={pick('all')} aria-pressed={filter === 'all'}>
              all
            </button>
            <button
              className={filter === 'watched' ? 'chip on' : 'chip'}
              onClick={pick('watched')}
              aria-pressed={filter === 'watched'}
              title="orgs under watch · their changes land in your inbox"
            >
              watched
            </button>
            <button
              className={filter === 'mine' ? 'chip on' : 'chip'}
              onClick={pick('mine')}
              aria-pressed={filter === 'mine'}
              title="orgs you own"
            >
              mine
            </button>
          </span>
        </div>

        {/* ══ INSTRUMENT · the orgs lens (agent-rendered) ══ */}
        <section className="instrument" aria-label="orgs lens">
          <div
            className="instrument-eyebrow"
            title="agent-rendered lens · Antevon compiles it from the vault · re-renders when evidence changes"
          >
            <span>orgs lens · Antevon · as of 14:07</span>
          </div>
          <div className="ledger-wrap">
            <table className="ledger">
              <thead>
                <tr>
                  <th>org</th>
                  <th className="c-stage">stage</th>
                  <th className="c-owner">owner</th>
                  <th className="c-touch">last touch</th>
                  <th className="c-claims">claims</th>
                  <th className="c-watch" title="watch"></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((o) => {
                  const on = watched.has(o.id)
                  return (
                    <tr
                      key={o.id}
                      className={sel === o.id ? 'selected' : undefined}
                      tabIndex={0}
                      aria-selected={sel === o.id}
                      onClick={onRowClick(o.id)}
                      onKeyDown={onRowKey(o.id)}
                    >
                      <td>
                        <span className="org-name">{o.name}</span>
                      </td>
                      <td className="c-stage">
                        <a className="stage" href="/app/pipeline" title={`pipeline · ${o.stage}`}>
                          {o.stage}
                        </a>
                      </td>
                      <td className="c-owner">
                        <span className="seal seal-human" title={OWNER_TIP[o.owner]}>
                          {o.owner}
                        </span>
                      </td>
                      <td className="c-touch">
                        <span className={o.touch.date === TODAY ? 'touch today' : 'touch'} title={o.touch.tip}>
                          {o.touch.date}
                        </span>
                      </td>
                      <td className="c-claims">
                        <Link className="count" to="/app/vault" title={`the vault, filtered to ${o.name}`}>
                          {o.claims}
                        </Link>
                      </td>
                      <td className="c-watch">
                        <button
                          className={on ? 'watch on' : 'watch'}
                          aria-pressed={on}
                          aria-label={on ? `stop watching ${o.name}` : `watch ${o.name}`}
                          title={on ? 'watching · click to stop' : 'watch this org · its changes land in your inbox'}
                          onClick={toggleWatch(o.id)}
                        />
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
            {rows.length === 0 && (
              <div className="ledger-empty">
                {filter === 'watched' ? 'No org under watch yet.' : 'No org of yours yet.'}
              </div>
            )}
          </div>
        </section>
      </div>

      {/* ── the dossier: something you READ, so it lives in the column ── */}
      <aside className="context" hidden={!org} aria-label="the dossier">
        {org && (
          <Dossier
            key={org.id}
            org={org}
            watched={watched.has(org.id)}
            settled={settled[org.id] ?? {}}
            onWatch={toggleWatch(org.id)}
            onSettle={(k) => settle(org.id, k)}
            onClose={() => setSel(null)}
          />
        )}
      </aside>
    </main>
  )
}

/* ══ the dossier · a calm printed record ══ */
function Dossier({
  org,
  watched,
  settled,
  onWatch,
  onSettle,
  onClose,
}: {
  org: Org
  watched: boolean
  settled: { drafted?: boolean; booked?: boolean }
  onWatch: (e: React.MouseEvent) => void
  onSettle: (k: 'drafted' | 'booked') => (e: React.MouseEvent) => void
  onClose: () => void
}) {
  const crumb = `orgs · ${org.name.toLowerCase()}`
  return (
    <>
      <div className="ctx-head">
        <span className="ctx-crumb" title="Antevon compiles the dossier from the vault · as of 13:44">
          {crumb}
        </span>
        <button className="chat-close" aria-label="close the dossier" title="close · esc" onClick={onClose}>
          ×
        </button>
      </div>
      <div className="dhead">
        <div className="ctx-title">{org.name}</div>
        <div className="ctx-byline">{org.byline}</div>
      </div>

      {/* people */}
      <section className="dsec" aria-label="people">
        <span className="label">people</span>
        {org.people.length === 0 && <span className="dline quiet">No one on record yet.</span>}
        {org.people.map((p) => (
          <div className="drow" key={p.seal + p.line}>
            <span className="seal seal-human seal-class" title={p.tip}>
              {p.seal}
            </span>
            <span className="dstack">
              <span className={`dline conf-${p.conf}`}>{p.line}</span>
              {p.door && (
                <Link className="act quiet" to={p.door.href} title={p.door.tip}>
                  {p.door.text}
                </Link>
              )}
            </span>
          </div>
        ))}
      </section>

      {/* what we know · every claim is a door to the vault */}
      <section className="dsec" aria-label="what we know">
        <span className="label">what we know</span>
        {org.know.map((c) => (
          <div className="drow" key={c.text}>
            <span className={DOT[c.state].cls} title={DOT[c.state].tip}></span>
            <Link className={`dline conf-${c.conf}`} to="/app/vault" title={c.tip}>
              {c.text}
            </Link>
          </div>
        ))}
        <Link className="act" to="/app/vault" title={`the vault, filtered to ${org.name}`}>
          all {org.claims} claims
        </Link>
      </section>

      {/* the thread · seal or name, the line; time and channel ride the tooltip */}
      <section className="dsec" aria-label="the thread">
        <span className="label">the thread</span>
        {org.thread.map((t, i) => (
          <div className="drow" key={i}>
            {t.kind === 'human' ? (
              <span className={t.cls ? 'seal seal-human seal-class' : 'seal seal-human'} title={t.tip}>
                {t.seal}
              </span>
            ) : (
              <span className="aname" data-agent={t.agent} title={t.tip}>
                {t.name}
              </span>
            )}
            <span className={`dline conf-${t.conf}`} lang={t.kind === 'human' ? t.lang : undefined}>
              {t.msg}
            </span>
          </div>
        ))}
        <a className="act" href="/app/threads" title={`threads · ${org.name} · every channel`}>
          the thread
        </a>
      </section>

      {/* next step · the acts settle in place */}
      <section className="dsec" aria-label="next step">
        <span className="label">next step</span>
        <span className="dnext">{org.next.line}</span>
        <div className="dacts">
          {org.next.draft && !settled.drafted && (
            <button
              className="act"
              type="button"
              title="verb: draft_message · Eiri drafts · the send stays your click"
              onClick={onSettle('drafted')}
            >
              {org.next.draft}
            </button>
          )}
          {org.next.book && !settled.booked && (
            <button className="act" type="button" title="verb: book_call · Eiri offers slots on the thread" onClick={onSettle('booked')}>
              book the call
            </button>
          )}
          <a className="act" href="/app/pipeline" title={`pipeline · ${org.stage} · ${org.name}`}>
            open in pipeline
          </a>
        </div>
        {(settled.drafted || settled.booked) && (
          <div className="receipts">
            {settled.drafted && (
              <span className="receipt">
                <span className="aname" data-agent="eiri" title="Eiri · outbound · the draft waits for your click">
                  Eiri
                </span>
                <span>is drafting · lands in your inbox</span>
              </span>
            )}
            {settled.booked && (
              <span className="receipt">
                <span className="aname" data-agent="eiri" title="Eiri · outbound · two slots go out on the thread">
                  Eiri
                </span>
                <span>is booking · slots go out on the thread</span>
              </span>
            )}
          </div>
        )}
      </section>

      {/* notes · doors to the notes lens */}
      {org.notes.length > 0 && (
        <section className="dsec" aria-label="notes">
          <span className="label">notes</span>
          {org.notes.map((n) => (
            <div className="drow" key={n.title}>
              <a className="dline conf-2" href="/app/notes" title={n.tip}>
                {n.title}
              </a>
            </div>
          ))}
        </section>
      )}

      {/* the foot act cools into its state */}
      <div className="dfoot">
        {watched ? (
          <span className="receipt" title="the ledger dot stops the watch">
            watching · changes land in your inbox digest
          </span>
        ) : (
          <button className="act" type="button" title="verb: watch_org · a saved query · changes land in your inbox" onClick={onWatch}>
            watch this org
          </button>
        )}
      </div>
    </>
  )
}
