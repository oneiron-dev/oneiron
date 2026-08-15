import * as React from 'react'
import { Link, createFileRoute } from '@tanstack/react-router'
import { cue, markCued, openChat, useEscape } from '~/components/safelight/hooks'
import briefsCss from '~/styles/briefs.css?url'

export const Route = createFileRoute('/app/briefs')({
  head: () => ({
    links: [{ rel: 'stylesheet', href: briefsCss }],
  }),
  component: Briefs,
})

/* ── the cast (FLOWS §2 · rule 15): companions Eiri (outbound) and Tory
   (research); the house mind is Antevon. the name in its ink is the
   mark — never a dot beside it. ── */
type Agent = 'antevon' | 'tory' | 'eiri'
const AGENT: Record<Agent, { name: string; tip: string }> = {
  antevon: { name: 'Antevon', tip: 'Antevon · the house mind' },
  tory: { name: 'Tory', tip: 'Tory · research companion' },
  eiri: { name: 'Eiri', tip: 'Eiri · outbound companion · every send waits for your click' },
}
function Aname({ who, tip }: { who: Agent; tip?: string }) {
  return (
    <span className="aname" data-agent={who} title={tip ?? AGENT[who].tip}>
      {AGENT[who].name}
    </span>
  )
}

/* ── fixtures: five briefs, three age groups ── */
type BriefId = 'hokuei' | 'night' | 'week' | 'kanto' | 'rumor'
type Group = 'today' | 'this week' | 'earlier'
type BriefRow = {
  id: BriefId
  title: string
  forWhom: string
  by: Agent
  when: string /* hover-tier: rides the row's title */
  group: Group
}
const BRIEFS: BriefRow[] = [
  {
    id: 'hokuei',
    title: 'Meeting brief: Hokuei pilot call, Thursday 10:00',
    forWhom: 'Hokuei · pilot call',
    by: 'antevon',
    when: 'prepared today 06:40',
    group: 'today',
  },
  {
    id: 'night',
    title: 'Night-shift note: 03:12 run, one line per receipt',
    forWhom: 'the vault · nightly run',
    by: 'antevon',
    when: 'prepared today 04:05',
    group: 'today',
  },
  {
    id: 'week',
    title: 'Week in review, Aug 8–14',
    forWhom: 'antevon / ops',
    by: 'antevon',
    when: 'prepared Fri Aug 14 · 18:00',
    group: 'this week',
  },
  {
    id: 'kanto',
    title: 'Kanto Logistics: what to know before the call',
    forWhom: 'Kanto Logistics · first call',
    by: 'tory',
    when: 'prepared Wed Aug 12 · 17:20',
    group: 'this week',
  },
  {
    id: 'rumor',
    title: 'Supplier rumor: filings read',
    forWhom: 'Hokuei · supplier watch',
    by: 'tory',
    when: 'prepared Thu Aug 6 · 09:40',
    group: 'earlier',
  },
]
const GROUPS: Group[] = ['today', 'this week', 'earlier']

/* per-brief state: read settles once; a draft act settles once */
type DocState = { readAt: string | null; drafting: boolean }
const nowHHMM = () => {
  const d = new Date()
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
}

/* ── document atoms ── */
function Sec({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <section className="bsec" aria-label={label}>
      <span className="label">{label}</span>
      {children}
    </section>
  )
}
/* a cited phrase is a door into the vault; the claim's confidence rides
   its ink, the exact numeral rides the title */
function Cite({
  id,
  conf,
  children,
}: {
  id: string
  conf: number
  children: React.ReactNode
}) {
  const rung = conf >= 0.9 ? 'conf-1' : conf >= 0.7 ? 'conf-2' : conf >= 0.4 ? 'conf-3' : 'conf-4'
  return (
    <Link
      to="/app/vault"
      className={`cited ${rung}`}
      title={`${id} · ${conf.toFixed(2)} · open the claim in the vault`}
    >
      {children}
    </Link>
  )
}
function Sep() {
  return <span className="sep">·</span>
}

/* the provenance eyebrow: this document is agent-rendered; its receipt
   reads first. every mono token is a door. */
function Eyebrow({ children, tip }: { children: React.ReactNode; tip: string }) {
  return (
    <div className="instrument-eyebrow" title={tip}>
      {children}
    </div>
  )
}

/* the foot: read settles into a receipt line; ask opens a chat about it */
function Foot({
  state,
  onRead,
}: {
  state: DocState
  onRead: (e: React.MouseEvent) => void
}) {
  return (
    <div className="brief-foot">
      {state.readAt ? (
        <span className="meta-line" title="marked read · yours">
          read {state.readAt}
        </span>
      ) : (
        <a className="act" href="#" title="verb: mark_read" onClick={onRead}>
          mark read
        </a>
      )}
      <a
        className="act"
        href="#"
        title="opens a chat scoped to this brief"
        onClick={(e) => {
          e.preventDefault()
          openChat('ask')
        }}
      >
        ask about this brief
      </a>
    </div>
  )
}

/* the draft act cools into the companion's name and what she is doing */
function DraftAct({
  state,
  label,
  onDraft,
}: {
  state: DocState
  label: string
  onDraft: (e: React.MouseEvent) => void
}) {
  if (state.drafting)
    return (
      <span className="doing-line" title="Eiri · a draft lands in the inbox for your click">
        <Aname who="eiri" />
        <span className="doing">is drafting</span>
      </span>
    )
  return (
    <a className="act" href="#" title="verb: draft · Eiri writes it, you send it" onClick={onDraft}>
      {label}
    </a>
  )
}

/* ── the documents ── */
type DocProps = {
  state: DocState
  onRead: (e: React.MouseEvent) => void
  onDraft: (e: React.MouseEvent) => void
}

function HokueiBrief({ state, onRead, onDraft }: DocProps) {
  return (
    <article className="brief" aria-label="Meeting brief: Hokuei pilot call">
      <Eyebrow tip="agent-rendered · Antevon · built 06:40 from the vault · every load-bearing sentence cites its claim">
        <span>brief</span>
        <Sep />
        <Link to="/app/vault" title="the 14 claims this brief stands on">
          built from 14 claims
        </Link>
        <Sep />
        <a href="/app/threads" title="the 3 threads it read">
          3 threads
        </a>
        <Sep />
        <span>as of 06:40</span>
      </Eyebrow>

      <div className="brief-head">
        <h2>Meeting brief: Hokuei pilot call, Thursday 10:00</h2>
        <div className="brief-by">
          <Aname who="antevon" tip="Antevon · the house mind · prepared this brief 06:40 today" />
          <Sep />
          <span>call Thu 10:00</span>
        </div>
      </div>

      <Sec label="what to know">
        <ul>
          <li>
            <Cite id="cl_2c71" conf={0.93}>
              Hokuei runs a two-week close on procurement decisions
            </Cite>
            . Thursday is inside the window. Mika Tanaka needs the numbers by Tuesday.
          </li>
          <li>
            <Cite id="cl_9d17" conf={0.81}>
              Hokuei may be consolidating suppliers this fiscal year
            </Cite>
            . Tory read it in the filings. It waits for your review in the inbox.
          </li>
          <li>
            <Cite id="cl_44b1" conf={0.92}>
              Client-facing numbers come from the model registry
            </Cite>
            . The pre-read carries registry figures only.
          </li>
        </ul>
      </Sec>

      <Sec label="who's in the room">
        <div className="who">
          <div className="who-row">
            <span className="seal seal-human seal-class" title="m · Mika Tanaka · contact">
              m
            </span>
            <span className="wname">Mika Tanaka</span>
            <span className="wrole">procurement</span>
          </div>
          <div className="who-row">
            <span className="seal-slot" aria-hidden="true"></span>
            <span className="wname">the COO</span>
            <span className="wrole">not yet reached</span>
          </div>
        </div>
      </Sec>

      <Sec label="open questions">
        <ul>
          <li>Does the pilot scope include the Osaka warehouse?</li>
          <li>Who signs, procurement or the COO?</li>
        </ul>
      </Sec>

      <Sec label="what we promised">
        <div className="promise">
          <span className="pclaim">
            <Cite id="cl_1e08" conf={0.96}>
              We promised an eight-week pilot from kickoff
            </Cite>
            .
          </span>
          <div className="clocks">
            <span className="clock" title="occurred · when it was said">
              <span className="cdot" aria-hidden="true"></span>
              <span className="cwhat">occurred</span>
              <Link to="/app/vault" className="cwhen" title="the claim · as of 2026-03-12">
                2026-03-12
              </Link>
            </span>
            <span className="clock" title="learned · when the vault got it">
              <span className="cdot hollow" aria-hidden="true"></span>
              <span className="cwhat">learned</span>
              <Link to="/app/vault" className="cwhen hollow" title="the scope note · learned 2026-06-24">
                2026-06-24
              </Link>
            </span>
            <span className="gap">3 months apart</span>
          </div>
          <span className="pnote">
            We said it in March. The vault learned it in June, from the scope note.
          </span>
        </div>
      </Sec>

      <Sec label="next step">
        <div className="next">
          <p>Send the pre-read to Mika Tanaka before Tuesday. Ask her for twenty minutes with the COO.</p>
          <div className="bacts">
            <DraftAct state={state} label="draft the follow-up" onDraft={onDraft} />
            <a className="act" href="/app/orgs" title="Hokuei · the org">
              open the org
            </a>
            <a className="act" href="/app/pipeline" title="Hokuei · pilot · in the pipeline">
              open in pipeline
            </a>
          </div>
        </div>
      </Sec>

      <Foot state={state} onRead={onRead} />
    </article>
  )
}

const NIGHT_ROWS: { t: string; what: string; out: string; tip: string; conf?: string }[] = [
  { t: '03:12', what: 'The run began: three threads and two imports to read.', out: 'began', tip: 'rx_7b12 · run start' },
  { t: '03:14', what: 'Read the LINE thread with Mika Tanaka.', out: 'read', tip: 'rx_7b12 · read receipt' },
  { t: '03:19', what: 'Wrote 12 claims from the Hokuei email thread.', out: 'written', tip: '12 writes · each receipted' },
  { t: '03:26', what: 'May be allergic to shellfish. One source only, so it waits.', out: 'waits', tip: 'cl_58aa · 0.52 · in the inbox', conf: 'conf-3' },
  { t: '03:31', what: 'Hokuei may be consolidating suppliers. It contradicts a May claim, so it waits.', out: 'waits', tip: 'cl_9d17 · 0.81 · in the inbox', conf: 'conf-2' },
  { t: '03:40', what: 'Wrote 28 claims from the LinkedIn import.', out: 'written', tip: '28 writes · each receipted' },
  { t: '03:52', what: 'Merged two records for Mika Tanaka into one.', out: 'merged', tip: 'ct_0a3f · the merge receipt' },
  { t: '04:05', what: 'The run ended. Every write has a receipt.', out: 'ended', tip: 'rx_7b12 · run end · 53 min' },
]

function NightNote({ state, onRead }: DocProps) {
  return (
    <article className="brief" aria-label="Night-shift note">
      <Eyebrow tip="agent-rendered · Antevon · run rx_7b12 · 03:12 to 04:05 · 42 writes, 2 wait">
        <span>night-shift note</span>
        <Sep />
        <a href="/app/agents" title="run rx_7b12 · the run's receipts">
          run rx_7b12
        </a>
        <Sep />
        <Link to="/app/vault" title="the 42 writes">
          42 writes
        </Link>
        <Sep />
        <span>as of 04:05</span>
      </Eyebrow>

      <div className="brief-head">
        <h2>Night-shift note: 03:12 run, one line per receipt</h2>
        <div className="brief-by">
          <Aname who="antevon" tip="Antevon · the house mind · the overnight run" />
          <Sep />
          <span>run 03:12 to 04:05</span>
        </div>
      </div>

      <p className="brief-lead">
        The night wrote 42 claims. Two wait for you in the inbox. Nothing crossed a channel.
      </p>

      <section className="instrument" aria-label="the receipts">
        <table className="ledger">
          <thead>
            <tr>
              <th className="c-time">time</th>
              <th>what</th>
              <th className="c-out">outcome</th>
            </tr>
          </thead>
          <tbody>
            {NIGHT_ROWS.map((r) => (
              <tr key={r.t}>
                <td>
                  <a className="tm" href="#" title={r.tip}>
                    {r.t}
                  </a>
                </td>
                <td>
                  <span className={r.conf ? `claim ${r.conf}` : 'claim'} title={r.conf ? r.tip : undefined}>
                    {r.what}
                  </span>
                </td>
                <td>
                  {r.out === 'waits' ? (
                    <Link className={`out ${r.out}`} to="/app/inbox" title={`${r.tip} · open the inbox`}>
                      {r.out}
                    </Link>
                  ) : (
                    <a className={`out ${r.out}`} href="#" title={r.tip}>
                      {r.out}
                    </a>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <Sec label="next step">
        <div className="next">
          <p>Two claims wait for your click. The rest is in.</p>
          <div className="bacts">
            <Link className="act" to="/app/inbox" title="the two that wait">
              open the inbox
            </Link>
            <a className="act" href="/app/agents" title="run rx_7b12 · every receipt">
              the run
            </a>
          </div>
        </div>
      </Sec>

      <Foot state={state} onRead={onRead} />
    </article>
  )
}

function WeekReview({ state, onRead }: DocProps) {
  return (
    <article className="brief" aria-label="Week in review">
      <Eyebrow tip="agent-rendered · Antevon · built Fri 18:00 from the week's receipts">
        <span>week in review</span>
        <Sep />
        <a href="/app/agents" title="the 61 receipts behind this digest">
          built from 61 receipts
        </a>
        <Sep />
        <a href="/app/threads" title="the 5 threads it read">
          5 threads
        </a>
        <Sep />
        <span>as of Aug 14 18:00</span>
      </Eyebrow>

      <div className="brief-head">
        <h2>Week in review, Aug 8–14</h2>
        <div className="brief-by">
          <Aname who="antevon" tip="Antevon · the house mind · prepared this digest Fri 18:00" />
          <Sep />
          <span>Aug 8 to 14</span>
        </div>
      </div>

      <p className="brief-lead">
        A quiet week that moved one thing: Hokuei booked the pilot call. Kanto Logistics answered.
      </p>

      <Sec label="what moved">
        <ul>
          <li>
            <Cite id="cl_7a20" conf={0.95}>
              Hokuei booked the pilot call for Thursday 10:00
            </Cite>
            . Mika Tanaka confirmed it on LINE.
          </li>
          <li>
            <Cite id="cl_5b3e" conf={0.88}>
              Kanto Logistics replied to the intro
            </Cite>
            . No call is booked yet. Yurii owns the next message.
          </li>
          <li>
            <Cite id="cl_9d17" conf={0.81}>
              Hokuei may be consolidating suppliers
            </Cite>
            . Tory read the filings. The claim waits in the inbox.
          </li>
        </ul>
      </Sec>

      <Sec label="by the numbers">
        <div className="nums">
          <div className="kv">
            <span className="k">writes</span>
            <span className="v">
              <Link to="/app/vault" title="the week's writes in the vault">
                212
              </Link>
            </span>
          </div>
          <div className="kv">
            <span className="k">sends</span>
            <span className="v">
              <a href="/app/threads" title="9 sends · every one your click">
                9
              </a>
            </span>
          </div>
          <div className="kv">
            <span className="k">calls</span>
            <span className="v">
              <a href="/app/today" title="3 calls · today lens">
                3
              </a>
            </span>
          </div>
          <div className="kv">
            <span className="k">waited for you</span>
            <span className="v">
              <Link to="/app/inbox" title="7 waited · 5 settled · 2 still wait">
                7
              </Link>
            </span>
          </div>
        </div>
      </Sec>

      <Sec label="next week">
        <div className="next">
          <p>Thursday is the Hokuei call. Book the Kanto Logistics call before then.</p>
          <div className="bacts">
            <a className="act" href="/app/pipeline" title="the funnel">
              open the pipeline
            </a>
            <a className="act" href="/app/today" title="what is due">
              open today
            </a>
          </div>
        </div>
      </Sec>

      <Foot state={state} onRead={onRead} />
    </article>
  )
}

function KantoBrief({ state, onRead, onDraft }: DocProps) {
  return (
    <article className="brief" aria-label="Kanto Logistics brief">
      <Eyebrow tip="agent-rendered · Tory · built Wed 17:20 from public sources and the intro thread">
        <span>brief</span>
        <Sep />
        <Link to="/app/vault" title="the 9 claims this brief stands on">
          built from 9 claims
        </Link>
        <Sep />
        <a href="/app/threads" title="the 2 threads it read">
          2 threads
        </a>
        <Sep />
        <span>as of Aug 12 17:20</span>
      </Eyebrow>

      <div className="brief-head">
        <h2>Kanto Logistics: what to know before the call</h2>
        <div className="brief-by">
          <Aname who="tory" tip="Tory · research companion · prepared this brief Wed 17:20" />
          <Sep />
          <span>first call · not booked</span>
        </div>
      </div>

      <Sec label="what to know">
        <ul>
          <li>
            <Cite id="cl_c410" conf={0.91}>
              Kanto Logistics runs four warehouses in the Kanto region
            </Cite>
            . Two are cold chain.
          </li>
          <li>
            <Cite id="cl_c418" conf={0.62}>
              One planner does the demand forecast in a spreadsheet
            </Cite>
            . One source, a job posting. Treat it as a guess until they say it.
          </li>
          <li>
            <Cite id="cl_c42b" conf={0.74}>
              They lost a 3PL contract in June
            </Cite>
            . Two trade articles agree on the month, not on the size.
          </li>
        </ul>
      </Sec>

      <Sec label="who's in the room">
        <div className="who">
          <div className="who-row">
            <span className="seal-slot" aria-hidden="true"></span>
            <span className="wname">Ren Sato</span>
            <span className="wrole">head of planning</span>
          </div>
          <div className="who-row">
            <span className="seal-slot" aria-hidden="true"></span>
            <span className="wname">the CFO</span>
            <span className="wrole">not yet reached</span>
          </div>
        </div>
      </Sec>

      <Sec label="next step">
        <div className="next">
          <p>Book the call. Yurii owns the intro. Lead with the June contract, not the spreadsheet.</p>
          <div className="bacts">
            <DraftAct state={state} label="draft the intro" onDraft={onDraft} />
            <a className="act" href="/app/orgs" title="Kanto Logistics · the org">
              open the org
            </a>
            <a className="act" href="/app/pipeline" title="Kanto Logistics · lead · in the pipeline">
              open in pipeline
            </a>
          </div>
        </div>
      </Sec>

      <Foot state={state} onRead={onRead} />
    </article>
  )
}

const FILINGS: { d: string; what: string; src: string; tip: string }[] = [
  { d: '2026-07-28', what: 'Notice of change to the approved supplier list.', src: 'edinet', tip: 'the filing · public' },
  { d: '2026-07-30', what: 'Two supplier codes retired, none added.', src: 'edinet', tip: 'the filing · public' },
  { d: '2026-08-04', what: 'A trade note reads it as consolidation.', src: 'nikkei', tip: 'the article · one source' },
]

function RumorBrief({ state, onRead }: DocProps) {
  return (
    <article className="brief" aria-label="Supplier rumor brief">
      <Eyebrow tip="agent-rendered · Tory · run rx_8c41 · public filings · built Aug 6 09:40">
        <span>brief</span>
        <Sep />
        <a href="/app/agents" title="run rx_8c41 · Tory · public filings">
          run rx_8c41
        </a>
        <Sep />
        <span>built from 6 filings</span>
        <Sep />
        <span>as of Aug 6 09:40</span>
      </Eyebrow>

      <div className="brief-head">
        <h2>Supplier rumor: filings read</h2>
        <div className="brief-by">
          <Aname who="tory" tip="Tory · research companion · run rx_8c41" />
          <Sep />
          <span>Hokuei · supplier watch</span>
        </div>
      </div>

      <p className="brief-lead">
        Hokuei changed its supplier list twice in a week. It reads like consolidation, not
        expansion. The claim went to the inbox at 0.81.
      </p>

      <section className="instrument" aria-label="the filings">
        <table className="ledger">
          <thead>
            <tr>
              <th className="c-time">date</th>
              <th>filing</th>
              <th className="c-src">source</th>
            </tr>
          </thead>
          <tbody>
            {FILINGS.map((r) => (
              <tr key={r.d}>
                <td>
                  <a className="tm" href="#" title={r.tip}>
                    {r.d}
                  </a>
                </td>
                <td>
                  <span className="claim">{r.what}</span>
                </td>
                <td>
                  <a className="src" href="#" title={r.tip}>
                    {r.src}
                  </a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <Sec label="what it means">
        <ul>
          <li>
            <Cite id="cl_9d17" conf={0.81}>
              Hokuei may be consolidating suppliers this fiscal year
            </Cite>
            . It contradicts the May claim that they were expanding.
          </li>
          <li>Fewer suppliers means a bigger share for whoever stays. The pilot is the way in.</li>
        </ul>
      </Sec>

      <Sec label="next step">
        <div className="next">
          <p>Ask Mika Tanaka on Thursday. Do not lead with it.</p>
          <div className="bacts">
            <Link className="act" to="/app/vault" title="cl_9d17 · the claim">
              open the claim
            </Link>
            <a className="act" href="/app/lens/supplier-watch" title="supplier watch · the lens">
              open the lens
            </a>
          </div>
        </div>
      </Sec>

      <Foot state={state} onRead={onRead} />
    </article>
  )
}

/* ── the page ── */
function Briefs() {
  const [sel, setSel] = React.useState<BriefId>('hokuei')
  /* a new brief starts at its own top, never mid-scroll of the last one */
  const bodyRef = React.useRef<HTMLDivElement>(null)
  const [hintOpen, setHintOpen] = React.useState(false)
  /* read = a receipt (when); the Hokuei brief is the one still unread */
  const [docs, setDocs] = React.useState<Record<BriefId, DocState>>({
    hokuei: { readAt: null, drafting: false },
    night: { readAt: '08:12', drafting: false },
    week: { readAt: 'Aug 14 18:40', drafting: false },
    kanto: { readAt: 'Aug 12 18:02', drafting: false },
    rumor: { readAt: 'Aug 6 10:15', drafting: false },
  })
  useEscape(() => setHintOpen(false))
  React.useEffect(() => {
    bodyRef.current?.scrollTo({ top: 0 })
  }, [sel])

  const pick = (id: BriefId) => () => {
    if (id === sel) return
    setSel(id)
    cue('toggle')
  }
  const markRead = (id: BriefId) => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setDocs((d) => ({ ...d, [id]: { ...d[id], readAt: nowHHMM() } }))
    cue('success')
  }
  const draft = (id: BriefId) => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setDocs((d) => ({ ...d, [id]: { ...d[id], drafting: true } }))
    cue('press')
  }

  /* unread until you mark it read; opening alone does not settle it */
  const isUnread = (b: BriefRow) => !docs[b.id].readAt

  const props = (id: BriefId): DocProps => ({
    state: docs[id],
    onRead: markRead(id),
    onDraft: draft(id),
  })
  const doc =
    sel === 'hokuei' ? (
      <HokueiBrief {...props('hokuei')} />
    ) : sel === 'night' ? (
      <NightNote {...props('night')} />
    ) : sel === 'week' ? (
      <WeekReview {...props('week')} />
    ) : sel === 'kanto' ? (
      <KantoBrief {...props('kanto')} />
    ) : (
      <RumorBrief {...props('rumor')} />
    )

  return (
    <main className="pane" id="pane">
      {/* the index column: a tinted zone divides, not a line */}
      <aside className="blist" aria-label="briefs">
        <div className="pane-head">
          <h1>Briefs</h1>
          <span className="pane-tools">
            <button
              className="hint-btn"
              aria-expanded={hintOpen}
              aria-controls="briefs-why"
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
        <div className="dial-why" id="briefs-why" hidden={!hintOpen}>
          <span className="why-voice">
            Your agents prepare these before you need them: meeting briefs, night-shift notes,
            the week in review. Every sentence that matters cites the claim under it.
          </span>
        </div>

        <div className="bgroups">
          {GROUPS.map((g) => {
            const rows = BRIEFS.filter((b) => b.group === g)
            if (rows.length === 0) return null
            return (
              <div className="bgroup" key={g} role="group" aria-label={g}>
                <span className="label">{g}</span>
                {rows.map((b) => {
                  const unread = isUnread(b)
                  const on = b.id === sel
                  return (
                    <button
                      key={b.id}
                      className={`bitem${unread ? ' unread' : ''}${on ? ' sel' : ''}`}
                      aria-current={on ? 'true' : undefined}
                      title={`${b.when} · ${unread ? 'unread' : 'read'}`}
                      onClick={pick(b.id)}
                    >
                      <span className="bmark" aria-hidden="true"></span>
                      <span className="btitle">{b.title}</span>
                      <span className="bsub">
                        <span>{b.forWhom}</span>
                        <span className="sep">·</span>
                        <Aname who={b.by} />
                      </span>
                    </button>
                  )
                })}
              </div>
            )
          })}
        </div>
      </aside>

      {/* the document */}
      <div className="pane-body" ref={bodyRef}>
        {doc}
      </div>
    </main>
  )
}
