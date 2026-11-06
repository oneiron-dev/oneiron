import * as React from 'react'
import { Link, createFileRoute } from '@tanstack/react-router'
import { Chevron } from '~/components/safelight/icons'
import { cue, markCued, openChat, useEscape } from '~/components/safelight/hooks'
import todayCss from '~/styles/today.css?url'

export const Route = createFileRoute('/app/today')({
  head: () => ({
    links: [{ rel: 'stylesheet', href: todayCss }],
  }),
  component: Today,
})

/* ── fixtures · the day (Fable breadboard 08-15 eve; shared cast per
   FLOWS §2 — Hokuei, Mika Tanaka the COO, Eiri, Tory, Antevon) ── */
const DATE_LINE = 'Friday, August 15'

/* the fixture clock: the page reads at 11:24; ?at=HH:MM previews any
   hour (the now marker moves, past rows cool, an empty region says so) */
const FIXTURE_NOW = '11:24'

type Live = { agent: 'eiri' | 'tory'; name: string; doing: string; tip: string }
const LIVE: Live[] = [
  { agent: 'eiri', name: 'Eiri', doing: 'drafting the COO intro', tip: 'Eiri · outbound · 2m 14s · open the run in the agent line' },
  { agent: 'tory', name: 'Tory', doing: 'checking filings', tip: 'Tory · research · 6m 02s · open the run in the agent line' },
]
const WAITING = 2

type Door = '/app/inbox' | '/app/briefs' | '/app/pipeline' | '/app/notes'
type Slot = { time: string; what: string; who: string; door: string; to: Door; tip: string }
const NEXT: Slot[] = [
  { time: '10:00', what: 'Hokuei pilot call', who: 'Mika Tanaka, the COO', door: 'brief', to: '/app/briefs', tip: 'the meeting brief · every sentence cites the vault' },
  { time: '13:00', what: 'Kanto Logistics', who: 'call', door: 'prep', to: '/app/briefs', tip: 'the call prep · Kanto Logistics' },
  { time: '15:30', what: 'Send the pilot scope', who: 'next step due', door: 'open in pipeline', to: '/app/pipeline', tip: 'Hokuei · pilot · next step due today' },
  { time: '17:00', what: 'Review the digest', who: '', door: 'open', to: '/app/notes', tip: "today's digest · notes" },
]

type Receipt = { time: string; what: string; to: Door; tip: string }
const RECEIPTS: Receipt[] = [
  { time: '03:12', what: 'Nightly consolidation', to: '/app/inbox', tip: 'run rx_7b12 · 42 writes · 2 wait · the receipts' },
  { time: '03:40', what: 'LinkedIn import stopped by the burst guard', to: '/app/inbox', tip: 'run rx_9a04 · paused · the bundle waits in the inbox' },
]

type Day = { day: string; what: string; door?: string; to?: Door; tip?: string }
const WEEK: Day[] = [
  { day: 'sat', what: 'Nothing booked' },
  { day: 'mon', what: 'Sakura proposal due', door: 'open in pipeline', to: '/app/pipeline', tip: 'Sakura · proposal · due Monday' },
  { day: 'tue', what: 'Nishi deposit call', door: 'prep', to: '/app/briefs', tip: 'the call prep · Nishi' },
]

/* HH:MM → minutes; a bad ?at falls back to the fixture clock */
function minutes(hm: string): number {
  const m = /^(\d{1,2}):(\d{2})$/.exec(hm)
  if (!m) return minutes(FIXTURE_NOW)
  const h = Number(m[1])
  const mm = Number(m[2])
  if (h > 23 || mm > 59) return minutes(FIXTURE_NOW)
  return h * 60 + mm
}

/* ── a section: the head is a quiet toggle (hover chevron); the count
   shows only when the rows are hidden ── */
function Bundle({
  label,
  title,
  meta,
  defaultClosed = false,
  children,
}: {
  label: string
  title: string
  meta?: React.ReactNode
  defaultClosed?: boolean
  children: React.ReactNode
}) {
  const [closed, setClosed] = React.useState(defaultClosed)
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
        <span className="title">{title}</span>
        <span className="fold-hint" aria-hidden="true">
          <Chevron />
        </span>
        {meta}
      </div>
      <div className="body">{children}</div>
    </section>
  )
}

function Today() {
  const [hintOpen, setHintOpen] = React.useState(false)
  const [now, setNow] = React.useState(FIXTURE_NOW)

  /* ?at=HH:MM previews another hour of the same day */
  React.useEffect(() => {
    const at = new URLSearchParams(location.search).get('at')
    if (at && /^\d{1,2}:\d{2}$/.test(at)) setNow(at)
  }, [])
  useEscape(() => setHintOpen(false))

  const nowMin = minutes(now)
  const past = NEXT.filter((s) => minutes(s.time) <= nowMin)
  const ahead = NEXT.filter((s) => minutes(s.time) > nowMin)

  /* the run door: the agent line owns the run; this is its title only
     until Ground exposes an open-run hook */
  const openRun = (e: React.MouseEvent, agent: 'eiri' | 'tory') => {
    e.preventDefault()
    markCued(e)
    openChat(agent)
  }

  const row = (s: Slot, cool: boolean) => (
    <Link key={s.time + s.what} className={cool ? 'trow past' : 'trow'} to={s.to} title={s.tip}>
      <span className="t-time">{s.time}</span>
      <span className="t-what">{s.what}</span>
      <span className="t-who">{s.who}</span>
      <span className="act">{s.door}</span>
    </Link>
  )

  return (
    <main className="pane today" id="pane">
      <div className="pane-body">
        <div className="pane-head">
          <h1>Today</h1>
          <span className="today-date">{DATE_LINE}</span>
          <span className="pane-tools">
            <button
              className="hint-btn"
              aria-expanded={hintOpen}
              aria-controls="today-why"
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
        <div className="dial-why" id="today-why" hidden={!hintOpen}>
          <span className="why-voice">
            The day on one page. What runs now, what comes next, what the night did.
          </span>
        </div>

        {/* NOW · what is live, name-fronted; the agent line carries the motion */}
        <Bundle
          label="Now"
          title="Now"
          meta={
            <span className="meta-line" title="two runs live · in the agent line">
              {LIVE.length} live
            </span>
          }
        >
          {LIVE.map((l) => (
            <a key={l.agent} className="trow nrow" href="#" title={l.tip} onClick={(e) => openRun(e, l.agent as 'eiri' | 'tory')}>
              <span className="aname" data-agent={l.agent}>
                {l.name}
              </span>
              <span className="t-what">{l.doing}</span>
              <span className="act">open the run</span>
            </a>
          ))}
          {WAITING > 0 && (
            <div className="quiet">
              <span>{WAITING} wait for you.</span>
              <Link className="act" to="/app/inbox" title="the inbox · what waits for your click">
                inbox
              </Link>
            </div>
          )}
        </Bundle>

        {/* NEXT · the time ledger; the now marker sits between past and ahead */}
        <Bundle
          label="Next"
          title="Next"
          meta={
            <span className="meta-line" title="booked today, still ahead">
              {ahead.length} ahead
            </span>
          }
        >
          {past.map((s) => row(s, true))}
          <div className="now-mark" role="separator" aria-label={`now, ${now}`}>
            <span className="t-time">{now}</span>
            <span className="label">now</span>
          </div>
          {ahead.map((s) => row(s, false))}
          {ahead.length === 0 && (
            <div className="quiet empty">
              <span>Nothing else booked.</span>
            </div>
          )}
        </Bundle>

        {/* OVERNIGHT · the house mind speaks for the vault's own night work */}
        <Bundle
          label="Overnight"
          title="Overnight"
          meta={
            <span className="meta-line" title="42 writes · 2 wait · 1 import paused">
              2 wait
            </span>
          }
        >
          <div className="sec-voice">
            <span
              className="aname"
              data-agent="antevon"
              title="Antevon · the house mind · the overnight run · 03:12"
            >
              Antevon
            </span>
            <span>
              42 claims went in on their own.
              <Link className="act" to="/app/inbox" title="run rx_7b12 · every write receipted">
                the receipts
              </Link>
            </span>
          </div>
          {RECEIPTS.map((r) => (
            <Link key={r.time} className="trow rrow" to={r.to} title={r.tip}>
              <span className="t-time">{r.time}</span>
              <span className="t-what">{r.what}</span>
            </Link>
          ))}
        </Bundle>

        {/* THE WEEK · folded by default; three lines for the next days */}
        <Bundle
          label="The week"
          title="The week"
          defaultClosed
          meta={
            <span className="meta-line" title="Saturday to Tuesday">
              {WEEK.filter((d) => d.door).length} booked
            </span>
          }
        >
          {WEEK.map((d) =>
            d.to ? (
              <Link key={d.day} className="trow wrow" to={d.to} title={d.tip}>
                <span className="t-time">{d.day}</span>
                <span className="t-what">{d.what}</span>
                <span className="t-who"></span>
                <span className="act">{d.door}</span>
              </Link>
            ) : (
              <div key={d.day} className="trow wrow none">
                <span className="t-time">{d.day}</span>
                <span className="t-what">{d.what}</span>
              </div>
            ),
          )}
        </Bundle>
      </div>
    </main>
  )
}
