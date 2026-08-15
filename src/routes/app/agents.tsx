import * as React from 'react'
import { Link, createFileRoute } from '@tanstack/react-router'
import { Chevron } from '~/components/safelight/icons'
import { cue, markCued, openChat, useEscape } from '~/components/safelight/hooks'
import agentsCss from '~/styles/agents.css?url'

export const Route = createFileRoute('/app/agents')({
  head: () => ({
    links: [{ rel: 'stylesheet', href: agentsCss }],
  }),
  component: Agents,
})

/* ══ Agents · the roster and its mission control (FLOWS §3 #4) ══
   who works here (roster ledger, rows unfold in place) · what runs now
   (live rows; stop settles in place, rule 34) · what already ran (run
   ledger with agent bylines and wake receipts) · what waits for you
   lives in the inbox, one home per item. Nothing rests red on this page:
   the name in the agent's ink is the presence (rule 36). */

type AgentKey = 'eiri' | 'tory' | 'antevon'
type RunKey = 'eiri' | 'tory'

type Door = { label: string; tip: string; to?: '/app/inbox' | '/app/vault'; href?: string }
type Tail = { when: string; what: string; door: Door }

type Agent = {
  key: AgentKey
  name: string
  tip: string
  creature: { w: number; h: number; alt: string }
  charter: string
  detail: string
  scope: string
  scopeTip: string
  model: string
  modelTip: string
  budget: string
  budgetTip: string
  last: string
  lastTip: string
  verbs: Array<{ v: string; tip: string }>
  tail: Tail[]
}

/* creatures are the ratified set (public/art/creatures), drawn at native
   pixel size; here they render at 2× width, pixel-true */
const AGENTS: Agent[] = [
  {
    key: 'eiri',
    name: 'Eiri',
    tip: 'Eiri · outbound · bound to you',
    creature: { w: 30, h: 24, alt: 'Eiri, the pigeon' },
    charter: 'Reaches out and keeps the thread warm.',
    detail:
      'Eiri writes outward in your register: intros, follow-ups, the note after a call. She may draft anything and promise nothing. Every send waits for your click. The sent copy comes back into the vault as a record.',
    scope: 'draft · send-with-consent',
    scopeTip:
      'read: clients, base · propose: claims from what she sends and hears · draft: anywhere · send: LINE and email, one human click per send · the grant lives in settings',
    model: 'kimi-k2.6',
    modelTip: 'kimi-k2.6 · pinned 08-02 · the model card and what it costs',
    budget: '¥170 of ¥600',
    budgetTip: '¥170 spent today of a ¥600 day cap · the cap pauses the agent, it never bills past it',
    last: '14:09',
    lastTip: 'the last run settled at 14:09',
    verbs: [
      { v: 'read', tip: 'clients, base · standing · never the internal world' },
      { v: 'propose', tip: 'claims from what she sends and hears · they wait for you' },
      { v: 'draft', tip: 'any world she can read · drafts land in the inbox' },
      { v: 'send', tip: 'LINE, email · one click per send · 20 a month · expires 2026-10-07' },
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
    scope: 'read-filings · propose',
    scopeTip: 'read: clients, base and the open web · propose: claims only · she has never had a write',
    model: 'kimi-k2.6',
    modelTip: 'kimi-k2.6 · pinned 08-02 · the model card and what it costs',
    budget: '¥110 of ¥450',
    budgetTip: '¥110 spent today of a ¥450 day cap · research is the cheap half of the roster',
    last: '14:09',
    lastTip: 'the last run settled at 14:09',
    verbs: [
      { v: 'read', tip: 'clients, base, the open web · standing' },
      { v: 'propose', tip: 'claims only · every one carries its source and its floor' },
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
    scope: 'read · consolidate · answer',
    scopeTip: 'read: every world, including internal · consolidate: the nightly pass · answer: Slack, email · cites the vault',
    model: 'qwen3-4b',
    modelTip: 'qwen3-4b · runs on this machine · nothing leaves it',
    budget: '¥0 · local',
    budgetTip: 'local inference · no credits, no metered tokens · electricity is the whole bill',
    last: '03:12',
    lastTip: 'run rx_7b12 · finished 03:12 · 42 writes · every write receipted',
    verbs: [
      { v: 'read', tip: 'every world, including internal · standing' },
      { v: 'consolidate', tip: 'the nightly pass · claims in, receipts out · two waited for you last night' },
      { v: 'answer', tip: 'Slack, email · answers cite the vault' },
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
    doing: 'Drafting the COO intro, in Yurii’s register',
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
const SETTLE_AT = '14:09'

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

function Agents() {
  const [hintOpen, setHintOpen] = React.useState(false)
  /* the roster: one row open at a time; esc closes it */
  const [open, setOpen] = React.useState<AgentKey | null>(null)
  /* pause parks the agent (nothing new starts; the live run finishes) */
  const [paused, setPaused] = React.useState<Partial<Record<AgentKey, string>>>({})
  /* stop = the cancel signal (rule 34): the run settles midway, in place */
  const [stopped, setStopped] = React.useState<Partial<Record<RunKey, boolean>>>({})

  useEscape(() => {
    setOpen(null)
    setHintOpen(false)
  })

  const toggleRow = (key: AgentKey) => {
    setOpen((cur) => (cur === key ? null : key))
    cue('toggle')
  }
  const onLineClick = (key: AgentKey) => (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest('a, button')) return
    toggleRow(key)
  }
  const onRowKey = (key: AgentKey) => (e: React.KeyboardEvent) => {
    const target = e.target as HTMLElement
    if ((e.key === 'Enter' || e.key === ' ') && !target.closest('a, button')) {
      e.preventDefault()
      toggleRow(key)
    }
  }

  const pause = (key: AgentKey) => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setPaused((p) => ({ ...p, [key]: SETTLE_AT }))
    cue('press')
  }
  const resume = (key: AgentKey) => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setPaused((p) => {
      const next = { ...p }
      delete next[key]
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

  /* what the roster derives from the live runs: a live run makes the row
     live (well + since); a stopped run settles it (idle, last = now) */
  const runOf = (key: AgentKey) => RUNS.find((r) => r.agent === key)
  const isLive = (key: AgentKey) => {
    const r = runOf(key)
    return !!r && !stopped[r.agent]
  }
  const stateOf = (key: AgentKey) => (paused[key] ? 'paused' : isLive(key) ? 'live' : 'idle')
  const stateTip = (key: AgentKey) => {
    if (paused[key]) return `paused ${paused[key]} · the live run finishes, nothing new starts`
    if (isLive(key)) return 'live · the run is in the now region below'
    if (key === 'antevon') return 'idle since 03:12 · it wakes with the vault, every night'
    return `idle since ${SETTLE_AT}`
  }
  const lastOf = (key: AgentKey, agent: Agent) => {
    const r = runOf(key)
    if (r && !stopped[r.agent]) return { text: `since ${r.since}`, tip: `started ${r.since} · still running` }
    return { text: agent.last, tip: agent.lastTip }
  }

  const liveCount = RUNS.filter((r) => !stopped[r.agent]).length
  const writes = HISTORY.reduce((n, h) => n + h.writes, 0)
  const waited = HISTORY.reduce((n, h) => n + h.waited, 0)

  return (
    <main className="pane" id="pane">
      <div className="pane-body">
        <div className="pane-head">
          <h1>Agents</h1>
          <span className="pane-tools">
            <span className="meta-line" title="what the roster spent today · as of 14:07">
              ¥280 today · as of 14:07
            </span>
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
            Who works in this vault, what each may do, and what runs now. Every run ends in a
            receipt. What waits for you lives in the inbox.
          </span>
        </div>

        {/* ══ THE ROSTER · one row per agent; the row unfolds in place ══ */}
        <section className="roster" aria-label="roster">
          <div className="rhead" aria-hidden="true">
            <span className="label h-agent">agent</span>
            <span className="label">charter</span>
            <span className="label">scope</span>
            <span className="label">model</span>
            <span className="label">budget</span>
            <span className="label">last run</span>
            <span className="label">state</span>
          </div>
          {AGENTS.map((a) => {
            const isOpen = open === a.key
            const live = isLive(a.key)
            const last = lastOf(a.key, a)
            const run = runOf(a.key)
            const detailId = `agent-${a.key}`
            return (
              <div key={a.key} className={isOpen ? 'ragent open' : 'ragent'} data-agent={a.key}>
                <div
                  className="rline"
                  role="button"
                  tabIndex={0}
                  aria-expanded={isOpen}
                  aria-controls={detailId}
                  data-work={live ? (run?.doing ?? '') : undefined}
                  title={isOpen ? `close ${a.name}` : `open ${a.name} · charter, granted verbs, receipts`}
                  onClick={onLineClick(a.key)}
                  onKeyDown={onRowKey(a.key)}
                >
                  <span className="rcreature">
                    <img
                      src={`/art/creatures/${a.key}.png`}
                      width={a.creature.w * 2}
                      height={a.creature.h * 2}
                      alt={a.creature.alt}
                    />
                  </span>
                  <span className="aname" title={a.tip}>
                    {a.name}
                  </span>
                  <span className="rcharter">
                    {a.charter}
                  </span>
                  <a className="rcell rdoor" href="/app/settings" title={a.scopeTip}>
                    {a.scope}
                  </a>
                  <a className="rcell rdoor" href="#" title={a.modelTip}>
                    {a.model}
                  </a>
                  <a className="rcell rdoor" href="/app/billing" title={a.budgetTip}>
                    {a.budget}
                  </a>
                  <span className="rcell" title={last.tip}>
                    {last.text}
                  </span>
                  <span className="rstate" title={stateTip(a.key)}>
                    {stateOf(a.key)}
                  </span>
                </div>
                <div className="rdetail" id={detailId}>
                  <div className="rd-inner">
                    <div className="rd-body">
                      <div className="rd-main">
                        <p className="rd-charter">{a.detail}</p>
                        <div className="rd-verbs" aria-label="granted verbs">
                          <span className="label">may</span>
                          {a.verbs.map((v) => (
                            <span key={v.v} className="vchip" title={v.tip}>
                              {v.v}
                            </span>
                          ))}
                        </div>
                      </div>
                      <div className="rd-tail" aria-label="receipts">
                        {a.tail.map((t) => (
                          <div key={t.when + t.what} className="tl">
                            <span className="when">{t.when}</span>
                            <span className="what">{t.what}</span>
                            <DoorAct door={t.door} />
                          </div>
                        ))}
                      </div>
                    </div>
                    <div className="rd-acts">
                      {a.key === 'antevon' ? (
                        <>
                          <span
                            className="always"
                            title="the house mind is the vault’s own · it wakes with the vault, it does not pause"
                          >
                            always on
                          </span>
                          <a
                            className="act"
                            href="#"
                            title="run rx_7b12 · 02:40 to 03:12 · every write receipted"
                          >
                            the last run
                          </a>
                        </>
                      ) : (
                        <>
                          {paused[a.key] ? (
                            <>
                              <span className="meta-line" title="nothing new starts · the live run finishes">
                                paused {paused[a.key]}
                              </span>
                              <button className="act" title="verb: resume_agent" onClick={resume(a.key)}>
                                resume
                              </button>
                            </>
                          ) : (
                            <button
                              className="act"
                              title="verb: pause_agent · the live run finishes, nothing new starts"
                              onClick={pause(a.key)}
                            >
                              pause
                            </button>
                          )}
                          <a
                            className="act"
                            href="#"
                            title={
                              live
                                ? 'opens the run in the agent line'
                                : 'opens the run in the agent line · stopped, the thread stays live'
                            }
                          >
                            open the run
                          </a>
                        </>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )
          })}
        </section>

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
                      <span className="aname" title={r.tip}>
                        {NAMES[r.agent]}
                      </span>
                      <span className="ndoing" title={still ? 'stopped · what landed stays' : r.doing}>
                        {r.doing}
                      </span>
                    </span>
                    <span className="ncell" title="world: hokuei · the pilot client">
                      {r.world}
                    </span>
                    <span className="ncell n-num" title={still ? `ran ${r.elapsed}, then stopped` : `running ${r.elapsed}`}>
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
                              openChat(r.agent as 'eiri' | 'tory')
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
                  {still ? (
                    <p className="nreceipt">What landed stays. The thread stays open.</p>
                  ) : null}
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
                  <th>run</th>
                  <th className="c-by">by</th>
                  <th className="c-num num">writes</th>
                  <th className="c-num num">waited</th>
                  <th className="c-rcpt">receipt</th>
                  <th className="c-wake">wake</th>
                </tr>
              </thead>
              <tbody>
                {HISTORY.map((h) => (
                  <tr key={h.id}>
                    <td>
                      <span className="ran" title={h.tip}>
                        {h.ran}
                      </span>
                    </td>
                    <td>
                      <a
                        className="aname"
                        data-agent={h.by}
                        href="#"
                        title={`${NAMES[h.by]} · a door: its runs and receipts`}
                      >
                        {NAMES[h.by]}
                      </a>
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
      </div>
    </main>
  )
}
