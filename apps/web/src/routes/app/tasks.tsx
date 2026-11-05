import * as React from 'react'
import { Link, createFileRoute } from '@tanstack/react-router'
import { Chevron } from '~/components/safelight/icons'
import { cue, markCued, useEscape } from '~/components/safelight/hooks'
import tasksCss from '~/styles/tasks.css?url'

export const Route = createFileRoute('/app/tasks')({
  head: () => ({
    links: [{ rel: 'stylesheet', href: tasksCss }],
  }),
  component: Tasks,
})

/* ── the list on paper: your tasks, plus what the agents propose or do.
   the bullet is the check (filled = yours · hollow = an agent proposed
   it · the check = done); the agents show only through names and hollow
   bullets. no toast ever — a row settles in place, then slides to done. ── */

type Who = 'o' | 'y' | 'eiri' | 'tory' | 'antevon'
type Group = 'today' | 'week' | 'later'
type State = 'mine' | 'proposed' | 'done' | 'skipped'
type Phase = 'rest' | 'settling' | 'leaving' | 'arriving'

type Door = { label: string; to: string; tip?: string }

type Task = {
  id: string
  title: string
  org?: string
  who: Who
  group: Group
  state: State
  due: string /* the mono word · the time is hover-tier */
  dueTip: string
  doneAt?: string /* takes the due slot once done */
  doneTs: number /* orders the done group, newest first */
  why: React.ReactNode
  doors: Door[]
}

const HUMANS: Record<'o' | 'y', string> = { o: 'oleksii', y: 'yurii' }
const AGENTS: Record<'eiri' | 'tory' | 'antevon', { name: string; tip: string }> = {
  eiri: { name: 'Eiri', tip: 'Eiri · outbound · every send waits for your click' },
  tory: { name: 'Tory', tip: 'Tory · research' },
  antevon: { name: 'Antevon', tip: 'Antevon · the house mind' },
}

function Name({ who }: { who: 'eiri' | 'tory' | 'antevon' }) {
  return (
    <span className="aname" data-agent={who} title={AGENTS[who].tip}>
      {AGENTS[who].name}
    </span>
  )
}

const FIXTURES: Task[] = [
  /* today */
  {
    id: 't1',
    title: 'Send the pilot scope to Hokuei',
    org: 'Hokuei',
    who: 'o',
    group: 'today',
    state: 'mine',
    due: 'today',
    dueTip: 'due today · 18:00',
    doneTs: 0,
    why: 'From the pipeline. Hokuei sits at the pilot stage; the scope is the next step.',
    doors: [
      { label: 'the pipeline', to: '/app/pipeline', tip: 'Hokuei · pilot stage' },
      { label: 'open the org', to: '/app/orgs', tip: 'Hokuei · the org dossier' },
    ],
  },
  {
    id: 't2',
    title: 'Reply to Mika about the Tuesday quote',
    org: 'Hokuei',
    who: 'eiri',
    group: 'today',
    state: 'mine',
    due: 'today',
    dueTip: 'due today · Mika asked for the quote by Tuesday',
    doneTs: 0,
    why: (
      <>
        <Name who="eiri" /> is drafting the reply. It waits in the inbox for your click.
      </>
    ),
    doors: [
      { label: 'the draft', to: '/app/inbox', tip: 'the draft waits in the inbox' },
      { label: 'the thread', to: '/app/threads', tip: 'LINE · Mika Tanaka · the whole thread' },
      { label: 'open the org', to: '/app/orgs', tip: 'Hokuei · the org dossier' },
    ],
  },
  {
    id: 't3',
    title: 'Book the Kanto call',
    org: 'Kanto Logistics',
    who: 'o',
    group: 'today',
    state: 'proposed',
    due: 'today',
    dueTip: 'proposed for today · Tory, Aug 14',
    doneTs: 0,
    why: (
      <>
        <Name who="tory" /> proposed this from the Hokuei thread, Aug 14. Kanto came up as a
        second supplier lead.
      </>
    ),
    doors: [
      { label: 'the thread', to: '/app/threads', tip: 'the Hokuei thread · Aug 14' },
      { label: 'open the org', to: '/app/orgs', tip: 'Kanto Logistics · the org dossier' },
    ],
  },
  /* this week */
  {
    id: 't4',
    title: 'Review the supplier consolidation digest',
    org: 'Hokuei',
    who: 'o',
    group: 'week',
    state: 'mine',
    due: 'wed',
    dueTip: 'due Wednesday, Aug 19',
    doneTs: 0,
    why: (
      <>
        <Name who="tory" /> compiled the digest from public filings and the Hokuei thread. It
        reads in the supplier watch lens.
      </>
    ),
    doors: [
      { label: 'the lens', to: '/app/lens/supplier-watch', tip: 'supplier watch · the digest' },
      { label: 'open the org', to: '/app/orgs', tip: 'Hokuei · the org dossier' },
    ],
  },
  {
    id: 't5',
    title: 'Sign the Documenso NDA',
    org: 'Hokuei',
    who: 'o',
    group: 'week',
    state: 'mine',
    due: 'thu',
    dueTip: 'due Thursday, Aug 20 · before the call',
    doneTs: 0,
    why: 'The NDA came in by email on Aug 13. Hokuei wants it signed before the call.',
    doors: [
      { label: 'the thread', to: '/app/threads', tip: 'email · Hokuei legal · Aug 13' },
      { label: 'open the org', to: '/app/orgs', tip: 'Hokuei · the org dossier' },
    ],
  },
  {
    id: 't6',
    title: 'Prep the Thursday call',
    org: 'Hokuei',
    who: 'o',
    group: 'week',
    state: 'mine',
    due: 'thu',
    dueTip: 'due Thursday, Aug 20 · the call is at 10:00',
    doneTs: 0,
    why: (
      <>
        <Name who="antevon" /> compiled a brief for the call. It cites every claim under it.
      </>
    ),
    doors: [
      { label: 'the brief', to: '/app/briefs', tip: 'meeting brief · Hokuei pilot call, Thursday 10:00' },
      { label: 'open the org', to: '/app/orgs', tip: 'Hokuei · the org dossier' },
    ],
  },
  {
    id: 't7',
    title: 'Send the intro deck to the Hokuei COO',
    org: 'Hokuei',
    who: 'y',
    group: 'week',
    state: 'mine',
    due: 'fri',
    dueTip: 'due Friday, Aug 21',
    doneTs: 0,
    why: 'Yurii owns the COO thread on LinkedIn. The deck follows his DM from today.',
    doors: [
      { label: 'the thread', to: '/app/threads', tip: 'linkedin · Hokuei COO · the whole thread' },
      { label: 'open the org', to: '/app/orgs', tip: 'Hokuei · the org dossier' },
    ],
  },
  /* later */
  {
    id: 't8',
    title: 'Draft the Q3 pricing sheet',
    who: 'o',
    group: 'later',
    state: 'mine',
    due: 'aug 28',
    dueTip: 'due Friday, Aug 28',
    doneTs: 0,
    why: 'Two pilots close in September. The sheet sets the price before the next call.',
    doors: [{ label: 'the pipeline', to: '/app/pipeline', tip: 'the funnel · September closes' }],
  },
  {
    id: 't9',
    title: 'Renew the LINE plan',
    who: 'o',
    group: 'later',
    state: 'mine',
    due: 'sep 1',
    dueTip: 'due Tuesday, Sep 1 · the plan expires that day',
    doneTs: 0,
    why: (
      <>
        The plan expires Sep 1. <Name who="eiri" /> sends to Mika through it.
      </>
    ),
    doors: [{ label: 'settings', to: '/settings/connectors', tip: 'channels · LINE' }],
  },
  {
    id: 't10',
    title: 'Follow up with Kanto procurement',
    org: 'Kanto Logistics',
    who: 'y',
    group: 'later',
    state: 'mine',
    due: 'aug 25',
    dueTip: 'due Tuesday, Aug 25',
    doneTs: 0,
    why: 'Yurii met their procurement lead in July. A quiet check-in keeps the door open.',
    doors: [{ label: 'open the org', to: '/app/orgs', tip: 'Kanto Logistics · the org dossier' }],
  },
  /* done */
  {
    id: 'd1',
    title: 'Answer the #ops timeline question',
    org: 'Hokuei',
    who: 'antevon',
    group: 'today',
    state: 'done',
    due: 'today',
    dueTip: 'was due today',
    doneAt: '14:05',
    doneTs: 3,
    why: (
      <>
        <Name who="antevon" /> answered in Slack at 14:05 and cited the scope note.
      </>
    ),
    doors: [
      { label: 'the thread', to: '/app/threads', tip: 'slack · #ops · the whole thread' },
      { label: 'the receipt', to: '/app/inbox', tip: 'the send receipt' },
    ],
  },
  {
    id: 'd2',
    title: 'DM the Hokuei COO',
    org: 'Hokuei',
    who: 'y',
    group: 'today',
    state: 'done',
    due: 'today',
    dueTip: 'was due today',
    doneAt: '14:02',
    doneTs: 2,
    why: "Sent from Yurii's account under the outreach grant. Verified in the thread.",
    doors: [{ label: 'the thread', to: '/app/threads', tip: 'linkedin · Hokuei COO' }],
  },
  {
    id: 'd3',
    title: 'Confirm the Thursday slot with Mika',
    org: 'Hokuei',
    who: 'o',
    group: 'today',
    state: 'done',
    due: 'aug 14',
    dueTip: 'was due Aug 14',
    doneAt: 'aug 14',
    doneTs: 1,
    why: 'Confirmed for Thursday 10:00. The brief for the call is already prepared.',
    doors: [
      { label: 'the thread', to: '/app/threads', tip: 'LINE · Mika Tanaka' },
      { label: 'the brief', to: '/app/briefs', tip: 'meeting brief · Hokuei pilot call' },
    ],
  },
  {
    id: 'd4',
    title: 'Approve the LinkedIn grant for Yurii',
    org: 'Hokuei',
    who: 'o',
    group: 'today',
    state: 'done',
    due: 'aug 14',
    dueTip: 'was due Aug 14',
    doneAt: 'aug 14',
    doneTs: 0,
    why: 'A scoped, budgeted grant so Yurii can reach the Hokuei COO. It expires in 30 days.',
    doors: [{ label: 'the grant', to: '/settings/grants', tip: 'linkedin grant · scope, budget, expiry' }],
  },
]

const GROUPS: { key: Group; title: string; tip: string }[] = [
  { key: 'today', title: 'today', tip: 'due today' },
  { key: 'week', title: 'this week', tip: 'due by Sunday' },
  { key: 'later', title: 'later', tip: 'due after this week' },
]

const isOpen = (t: Task) => t.state === 'mine' || t.state === 'proposed'

function nowWord() {
  const d = new Date()
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
}

/* a door is a bare act to another place; typed Links where the route
   exists, plain anchors where it is being built beside this one */
function DoorLink({ door }: { door: Door }) {
  if (door.to === '/app/inbox') {
    return (
      <Link className="act" to="/app/inbox" title={door.tip}>
        {door.label}
      </Link>
    )
  }
  if (door.to === '/app/vault') {
    return (
      <Link className="act" to="/app/vault" title={door.tip}>
        {door.label}
      </Link>
    )
  }
  return (
    <a className="act" href={door.to} title={door.tip}>
      {door.label}
    </a>
  )
}

/* the bullet: text-free, the state reads on hover */
function Bullet({ state, who }: { state: State; who: Who }) {
  if (state === 'done') {
    return (
      <span className="tbul done" title="done" aria-label="done" role="img">
        <svg viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M2 6.5 4.8 9.2 10 3.4" />
        </svg>
      </span>
    )
  }
  if (state === 'skipped') return <span className="tbul skipped" title="skipped · a proposal you did not take" role="img" aria-label="skipped" />
  if (state === 'proposed') return <span className="tbul proposed" title="proposed by an agent · accept makes it yours" role="img" aria-label="proposed" />
  const owner = who === 'o' || who === 'y' ? HUMANS[who] : `${AGENTS[who].name} does it`
  return <span className="tbul mine" title={`committed · ${owner}`} role="img" aria-label="committed" />
}

/* who: seals for humans (rule 15), the name in ink for an agent */
function WhoMark({ who }: { who: Who }) {
  if (who === 'o' || who === 'y') {
    return (
      <span className="seal seal-human" title={`${who} · ${HUMANS[who]}`}>
        {who}
      </span>
    )
  }
  return <Name who={who} />
}

/* headings collapse in place (rule 10); the count renders ONLY when
   the rows are hidden (rule 16) */
function Bundle({
  title,
  tip,
  count,
  countTip,
  defaultClosed = false,
  children,
}: {
  title: string
  tip: string
  count: number
  countTip: string
  defaultClosed?: boolean
  children: React.ReactNode
}) {
  const [closed, setClosed] = React.useState(defaultClosed)
  const toggle = () => {
    setClosed((c) => !c)
    cue('toggle')
  }
  return (
    <section className={closed ? 'bundle closed' : 'bundle'} aria-label={title}>
      <div
        className="head"
        tabIndex={0}
        role="button"
        aria-expanded={!closed}
        onClick={toggle}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault()
            toggle()
          }
        }}
      >
        <span className="title" title={tip}>
          {title}
        </span>
        <span className="fold-hint" aria-hidden="true">
          <Chevron ariaHidden={false} />
        </span>
        <span className="meta-line" title={countTip}>
          {count}
        </span>
      </div>
      {children}
    </section>
  )
}

function Tasks() {
  const [tasks, setTasks] = React.useState<Task[]>(FIXTURES)
  const [phases, setPhases] = React.useState<Record<string, Phase>>({})
  const [openIds, setOpenIds] = React.useState<Set<string>>(() => new Set())
  const [everyone, setEveryone] = React.useState(false)
  const [hintOpen, setHintOpen] = React.useState(false)
  const timers = React.useRef<ReturnType<typeof setTimeout>[]>([])

  /* ?empty previews the empty list; the real one comes when you finish everything */
  React.useEffect(() => {
    if (new URLSearchParams(location.search).has('empty')) {
      setTasks((ts) => ts.filter((t) => !isOpen(t)))
    }
  }, [])
  React.useEffect(
    () => () => {
      timers.current.forEach(clearTimeout)
    },
    [],
  )
  const later = (ms: number, fn: () => void) => {
    timers.current.push(setTimeout(fn, ms))
  }
  const setPhase = (id: string, phase: Phase) =>
    setPhases((p) => ({ ...p, [id]: phase }))
  const phaseOf = (id: string): Phase => phases[id] ?? 'rest'

  useEscape(() => setOpenIds(new Set()))

  const toggleOpen = (id: string) => {
    setOpenIds((s) => {
      const n = new Set(s)
      if (n.has(id)) n.delete(id)
      else n.add(id)
      return n
    })
    cue('toggle')
  }
  const closeOne = (id: string) =>
    setOpenIds((s) => {
      if (!s.has(id)) return s
      const n = new Set(s)
      n.delete(id)
      return n
    })

  /* the row cools (600ms), folds out of its group (220ms), lands in done */
  const slideToDone = (id: string) => {
    setPhase(id, 'settling')
    closeOne(id)
    later(600, () => setPhase(id, 'leaving'))
    later(840, () => setPhase(id, 'arriving'))
    later(1100, () => setPhase(id, 'rest'))
  }

  const finish = (id: string) => (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    markCued(e)
    cue('success')
    const at = nowWord()
    setTasks((ts) =>
      ts.map((t) => (t.id === id ? { ...t, state: 'done', doneAt: at, doneTs: Date.now() } : t)),
    )
    slideToDone(id)
  }
  const skip = (id: string) => (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    markCued(e)
    cue('press')
    setTasks((ts) => ts.map((t) => (t.id === id ? { ...t, state: 'skipped', doneTs: Date.now() } : t)))
    slideToDone(id)
  }
  const accept = (id: string) => (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    markCued(e)
    cue('success')
    setTasks((ts) => ts.map((t) => (t.id === id ? { ...t, state: 'mine' } : t)))
    /* the bullet fills and the acts vanish; the row's own verb comes back once it has settled */
    setPhase(id, 'settling')
    later(900, () => setPhase(id, 'rest'))
  }

  /* the view flip: what you SEE, never a policy. mine = yours + what
     agents do for you; everyone adds the rest of the vault */
  const visible = tasks.filter((t) => everyone || t.who !== 'y')
  const inTransit = (t: Task) => phaseOf(t.id) === 'settling' || phaseOf(t.id) === 'leaving'
  const rowsFor = (g: Group) => visible.filter((t) => t.group === g && (isOpen(t) || inTransit(t)))
  const doneRows = visible
    .filter((t) => !isOpen(t) && !inTransit(t))
    .sort((a, b) => b.doneTs - a.doneTs)
  const openCount = visible.filter(isOpen).length
  const empty = openCount === 0

  /* a render function, not a component: the rows keep their DOM across
     renders so the unfold and the settle can transition */
  const renderRow = (t: Task) => {
    const phase = phaseOf(t.id)
    const open = openIds.has(t.id)
    const cool = t.state === 'done' || t.state === 'skipped'
    const rowClass = [
      'brow',
      open ? 'open' : '',
      t.state === 'proposed' ? 'proposed' : '',
      cool ? 'cool' : '',
      t.state === 'skipped' ? 'skipped' : '',
    ]
      .filter(Boolean)
      .join(' ')
    const slotClass = ['brow-slot', phase === 'leaving' ? 'leaving' : '', phase === 'arriving' ? 'arriving' : '']
      .filter(Boolean)
      .join(' ')
    const dueWord = t.state === 'skipped' ? 'skipped' : t.state === 'done' ? t.doneAt : t.due
    const dueTip =
      t.state === 'skipped'
        ? `skipped · was ${t.dueTip}`
        : t.state === 'done'
          ? `done ${t.doneAt} · ${t.dueTip}`
          : t.dueTip
    return (
      <div key={t.id} className={slotClass}>
        <div
          className={rowClass}
          tabIndex={0}
          aria-expanded={open}
          onKeyDown={(e) => {
            const target = e.target as HTMLElement
            if ((e.key === 'Enter' || e.key === ' ') && !target.closest('a, button')) {
              e.preventDefault()
              toggleOpen(t.id)
            }
          }}
        >
          <div
            className="brow-line"
            onClick={(e) => {
              if ((e.target as HTMLElement).closest('a, button')) return
              toggleOpen(t.id)
            }}
          >
            <Bullet state={t.state} who={t.who} />
            <span className="task">{t.title}</span>
            <span className="tfor" title={t.org ? `for ${t.org}` : undefined}>
              {t.org ?? ''}
            </span>
            <span className="twho">
              <WhoMark who={t.who} />
            </span>
            <span className="rverbs">
              {phase === 'rest' && t.state === 'proposed' && (
                <>
                  <button className="act" title="verb: accept_task · it becomes yours" onClick={accept(t.id)}>
                    accept
                  </button>
                  <button className="act" title="verb: skip_task · the proposal cools into done" onClick={skip(t.id)}>
                    skip
                  </button>
                </>
              )}
              {phase === 'rest' && t.state === 'mine' && (
                <button className="act" title="verb: complete_task" onClick={finish(t.id)}>
                  done
                </button>
              )}
            </span>
            <span className="tdue" title={dueTip}>
              {dueWord}
            </span>
          </div>
          <div className="brow-detail">
            <div className="bd-inner">
              <span className="bd-why">{t.why}</span>
              <span className="bd-acts">
                {t.doors.map((d) => (
                  <DoorLink key={d.to + d.label} door={d} />
                ))}
              </span>
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <main className="pane tasks-pane" id="pane">
      <div className="pane-body">
        <div className="pane-head">
          <h1>Tasks</h1>
          <span className="pane-tools">
            <button
              className="act"
              title="a view filter only · it changes nothing"
              onClick={() => {
                setEveryone((v) => !v)
                cue('toggle')
              }}
            >
              {everyone ? 'mine' : 'everyone'}
            </button>
            <button
              className="hint-btn"
              aria-expanded={hintOpen}
              aria-controls="tasks-why"
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
        <div className="dial-why" id="tasks-why" hidden={!hintOpen}>
          <span className="why-voice">
            Your list. A filled bullet is yours. A hollow one is an agent's proposal. Accept it
            or skip it. A name in ink means an agent is doing it. Click a row for the why.
          </span>
        </div>

        {empty && (
          <div className="tasks-empty">
            <img className="spot" src="/art/spot-flock.png" alt="" width={150} />
            <span className="lead">
              Nothing on your list.
              <span className="sub">Agents add a task here when a thread asks for one.</span>
            </span>
          </div>
        )}

        {GROUPS.map((g) => {
          const rows = rowsFor(g.key)
          if (rows.length === 0) return null
          return (
            <Bundle
              key={g.key}
              title={g.title}
              tip={g.tip}
              count={rows.filter(isOpen).length}
              countTip={`${rows.filter(isOpen).length} open`}
            >
              <div className="brows">
                {rows.map(renderRow)}
              </div>
            </Bundle>
          )
        })}

        <Bundle
          title="done"
          tip="finished, and the proposals you skipped"
          count={doneRows.length}
          countTip={`${doneRows.length} done`}
          defaultClosed
        >
          <div className="brows">
            {doneRows.map(renderRow)}
          </div>
        </Bundle>
      </div>
    </main>
  )
}
