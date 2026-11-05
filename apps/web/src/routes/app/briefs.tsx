import * as React from 'react'
import { Link, createFileRoute } from '@tanstack/react-router'
import { cue, markCued, useEscape } from '~/components/safelight/hooks'
import {
  Doc,
  HistoryAct,
  LABEL,
  LEAD,
  LI,
  Mark,
  NODE,
  P,
  ShareAct,
  TrailFold,
  WHO,
  c,
  hhmm,
  rowArrows,
  seal,
  type Block,
  type Change,
  type Trail,
  type Who,
} from './notes'
import briefsCss from '~/styles/briefs.css?url'

export const Route = createFileRoute('/app/briefs')({
  head: () => ({
    links: [{ rel: 'stylesheet', href: briefsCss }],
  }),
  component: Briefs,
})

/* ── the cast (FLOWS §2 · rule 15): companions Eiri (outbound) and Tory
   (research); the house mind is Antevon. the name in its ink is the
   mark — never a dot beside it. a brief is compiled by an agent, so
   every block is the agent's (ruling 4); your edits mark editedBy. ── */
type Agent = 'antevon' | 'tory' | 'eiri'
function Aname({ who, tip }: { who: Agent; tip?: string }) {
  return <Mark who={who} tip={tip} />
}

/* ── fixtures: five briefs, three age groups ── */
type BriefId = 'hokuei' | 'night' | 'week' | 'kanto' | 'rumor'
type Group = 'today' | 'this week' | 'earlier'
type Brief = {
  id: BriefId
  title: string
  forWhom: string
  by: Agent
  when: string /* hover-tier: rides the row's title */
  group: Group
  byline: string /* the one quiet meta-line after the name */
  built: string /* hover title on the byline: what it was built from */
  blocks: Block[]
  trail: Trail[]
}

const BRIEFS: Brief[] = [
  {
    id: 'hokuei',
    title: 'Meeting brief: Hokuei pilot call, Thursday 10:00',
    forWhom: 'Hokuei · pilot call',
    by: 'antevon',
    when: 'prepared today 06:40',
    group: 'today',
    byline: 'as of 06:40 · call Thu 10:00',
    built: 'Antevon · built 06:40 from the vault · 14 claims · 3 threads',
    blocks: seal('hokuei', 'antevon', 'today 06:40', [
      LABEL('what to know'),
      LI([
        c('Hokuei runs a two-week close on procurement decisions', 'cl_2c71', 0.93),
        '. Thursday is inside the window. Mika Tanaka needs the numbers by Tuesday.',
      ]),
      LI([
        c('Hokuei may be consolidating suppliers this fiscal year', 'cl_9d17', 0.81),
        '. Tory read it in the filings. It waits for your review in the inbox.',
      ]),
      LI([c('Client-facing numbers come from the model registry', 'cl_44b1', 0.92), '. The pre-read carries registry figures only.']),
      LABEL("who's in the room"),
      NODE('who-hokuei'),
      LABEL('open questions'),
      LI('Does the pilot scope include the Osaka warehouse?'),
      LI('Who signs, procurement or the COO?', { editedBy: 'o', editedAt: 'today 08:05' }),
      LABEL('what we promised'),
      NODE('promise'),
      LABEL('next step'),
      P('Send the pre-read to Mika Tanaka before Tuesday. Ask her for twenty minutes with the COO.'),
      P('The pre-read draft is in the inbox. It goes when you click.', { by: 'eiri', at: 'today 07:15', unread: true }),
      NODE('acts-hokuei'),
    ]),
    trail: [
      { when: 'today 08:05', who: 'o', what: 'edited ¶9' },
      { when: 'today 07:15', who: 'eiri', what: 'added ¶14' },
      { when: 'today 06:40', who: 'antevon', what: 'compiled · 14 claims' },
    ],
  },
  {
    id: 'night',
    title: 'Night-shift note: 03:12 run, one line per receipt',
    forWhom: 'the vault · nightly run',
    by: 'antevon',
    when: 'prepared today 04:05',
    group: 'today',
    byline: 'as of 04:05 · run 03:12 to 04:05',
    built: 'Antevon · run rx_7b12 · 03:12 to 04:05 · 42 writes, 2 wait',
    blocks: seal('night', 'antevon', 'today 04:05', [
      LEAD('The night wrote 42 claims. Two wait for you in the inbox. Nothing crossed a channel.'),
      NODE('night-ledger'),
      LABEL('next step'),
      P('Two claims wait for your click. The rest is in.'),
      NODE('acts-night'),
    ]),
    trail: [{ when: 'today 04:05', who: 'antevon', what: 'compiled · 8 receipts' }],
  },
  {
    id: 'week',
    title: 'Week in review, Aug 8–14',
    forWhom: 'antevon / ops',
    by: 'antevon',
    when: 'prepared Fri Aug 14 · 18:00',
    group: 'this week',
    byline: 'as of Aug 14 18:00 · Aug 8 to 14',
    built: 'Antevon · built Fri 18:00 from the week · 61 receipts · 5 threads',
    blocks: seal('week', 'antevon', 'Aug 14 18:00', [
      LEAD('A quiet week that moved one thing: Hokuei booked the pilot call. Kanto Logistics answered.'),
      LABEL('what moved'),
      LI([c('Hokuei booked the pilot call for Thursday 10:00', 'cl_7a20', 0.95), '. Mika Tanaka confirmed it on LINE.']),
      LI([c('Kanto Logistics replied to the intro', 'cl_5b3e', 0.88), '. No call is booked yet. Yuki owns the next message.']),
      LI([c('Hokuei may be consolidating suppliers', 'cl_9d17', 0.81), '. Tory read the filings. The claim waits in the inbox.']),
      LABEL('by the numbers'),
      NODE('nums'),
      LABEL('next week'),
      P('Thursday is the Hokuei call. Book the Kanto Logistics call before then.'),
      NODE('acts-week'),
    ]),
    trail: [{ when: 'Aug 14 18:00', who: 'antevon', what: 'compiled · 61 receipts' }],
  },
  {
    id: 'kanto',
    title: 'Kanto Logistics: what to know before the call',
    forWhom: 'Kanto Logistics · first call',
    by: 'tory',
    when: 'prepared Wed Aug 12 · 17:20',
    group: 'this week',
    byline: 'as of Aug 12 17:20 · first call · not booked',
    built: 'Tory · built Wed 17:20 from public sources and the intro thread · 9 claims · 2 threads',
    blocks: seal('kanto', 'tory', 'Aug 12 17:20', [
      LABEL('what to know'),
      LI([c('Kanto Logistics runs four warehouses in the Kanto region', 'cl_c410', 0.91), '. Two are cold chain.']),
      LI([
        c('One planner does the demand forecast in a spreadsheet', 'cl_c418', 0.62),
        '. One source, a job posting. Treat it as a guess until they say it.',
      ]),
      LI([c('They lost a 3PL contract in June', 'cl_c42b', 0.74), '. Two trade articles agree on the month, not on the size.']),
      LABEL("who's in the room"),
      NODE('who-kanto'),
      LABEL('next step'),
      P('Book the call. Yuki owns the intro. Lead with the June contract, not the spreadsheet.', { editedBy: 'y', editedAt: 'Aug 12 18:02' }),
      NODE('acts-kanto'),
    ]),
    trail: [
      { when: 'Aug 12 18:02', who: 'y', what: 'edited ¶8' },
      { when: 'Aug 12 17:20', who: 'tory', what: 'compiled · 9 claims' },
    ],
  },
  {
    id: 'rumor',
    title: 'Supplier rumor: filings read',
    forWhom: 'Hokuei · supplier watch',
    by: 'tory',
    when: 'prepared Thu Aug 6 · 09:40',
    group: 'earlier',
    byline: 'as of Aug 6 09:40 · Hokuei · supplier watch',
    built: 'Tory · run rx_8c41 · public filings · built Aug 6 09:40 · 6 filings',
    blocks: seal('rumor', 'tory', 'Aug 6 09:40', [
      LEAD('Hokuei changed its supplier list twice in a week. It reads like consolidation, not expansion. The claim went to the inbox at 0.81.'),
      NODE('filings'),
      LABEL('what it means'),
      LI([c('Hokuei may be consolidating suppliers this fiscal year', 'cl_9d17', 0.81), '. It contradicts the May claim that they were expanding.']),
      LI('Fewer suppliers means a bigger share for whoever stays. The pilot is the way in.'),
      LABEL('next step'),
      P('Ask Mika Tanaka on Thursday. Do not lead with it.'),
      NODE('acts-rumor'),
    ]),
    trail: [{ when: 'Aug 6 09:40', who: 'tory', what: 'compiled · 6 filings' }],
  },
]
const GROUPS: Group[] = ['today', 'this week', 'earlier']

/* per-brief state: read settles once; a draft act settles once */
type DocState = { readAt: string | null; drafting: boolean }

function Sep() {
  return <span className="sep">·</span>
}

/* the draft act cools into the companion's name and what she is doing */
function DraftAct({ state, label, onDraft }: { state: DocState; label: string; onDraft: (e: React.MouseEvent) => void }) {
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

/* ── the fixed pieces a brief carries between its prose: who is in the
   room, the promise and its two clocks, the receipts, the numbers, the
   acts. they are blocks too (they carry who compiled them) but they
   are not prose, so they do not take the caret. ── */
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
const FILINGS: { d: string; what: string; src: string; tip: string }[] = [
  { d: '2026-07-28', what: 'Notice of change to the approved supplier list.', src: 'edinet', tip: 'the filing · public' },
  { d: '2026-07-30', what: 'Two supplier codes retired, none added.', src: 'edinet', tip: 'the filing · public' },
  { d: '2026-08-04', what: 'A trade note reads it as consolidation.', src: 'nikkei', tip: 'the article · one source' },
]

function WhoHokuei() {
  return (
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
  )
}
function WhoKanto() {
  return (
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
  )
}
function Promise_() {
  return (
    <div className="promise">
      <span className="pclaim">
        <Link to="/app/vault" className="cited conf-1" title="cl_1e08 · 0.96 · open the claim in the vault">
          We promised an eight-week pilot from kickoff
        </Link>
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
      <span className="pnote">We said it in March. The vault learned it in June, from the scope note.</span>
    </div>
  )
}
function NightLedger() {
  return (
    <div className="receipts" aria-label="the receipts">
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
    </div>
  )
}
function Filings() {
  return (
    <div className="receipts" aria-label="the filings">
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
    </div>
  )
}
function Nums() {
  return (
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
  )
}

/* ── the page ── */
function Briefs() {
  const [briefs, setBriefs] = React.useState<Brief[]>(BRIEFS)
  const [sel, setSel] = React.useState<BriefId>('hokuei')
  /* a new brief starts at its own top, never mid-scroll of the last one */
  const bodyRef = React.useRef<HTMLDivElement>(null)
  const [hintOpen, setHintOpen] = React.useState(false)
  const [histOpen, setHistOpen] = React.useState(false)
  const touched = React.useRef(new Set<string>()) /* one trail row per block per sitting */
  /* read = a receipt (when); the Hokuei brief is the one still unread */
  const [docs, setDocs] = React.useState<Record<BriefId, DocState>>({
    hokuei: { readAt: null, drafting: false },
    night: { readAt: '08:12', drafting: false },
    week: { readAt: 'Aug 14 18:40', drafting: false },
    kanto: { readAt: 'Aug 12 18:02', drafting: false },
    rumor: { readAt: 'Aug 6 10:15', drafting: false },
  })
  useEscape(() => {
    setHintOpen(false)
    setHistOpen(false)
  })
  React.useEffect(() => {
    bodyRef.current?.scrollTo({ top: 0 })
  }, [sel])

  const pick = (id: BriefId) => () => {
    if (id === sel) return
    setSel(id)
    setHistOpen(false)
    cue('toggle')
  }
  const markRead = (id: BriefId) => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setDocs((d) => ({ ...d, [id]: { ...d[id], readAt: hhmm() } }))
    cue('success')
  }
  const draft = (id: BriefId) => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setDocs((d) => ({ ...d, [id]: { ...d[id], drafting: true } }))
    cue('press')
  }
  /* an edit lands in the brief and the trail takes one row per block per sitting */
  const change = (id: BriefId) => (blocks: Block[], ch: Change) => {
    const t = hhmm()
    setBriefs((bs) =>
      bs.map((b) => {
        if (b.id !== id) return b
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
        let trail = b.trail
        if (ch.op !== 'edit' || !touched.current.has(key)) {
          touched.current.add(key)
          trail = [{ when: `today ${t}`, who: 'o' as Who, what }, ...b.trail]
        }
        return { ...b, blocks, trail }
      }),
    )
  }

  /* unread until you mark it read; opening alone does not settle it */
  const isUnread = (b: Brief) => !docs[b.id].readAt
  const brief = briefs.find((b) => b.id === sel) ?? briefs[0]
  const state = docs[brief.id]

  /* the fixed pieces, by key; the acts close over this brief's state */
  const renderNode = (key: string) => {
    switch (key) {
      case 'who-hokuei':
        return <WhoHokuei />
      case 'who-kanto':
        return <WhoKanto />
      case 'promise':
        return <Promise_ />
      case 'night-ledger':
        return <NightLedger />
      case 'filings':
        return <Filings />
      case 'nums':
        return <Nums />
      case 'acts-hokuei':
        return (
          <div className="bacts">
            <DraftAct state={state} label="draft the follow-up" onDraft={draft('hokuei')} />
            <a className="act" href="/app/orgs" title="Hokuei · the org">
              open the org
            </a>
            <a className="act" href="/app/pipeline" title="Hokuei · pilot · in the pipeline">
              open in pipeline
            </a>
          </div>
        )
      case 'acts-night':
        return (
          <div className="bacts">
            <Link className="act" to="/app/inbox" title="the two that wait">
              open the inbox
            </Link>
            <a className="act" href="/app/agents" title="run rx_7b12 · every receipt">
              the run
            </a>
          </div>
        )
      case 'acts-week':
        return (
          <div className="bacts">
            <a className="act" href="/app/pipeline" title="the funnel">
              open the pipeline
            </a>
            <a className="act" href="/app/today" title="what is due">
              open today
            </a>
          </div>
        )
      case 'acts-kanto':
        return (
          <div className="bacts">
            <DraftAct state={state} label="draft the intro" onDraft={draft('kanto')} />
            <a className="act" href="/app/orgs" title="Kanto Logistics · the org">
              open the org
            </a>
            <a className="act" href="/app/pipeline" title="Kanto Logistics · lead · in the pipeline">
              open in pipeline
            </a>
          </div>
        )
      case 'acts-rumor':
        return (
          <div className="bacts">
            <Link className="act" to="/app/vault" title="cl_9d17 · the claim">
              open the claim
            </Link>
            <a className="act" href="/app/lens/supplier-watch" title="supplier watch · the lens">
              open the lens
            </a>
          </div>
        )
      default:
        return null
    }
  }
  const unreadBlocks = brief.blocks.filter((b) => b.unread).length

  return (
    <main className="pane briefs-pane">
      {/* the index column: a tinted zone divides, not a line */}
      <nav className="blist" aria-label="briefs" onKeyDown={rowArrows('.bitem')}>
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
            Your agents prepare these before you need them: meeting briefs, night notes, the week in
            review. Every sentence that matters cites the claim under it. Click into a line to write.
            Select words to hand them to an agent.
          </span>
        </div>

        <div className="bgroups">
          {GROUPS.map((g) => {
            const rows = briefs.filter((b) => b.group === g)
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
      </nav>

      {/* the document: compiled by an agent, yours to write in */}
      <div className="pane-body" ref={bodyRef}>
        <article className="brief" key={brief.id} aria-label={brief.title}>
          <div className="brief-head">
            <div className="brief-title">
              <h2>{brief.title}</h2>
              <span className="brief-tools">
                <HistoryAct open={histOpen} onToggle={() => setHistOpen((o) => !o)} controls="briefs-trail" />
                <ShareAct />
              </span>
            </div>
            {/* the one quiet meta-line: the name in its ink · as of · for whom.
                what it was built from rides the hover */}
            <div className="brief-by" title={brief.built}>
              <Aname who={brief.by} tip={`${WHO[brief.by].tip} · ${brief.when}`} />
              <Sep />
              <span>{brief.byline}</span>
              {unreadBlocks > 0 && (
                <>
                  <Sep />
                  <span title="an agent touched this brief · the ink shows where">{unreadBlocks} unread</span>
                </>
              )}
            </div>
            <TrailFold rows={brief.trail} open={histOpen} id="briefs-trail" />
          </div>

          <Doc blocks={brief.blocks} onChange={change(brief.id)} renderNode={renderNode} />

          {/* the foot: read settles into a receipt line */}
          <div className="brief-foot">
            {state.readAt ? (
              <span className="meta-line" title="marked read · yours">
                read {state.readAt}
              </span>
            ) : (
              <a className="act" href="#" title="verb: mark_read" onClick={markRead(brief.id)}>
                mark read
              </a>
            )}
          </div>
        </article>
      </div>
    </main>
  )
}
