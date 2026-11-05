import * as React from 'react'
import { Link, createFileRoute } from '@tanstack/react-router'
import { ChanLine, ChanMail, ChanSlack, Chevron } from '~/components/safelight/icons'
import { cue, markCued, useEscape } from '~/components/safelight/hooks'
import lensCss from '~/styles/lens.css?url'

export const Route = createFileRoute('/app/lens/supplier-watch')({
  head: () => ({
    links: [{ rel: 'stylesheet', href: lensCss }],
  }),
  component: SupplierWatch,
})

/* ══ supplier watch · a saved LENS (a custom watch query) ══
   A lens is an instrument: the eyebrow names the agent and the as-of;
   the definition is the only sentence in quotes; everything else is
   ledgers and one calm digest. Fixtures live here; the page works. */

const DEFINITION = "Anything about Hokuei's suppliers, and any rumor of consolidation."

type Claim = {
  id: string
  text: string
  conf: 1 | 2 | 3 | 4
  confNum: string
  proposed?: boolean
  occurred: string
  learned: string
  world: string
  src: string
  srcTip: string
  why: string
}

const CLAIMS: Claim[] = [
  {
    id: 'cl_9d17',
    text: 'Hokuei may be consolidating suppliers this fiscal year',
    conf: 3,
    confNum: '0.58',
    proposed: true,
    occurred: '2026-08-14',
    learned: '2026-08-15',
    world: 'work',
    src: 'filing',
    srcTip: 'Tory · run rx_8c41 · public filings · 2026-08-15 03:12',
    why: 'One source, proposed. It contradicts the standing claim that Hokuei is expanding the supplier base. Accepting supersedes it.',
  },
  {
    id: 'cl_31f0',
    text: 'Hokuei is expanding the supplier base',
    conf: 2,
    confNum: '0.77',
    occurred: '2026-05-12',
    learned: '2026-05-14',
    world: 'work',
    src: '#ops',
    srcTip: 'slack · #ops · Yuki · 2026-05-14',
    why: 'The standing claim. Yuki heard it from the Hokuei buyer in May. The new filing may supersede it.',
  },
  {
    id: 'cl_4c02',
    text: 'Hokuei buys steel from three suppliers in Kansai',
    conf: 1,
    confNum: '0.94',
    occurred: '2026-06-30',
    learned: '2026-07-03',
    world: 'work',
    src: 'email',
    srcTip: 'email · filings alert · Q1 report · 2026-07-03',
    why: 'Two sources agree: the June supplier list and the Q1 report.',
  },
  {
    id: 'cl_7a55',
    text: "Hokuei's head of procurement changed in April",
    conf: 2,
    confNum: '0.81',
    occurred: '2026-04-01',
    learned: '2026-07-18',
    world: 'work',
    src: 'LINE',
    srcTip: 'LINE · Mika Tanaka · 2026-07-18',
    why: 'Mika Tanaka mentioned the new head in July. Learned three months after it happened.',
  },
]

type WireKey = 'm1' | 'm2' | 'm3'
type Wire = {
  key: WireKey
  date: string
  time: string
  chan: 'slack' | 'line' | 'email'
  by: React.ReactNode
  line: string
  crumb: string
  title: string
  ctxBy: React.ReactNode
  body: string
  threadTip: string
}

const WIRE: Wire[] = [
  {
    key: 'm1',
    date: '08-14',
    time: '16:22',
    chan: 'slack',
    by: (
      <span className="seal seal-human" title="y · Yuki">
        y
      </span>
    ),
    line: 'Hokuei’s buyer says fewer vendors next year. Nothing on paper yet.',
    crumb: '08-14 · 16:22 · slack · #ops',
    title: 'Yuki in #ops',
    ctxBy: (
      <>
        <span className="seal seal-human" title="y · Yuki">
          y
        </span>
        <span>Yuki</span>
      </>
    ),
    body:
      'Talked to the Hokuei buyer after the call. He says fewer vendors next year, maybe one partner for steel. Nothing on paper yet.\n\nI asked for the timeline. He said the review runs to March.',
    threadTip: 'slack · #ops · the whole thread',
  },
  {
    key: 'm2',
    date: '08-13',
    time: '09:15',
    chan: 'line',
    by: (
      <span className="seal seal-human seal-class" title="m · Mika Tanaka">
        m
      </span>
    ),
    line: 'Mika Tanaka: the procurement review runs to the end of March.',
    crumb: '08-13 · 09:15 · LINE',
    title: 'Mika Tanaka, on LINE',
    ctxBy: (
      <>
        <span className="seal seal-human seal-class" title="m · Mika Tanaka">
          m
        </span>
        <span>Mika Tanaka</span>
      </>
    ),
    body:
      'Our procurement review runs to the end of March. I will share the supplier list when it is final.\n\nCan you send the pilot quote by Tuesday?',
    threadTip: 'LINE · the whole thread',
  },
  {
    key: 'm3',
    date: '08-11',
    time: '07:02',
    chan: 'email',
    by: (
      <span className="seal seal-system" title="s · filings alert · system">
        s
      </span>
    ),
    line: 'Filings alert: Hokuei’s Q1 report lists three steel suppliers in Kansai.',
    crumb: '08-11 · 07:02 · email · filings alert',
    title: 'Hokuei Q1 report, filed',
    ctxBy: (
      <>
        <span className="seal seal-system" title="s · filings alert · system">
          s
        </span>
        <span>filings alert</span>
      </>
    ),
    body:
      'Hokuei Co., Ltd. filed its Q1 report. Section 3 lists three steel suppliers, all in Kansai. The vendor count has not changed since the annual report.',
    threadTip: 'email · the filing and its alert',
  },
]

function ChanGlyph({ chan }: { chan: Wire['chan'] }) {
  if (chan === 'slack') return <ChanSlack />
  if (chan === 'line') return <ChanLine />
  return <ChanMail />
}

/* headings collapse in place; the count renders only when closed */
function Bundle({
  label,
  title,
  count,
  children,
}: {
  label: string
  title: string
  count: string
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
          <Chevron ariaHidden={false} />
        </span>
        <span className="meta-line">{count}</span>
      </div>
      <div className="sec-body">{children}</div>
    </section>
  )
}

/* the definition's life: live → (edit) saved · paused · deleted.
   every outcome settles in place as a receipt line; no toast, no modal */
type DefState = 'live' | 'saved' | 'paused' | 'deleted'

function SupplierWatch() {
  const [def, setDef] = React.useState(DEFINITION)
  const [draft, setDraft] = React.useState(DEFINITION)
  const [editing, setEditing] = React.useState(false)
  const [defState, setDefState] = React.useState<DefState>('live')
  const [openRow, setOpenRow] = React.useState<string | null>(null)
  const [ctx, setCtx] = React.useState<WireKey | null>(null)
  const [widened, setWidened] = React.useState(false)
  const inputRef = React.useRef<HTMLInputElement>(null)

  React.useEffect(() => {
    if (editing) inputRef.current?.select()
  }, [editing])

  /* esc peels the innermost thing you opened */
  useEscape(() => {
    if (editing) {
      setEditing(false)
      setDraft(def)
    } else if (ctx) setCtx(null)
    else if (openRow) setOpenRow(null)
  })

  const startEdit = (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setDraft(def)
    setEditing(true)
    cue('toggle')
  }
  const saveEdit = () => {
    const next = draft.trim()
    setEditing(false)
    if (!next || next === def) {
      setDraft(def)
      return
    }
    setDef(next)
    setDefState('saved')
    cue('success')
  }
  const pause = (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setDefState('paused')
    cue('press')
  }
  const resume = (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setDefState('live')
    cue('success')
  }
  const remove = (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setEditing(false)
    setDefState('deleted')
    setOpenRow(null)
    setCtx(null)
    cue('press')
  }
  const undo = (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setDefState('live')
    cue('success')
  }

  const toggleRow = (id: string) => {
    setOpenRow((cur) => (cur === id ? null : id))
    cue('toggle')
  }
  const select = (key: WireKey) => (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest('a')) return
    setCtx((cur) => (cur === key ? null : key))
    cue('toggle')
  }
  const c = ctx ? WIRE.find((w) => w.key === ctx) ?? null : null

  const bodyClass = defState === 'deleted' ? 'pane-body deleted' : defState === 'paused' ? 'pane-body paused' : 'pane-body'

  return (
    <main className={ctx ? 'pane lens ctx-on' : 'pane lens'} id="pane">
      <div className={bodyClass}>
        <div className="pane-head">
          <h1>Supplier watch</h1>
          <span className="lens-meta" title="minted 2026-07-02">
            a lens · yours · since Jul 2
          </span>
        </div>

        {/* the WATCH DEFINITION: the one sentence in quotes; its acts
            settle in place — edit becomes an inline input, pause and
            delete cool into a receipt line */}
        <div className="watch-def" aria-label="the watch definition">
          {editing ? (
            <input
              ref={inputRef}
              className="def-input"
              value={draft}
              autoFocus
              aria-label="the watch definition · enter saves · esc ends"
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault()
                  saveEdit()
                }
              }}
            />
          ) : (
            <span className="def-quote">{def}</span>
          )}
          <span className="def-acts">
            {defState === 'deleted' ? (
              <span className="receipt">
                <span className="meta-line">deleted · receipt kept</span>
                <a className="act" href="#" title="restore the watch · the receipt stays" onClick={undo}>
                  undo
                </a>
              </span>
            ) : defState === 'paused' ? (
              <span className="receipt">
                <span className="meta-line">paused</span>
                <a className="act" href="#" title="the watch runs again · from the next run" onClick={resume}>
                  resume
                </a>
                <a className="act" href="#" title="delete the watch · its receipts stay" onClick={remove}>
                  delete
                </a>
              </span>
            ) : editing ? (
              <span className="meta-line">enter saves · esc ends</span>
            ) : (
              <>
                <a className="act" href="#" title="edit the definition in place" onClick={startEdit}>
                  edit
                </a>
                <a className="act" href="#" title="pause the watch · resume when you say" onClick={pause}>
                  pause
                </a>
                <a className="act" href="#" title="delete the watch · its receipts stay" onClick={remove}>
                  delete
                </a>
                {defState === 'saved' && <span className="meta-line">saved · next run</span>}
              </>
            )}
          </span>
        </div>

        {/* ══ INSTRUMENT · agent-rendered; the eyebrow names the agent
            and the as-of ══ */}
        <section className="instrument" aria-label="supplier watch lens">
          <div className="label" title="Antevon · the house mind · rendered this lens at 06:40 · regenerates when the evidence changes">
            <span className="aname" data-agent="antevon">
              Antevon
            </span>
            <span>· as of 08-15 06:40</span>
          </div>

          {/* WHAT CHANGED · the digest, name-fronted, in the agent's voice */}
          <Bundle label="what changed" title="What changed" count="1 proposed">
            <div className="digest">
              <span className="aname" data-agent="antevon" title="Antevon · the house mind · 06:40">
                Antevon
              </span>
              <span className="words">
                Hokuei may be consolidating suppliers this fiscal year. One source so far, still
                proposed. Tory read two filings. None names a partner.
                <Link className="act" to="/app/inbox" title="the proposed claim waits in the inbox">
                  review it
                </Link>
              </span>
            </div>
          </Bundle>

          {/* MATCHED CLAIMS · the vault's ledger idiom; a row unfolds its
              why + doors under itself (rule 39, rec A) */}
          <Bundle label="matched claims" title="Matched claims" count="4 claims">
            <div className="ledger-wrap">
              <table className="ledger">
                <thead>
                  <tr>
                    <th className="c-dot"></th>
                    <th>claim</th>
                    <th className="c-occ">occurred</th>
                    <th className="c-lrn">learned</th>
                    <th className="c-world">world</th>
                    <th className="c-src">source</th>
                  </tr>
                </thead>
                <tbody>
                  {CLAIMS.map((cl) => {
                    const open = openRow === cl.id
                    return (
                      <React.Fragment key={cl.id}>
                        <tr
                          className={open ? 'row open' : 'row'}
                          role="button"
                          tabIndex={0}
                          aria-expanded={open}
                          onClick={(e) => {
                            if ((e.target as HTMLElement).closest('a')) return
                            toggleRow(cl.id)
                          }}
                          onKeyDown={(e) => {
                            if ((e.key === 'Enter' || e.key === ' ') && !(e.target as HTMLElement).closest('a')) {
                              e.preventDefault()
                              toggleRow(cl.id)
                            }
                          }}
                        >
                          <td className="c-dot">
                            {cl.proposed && (
                              <span className="dot dot-proposed" title="proposed · one source · waits in the inbox"></span>
                            )}
                          </td>
                          <td>
                            <span className={`claim conf-${cl.conf}`} title={`confidence ${cl.confNum} · ${cl.id}`}>
                              {cl.text}
                            </span>
                          </td>
                          <td>
                            <span className="clk" title="occurred · when it became true">
                              {cl.occurred}
                            </span>
                          </td>
                          <td>
                            <span className="clk hollow" title="learned · when the vault heard it">
                              {cl.learned}
                            </span>
                          </td>
                          <td>
                            <span className="world" title={`world: ${cl.world}`}>
                              {cl.world}
                            </span>
                          </td>
                          <td>
                            <a className="src" href="#" title={cl.srcTip}>
                              {cl.src}
                            </a>
                          </td>
                        </tr>
                        <tr className="detail" aria-hidden={!open}>
                          <td colSpan={6}>
                            <div className={open ? 'row-detail open' : 'row-detail'}>
                              <div className="rd-inner">
                                <span className="rd-why">{cl.why}</span>
                                <span className="rd-acts">
                                  {cl.proposed && (
                                    <Link className="act" to="/app/inbox" title="the proposed claim waits in the inbox" tabIndex={open ? 0 : -1}>
                                      review it
                                    </Link>
                                  )}
                                  <a className="act" href="#" title={cl.srcTip} tabIndex={open ? 0 : -1}>
                                    source
                                  </a>
                                  <Link
                                    className="act"
                                    to="/app/vault"
                                    title={`${cl.id} · confidence, occurred, learned, actor`}
                                    tabIndex={open ? 0 : -1}
                                  >
                                    open the claim
                                  </Link>
                                </span>
                              </div>
                            </div>
                          </td>
                        </tr>
                      </React.Fragment>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </Bundle>

          {/* MATCHED MESSAGES · one line each: date · channel glyph · who ·
              what was said. a row clicks into the context column */}
          <Bundle label="matched messages" title="Matched messages" count="3 messages">
            <div className="mrows">
              {WIRE.map((w) => (
                <button
                  key={w.key}
                  type="button"
                  className={ctx === w.key ? 'w-row sel' : 'w-row'}
                  aria-pressed={ctx === w.key}
                  onClick={select(w.key)}
                  title={`${w.date} · ${w.time} · read it`}
                >
                  <span className="w-time">{w.date}</span>
                  <span className="w-chan" title={w.chan === 'line' ? 'LINE' : w.chan}>
                    <ChanGlyph chan={w.chan} />
                  </span>
                  {w.by}
                  <span className="t-msg">{w.line}</span>
                </button>
              ))}
            </div>
          </Bundle>
        </section>

        {/* the foot: widen the watch (settles) · the vault, filtered */}
        <div className="lens-foot">
          {widened ? (
            <span className="meta-line">widened · next run</span>
          ) : (
            <a
              className="act"
              href="#"
              title="widen the watch · Antevon proposes the new line"
              onClick={(e) => {
                e.preventDefault()
                markCued(e)
                setWidened(true)
                cue('success')
              }}
            >
              watch more like this
            </a>
          )}
          <Link className="act" to="/app/vault" title="the vault, filtered to this watch">
            open the vault filtered
          </Link>
        </div>
      </div>

      {/* the context column: a matched message docks here to be READ */}
      <aside className="context" hidden={!c} aria-label="the message">
        {c && (
          <>
            <div className="ctx-head">
              <span className="ctx-crumb">{c.crumb}</span>
              <button className="ctx-close" aria-label="close the message" title="close · esc" onClick={() => setCtx(null)}>
                ×
              </button>
            </div>
            <div className="ctx-title">{c.title}</div>
            <div className="ctx-by">{c.ctxBy}</div>
            <div className="ctx-body">{c.body}</div>
            <div className="ctx-acts">
              <a className="act" href="#" title={c.threadTip}>
                the thread
              </a>
              <Link className="act" to="/app/vault" title="the claim this message fed">
                the claim
              </Link>
            </div>
          </>
        )}
      </aside>
    </main>
  )
}
