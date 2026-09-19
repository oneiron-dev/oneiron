import * as React from 'react'
import { Link, createFileRoute } from '@tanstack/react-router'
import { Chevron } from '~/components/safelight/icons'
import { cue, markCued, useEscape } from '~/components/safelight/hooks'
import recallCss from '~/styles/recall.css?url'
import { recallSceneAssets, useRecallScene } from '~/runtime/recall-scene'

export const Route = createFileRoute('/app/recall')({
  head: () => ({
    links: [{ rel: 'stylesheet', href: recallCss }],
  }),
  component: Recall,
})

/* ── recall is the search door: no rail row is active. the question is
   the pane title; the answer is a printed page that shows its work
   (FLOWS §3 #1). Two fixture asks, plus the empty door and a plain
   no-record print for anything the fixture vault does not hold. ── */

type AskKey = 'hokuei' | 'shellfish' | 'other'

const SAMPLES: { key: AskKey; chip: string; question: string; title: string }[] = [
  {
    key: 'hokuei',
    chip: 'the Hokuei promise',
    question: 'What did we promise Hokuei on the pilot timeline?',
    title: 'sample · a full answer',
  },
  {
    key: 'shellfish',
    chip: 'shellfish allergy',
    question: 'Is anyone at Hokuei allergic to shellfish?',
    title: 'sample · the thin state',
  },
]

const AS_OF = '08-13 14:02'

/* what made the cut: the claims the answer stands on. two clocks per row;
   the desk-floor row is the demo (occurred in May, learned in August). */
type CutRow = {
  id: string
  conf: number
  claim: string
  occurred: string
  learned: string
  gap?: string
  world: string
  source: { text: string; href: string; title: string }
  title: string
}

const CUT: CutRow[] = [
  {
    id: 'cl_9f21',
    conf: 0.94,
    claim: 'The pilot runs six weeks from the first week of September',
    occurred: '08-08',
    learned: '08-08',
    world: 'clients',
    source: { text: 'call note', href: '/app/notes', title: 'call note · Hokuei pilot call · 08-08' },
    title: 'cl_9f21 · 0.94 · occurred 08-08 · learned 08-08 · the call note',
  },
  {
    id: 'cl_a04c',
    conf: 0.91,
    claim: 'Yurii sends the formal quote by Tuesday',
    occurred: '08-12',
    learned: '08-12',
    world: 'clients',
    source: { text: 'line thread', href: '/app/threads', title: 'LINE thread · Mika Tanaka · 08-12' },
    title: 'cl_a04c · 0.91 · occurred 08-12 · learned 08-12 · the LINE thread',
  },
  {
    id: 'cl_77b8',
    conf: 0.84,
    claim: 'The desk floor is ¥380,000 a month, scoped',
    occurred: '05-30',
    learned: '08-05',
    gap: '+67d',
    world: 'base',
    source: { text: 'mail archive', href: '/app/vault', title: 'mail archive import · 08-05' },
    title:
      'cl_77b8 · 0.84 · two clocks: it occurred 05-30, the vault learned it 08-05 when the mail archive arrived. 67 days of hindsight, kept apart on purpose. This row is the demo.',
  },
]

/* confidence = ink (silver-1 ≥.9 · silver-2 .7–.89 · silver-3 .4–.69 · silver-4 <.4) */
function confClass(conf: number) {
  return conf >= 0.9 ? 'conf-1' : conf >= 0.7 ? 'conf-2' : conf >= 0.4 ? 'conf-3' : 'conf-4'
}

/* the fixture vault answers two questions; anything else prints thin and true */
function resolve(q: string): AskKey | null {
  const s = q.trim().toLowerCase()
  if (!s) return null
  if (/hokuei|promise|pilot|timeline/.test(s) && !/shellfish|allerg/.test(s)) return 'hokuei'
  if (/shellfish|allerg/.test(s)) return 'shellfish'
  return 'other'
}

/* a section of the print: serif head, a quiet toggle; the count shows only
   when the body is folded (rules 10 + 16) */
function Sect({
  title,
  count,
  openKey,
  children,
}: {
  title: string
  count: string
  openKey?: number
  children: React.ReactNode
}) {
  const [closed, setClosed] = React.useState(false)
  /* a cite or a successor door reaches into a folded section: it opens */
  React.useEffect(() => {
    if (openKey) setClosed(false)
  }, [openKey])
  const toggle = () => {
    setClosed((c) => !c)
    cue('toggle')
  }
  return (
    <div className={closed ? 'a-sect closed' : 'a-sect'}>
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
        <span className="title">{title}</span>
        <span className="fold-hint" aria-hidden="true">
          <Chevron ariaHidden={false} />
        </span>
        <span className="meta-line">{count}</span>
      </div>
      <div className="a-body">{children}</div>
    </div>
  )
}

/* the eyebrow: who rendered it, from what, as of when. the as-of is the
   door into the vault (the scrubber). */
function Eyebrow({ title }: { title: string }) {
  return (
    <div className="eyebrow" title={title}>
      <span className="aname" data-agent="antevon" title="Antevon · the house mind rendered this answer">
        Antevon
      </span>
      <span className="sep" aria-hidden="true">
        ·
      </span>
      <span>five signals · one blend</span>
      <span className="sep" aria-hidden="true">
        ·
      </span>
      <Link to="/app/vault" title={`the vault as of ${AS_OF} · the as-of scrubber`}>
        as of {AS_OF}
      </Link>
    </div>
  )
}

/* watch this question → a saved query. it settles in place, no toast. */
function Watch({ watched, onWatch }: { watched: boolean; onWatch: () => void }) {
  if (watched) {
    return (
      <span className="meta-line" title="saved query · changes to this answer land in your inbox">
        watching · quiet
      </span>
    )
  }
  return (
    <a
      className="act"
      href="#"
      title="verb: save_query · changes to this answer land in your inbox digest"
      onClick={(e) => {
        e.preventDefault()
        markCued(e)
        onWatch()
        cue('success')
      }}
    >
      watch this question
    </a>
  )
}

function Recall() {
  const [scene] = useRecallScene()
  const askRef = React.useRef<HTMLTextAreaElement>(null)
  const ledgerRef = React.useRef<HTMLTableElement>(null)
  const [draft, setDraft] = React.useState('')
  const [asked, setAsked] = React.useState<{ key: AskKey; q: string; n: number } | null>(null)
  const [selected, setSelected] = React.useState<string | null>(null)
  const [receipt, setReceipt] = React.useState(false)
  const [reach, setReach] = React.useState(0)
  const [watched, setWatched] = React.useState<Record<AskKey, boolean>>({
    hokuei: false,
    shellfish: false,
    other: false,
  })

  const run = React.useCallback((q: string) => {
    const key = resolve(q)
    setDraft(q)
    setSelected(null)
    setReceipt(false)
    if (!key) {
      setAsked(null)
      return
    }
    setAsked((cur) => ({ key, q, n: (cur?.n ?? 0) + 1 }))
    cue('press')
  }, [])

  /* the rail's search row can carry a query: /app/recall?q=… */
  React.useEffect(() => {
    const q = new URLSearchParams(location.search).get('q')
    if (q) run(q)
  }, [run])

  /* `/` lands on the ask from anywhere on this page (never while typing) */
  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null
      if (target && /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName)) return
      if (e.key === '/') {
        e.preventDefault()
        askRef.current?.focus()
        askRef.current?.select()
      }
    }
    addEventListener('keydown', onKey)
    return () => removeEventListener('keydown', onKey)
  }, [])

  /* the field grows with the question (a fallback where field-sizing is unknown) */
  const fit = React.useCallback(() => {
    const el = askRef.current
    if (!el) return
    el.style.height = 'auto'
    el.style.height = `${el.scrollHeight}px`
  }, [])
  React.useEffect(fit, [fit, draft])

  /* esc peels: the receipt, then the selection, then the question itself */
  useEscape(() => {
    if (receipt) setReceipt(false)
    else if (selected) setSelected(null)
    else if (asked) {
      setAsked(null)
      setDraft('')
      askRef.current?.focus()
    }
  })

  /* a cited span or a successor door selects the ledger row it stands on */
  const pick = (id: string) => (e: React.SyntheticEvent) => {
    e.preventDefault()
    markCued(e)
    setSelected(id)
    setReach((n) => n + 1)
    cue('toggle')
    requestAnimationFrame(() => {
      const row = ledgerRef.current?.querySelector<HTMLElement>(`[data-id="${id}"]`)
      row?.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
    })
  }
  const toggleRow = (id: string) => {
    setSelected((cur) => (cur === id ? null : id))
    cue('toggle')
  }
  const toggleReceipt = (e: React.SyntheticEvent) => {
    e.preventDefault()
    markCued(e)
    setReceipt((r) => !r)
    cue('toggle')
  }

  const cite = (id: string, conf: number, text: string) => (
    <button
      type="button"
      className={selected === id ? `cite ${confClass(conf)} on` : `cite ${confClass(conf)}`}
      title={`${id} · ${conf.toFixed(2)} · the claim it stands on`}
      onClick={pick(id)}
    >
      {text}
    </button>
  )

  const key = asked?.key ?? null
  const sceneAssets = !asked ? recallSceneAssets(scene) : null

  return (
    <main className={sceneAssets ? 'pane recall has-scene' : 'pane recall'} id="pane">
      {sceneAssets && (
        <div className="recall-scene-backdrop" aria-hidden="true">
          <div className="art-day" style={{ backgroundImage: `url("${sceneAssets.day}")` }} />
          <div className="art-night" style={{ backgroundImage: `url("${sceneAssets.night}")` }} />
        </div>
      )}
      <div className="pane-body">
        <div className="recall-entry">
          {/* the question IS the pane title */}
          <div className="pane-head">
            <textarea
              id="ask"
              ref={askRef}
              aria-label="ask the vault"
              className="ask"
              rows={1}
              placeholder="Ask the vault"
              value={draft}
              autoFocus
              spellCheck={false}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault()
                  run(draft)
                }
              }}
            />
          </div>

          {/* the empty door (rule 40): the flock, one line, the two sample doors */}
          {!asked && (
            <div className="recall-empty">
              <img className="spot" src="/art/spot-flock.png" width={150} alt="" />
              <span className="lead">
                <span className="line">Ask the vault. Every answer shows what it stands on.</span>
                <span className="doors">
                  {SAMPLES.map((s) => (
                    <button
                      key={s.key}
                      className="chip"
                      title={s.title}
                      onClick={() => run(s.question)}
                    >
                      {s.chip}
                    </button>
                  ))}
                </span>
              </span>
            </div>
          )}
        </div>

        {/* the sample asks: chips under the title once a question is live */}
        {asked && (
          <div className="asks" role="group" aria-label="asked lately">
            <span className="label">asked lately</span>
            {SAMPLES.map((s) => (
              <button
                key={s.key}
                className={key === s.key ? 'chip on' : 'chip'}
                title={s.title}
                aria-pressed={key === s.key}
                onClick={() => run(s.question)}
              >
                {s.chip}
              </button>
            ))}
          </div>
        )}

        {/* ══ STATE A · the full answer ══ */}
        {asked && key === 'hokuei' && (
          <section
            key={`hokuei-${asked.n}`}
            className="instrument answer"
            aria-label="the answer"
          >
            <Eyebrow title="agent-rendered lens · five signals blended into one answer · asked across base · clients" />

            <p className="a-prose">
              A {cite('cl_9f21', 0.94, 'six-week pilot')}, starting the{' '}
              {cite('cl_9f21', 0.94, 'first week of September')}. Yurii owes Mika the{' '}
              {cite('cl_a04c', 0.91, 'formal quote by Tuesday')}. The scope stands at the{' '}
              {cite('cl_77b8', 0.84, '¥380,000 desk floor')} agreed in May. The timeline moved on the
              8th. The mid-August start no longer holds.
            </p>

            <Sect title="What made the cut" count="3 claims" openKey={reach}>
              <div className="ledger-wrap">
                <table className="ledger cut" ref={ledgerRef}>
                  <thead>
                    <tr>
                      <th>claim</th>
                      <th className="c-occ">occurred</th>
                      <th className="c-lrn">learned</th>
                      <th className="c-world">world</th>
                      <th className="c-src">source</th>
                    </tr>
                  </thead>
                  <tbody>
                    {CUT.map((r) => (
                      <tr
                        key={r.id}
                        data-id={r.id}
                        className={[
                          selected === r.id ? 'selected' : '',
                          r.gap ? 'hindsight' : '',
                        ]
                          .filter(Boolean)
                          .join(' ')}
                        title={r.title}
                        tabIndex={0}
                        aria-selected={selected === r.id}
                        onClick={(e) => {
                          if ((e.target as HTMLElement).closest('a')) return
                          toggleRow(r.id)
                        }}
                        onKeyDown={(e) => {
                          if ((e.key === 'Enter' || e.key === ' ') && !(e.target as HTMLElement).closest('a')) {
                            e.preventDefault()
                            toggleRow(r.id)
                          }
                        }}
                      >
                        <td>
                          <span className={`claim ${confClass(r.conf)}`}>{r.claim}</span>
                        </td>
                        <td>
                          <span className="when">
                            <span className="tc-dot" aria-hidden="true"></span>
                            {r.occurred}
                          </span>
                        </td>
                        <td>
                          <span className="when learned">
                            <span className="tc-dot hollow" aria-hidden="true"></span>
                            {r.learned}
                            {r.gap && (
                              <span className="gap" title="learned 67 days after it occurred">
                                {r.gap}
                              </span>
                            )}
                          </span>
                        </td>
                        <td>
                          <span className="world">{r.world}</span>
                        </td>
                        <td>
                          <a className="src" href={r.source.href} title={r.source.title}>
                            {r.source.text}
                          </a>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Sect>

            <Sect title="Withheld, and why" count="3 withheld">
              <div className="withheld">
                <div className="wh-line">
                  <span className="wh-why">superseded</span>
                  <span className="wh-what superseded" title="cl_5c02 · 0.77 · thread, 07-15 · superseded 08-08">
                    The pilot starts mid-August
                  </span>
                  <a
                    className="act"
                    href="#"
                    title="cl_9f21 · the September start · the row above"
                    onClick={pick('cl_9f21')}
                  >
                    successor
                  </a>
                </div>
                <div className="wh-line">
                  <span className="wh-why">below the floor</span>
                  <span className="wh-what conf-4" title="cl_2e77 · 0.28 · one mention · under the evidence floor for this ask">
                    Hokuei may want a second pilot for the Osaka team
                  </span>
                  <span className="wh-num">0.28</span>
                </div>
                <div className="wh-line">
                  <span className="wh-why">foreign world</span>
                  <span className="wh-what" title="world: internal · this ask ran base + clients">
                    A margin note on pilot pricing sits in another world
                  </span>
                  <Link className="act quiet" to="/app/vault" title="world: internal · this ask ran base + clients">
                    internal
                  </Link>
                </div>
              </div>
            </Sect>

            <div className="explain">
              <span
                className="x-text"
                role="button"
                tabIndex={0}
                aria-expanded={receipt}
                aria-controls="receipt"
                title="a door: what this summary was compiled from"
                onClick={toggleReceipt}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') toggleReceipt(e)
                }}
              >
                Two promises anchor this: the September start and Tuesday's quote. The old start
                date sat out; it was superseded on the 8th.
              </span>
              <a
                className="byline"
                data-agent="antevon"
                href="/app/agents"
                title="Antevon · the house mind · rendered 14:02 · re-renders when the evidence changes"
              >
                Antevon
              </a>
            </div>

            <div>
              <div className="a-foot">
                <a
                  className="act"
                  href="#"
                  aria-expanded={receipt}
                  aria-controls="receipt"
                  title="verb: open_receipt · the context receipt for this answer"
                  onClick={toggleReceipt}
                >
                  {receipt ? 'close the receipt' : 'open the receipt'}
                </a>
                <Watch
                  watched={watched.hokuei}
                  onWatch={() => setWatched((w) => ({ ...w, hokuei: true }))}
                />
              </div>
              <div className={receipt ? 'receipt open' : 'receipt'} id="receipt">
                <div className="r-inner">
                  <div className="r-body">
                    <span className="meta-line" title="the receipt · every line above traces to a claim">
                      rc_4e11 · asked 08-13 14:02 · base · clients · 5 signals · 3 in · 3 withheld
                    </span>
                    <span className="meta-line" title="the hygiene pass · the overnight run">
                      hygiene pass 03:12 · rx_7b12
                    </span>
                    <span className="r-note">
                      Nothing here is a guess. Every line traces to a claim, and every claim to its
                      source.
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </section>
        )}

        {/* ══ STATE B · the thin answer: the floor speaks ══ */}
        {asked && key === 'shellfish' && (
          <section
            key={`shellfish-${asked.n}`}
            className="instrument answer"
            aria-label="the answer"
          >
            <Eyebrow title="agent-rendered lens · asked across base · clients · nothing was withheld" />

            <p className="a-prose">
              No committed record. One proposed claim waits in the inbox. Until you accept it,
              this answer stays empty.
            </p>

            <Sect title="Proposed, not yet yours" count="1 waits">
              <div className="thin-row">
                <span className="dot dot-proposed" title="proposed · held for review"></span>
                <span
                  className="claim conf-3"
                  title="cl_58aa · 0.52 · one mention, April · held: low-confidence critical"
                >
                  May be allergic to shellfish
                </span>
                <Link className="act" to="/app/inbox" title="the held write, in the needs-you queue">
                  review it
                </Link>
              </div>
            </Sect>

            <div className="explain">
              <span className="x-text">
                The vault holds little on this yet. It will say so, every time.
              </span>
              <a
                className="byline"
                data-agent="antevon"
                href="/app/agents"
                title="Antevon · the house mind · rendered 14:02"
              >
                Antevon
              </a>
            </div>

            <div className="a-foot">
              <Watch
                watched={watched.shellfish}
                onWatch={() => setWatched((w) => ({ ...w, shellfish: true }))}
              />
            </div>
          </section>
        )}

        {/* ══ anything else · the fixture vault holds no record; it says so ══ */}
        {asked && key === 'other' && (
          <section
            key={`other-${asked.n}`}
            className="instrument answer"
            aria-label="the answer"
          >
            <Eyebrow title="agent-rendered lens · asked across base · clients · nothing was withheld" />
            <p className="a-prose">No committed record, and nothing waits in the inbox for it.</p>
            <div className="explain">
              <span className="x-text">
                The vault holds nothing on this yet. It will say so, every time.
              </span>
              <a
                className="byline"
                data-agent="antevon"
                href="/app/agents"
                title="Antevon · the house mind · rendered 14:02"
              >
                Antevon
              </a>
            </div>
            <div className="a-foot">
              <Watch
                watched={watched.other}
                onWatch={() => setWatched((w) => ({ ...w, other: true }))}
              />
            </div>
          </section>
        )}
      </div>
    </main>
  )
}
