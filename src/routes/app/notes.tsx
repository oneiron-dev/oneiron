import * as React from 'react'
import { Link, createFileRoute } from '@tanstack/react-router'
import { cue, markCued, openChat, useEscape } from '~/components/safelight/hooks'
import notesCss from '~/styles/notes.css?url'

export const Route = createFileRoute('/app/notes')({
  head: () => ({
    links: [{ rel: 'stylesheet', href: notesCss }],
  }),
  component: Notes,
})

/* ── fixtures · the office notes (app-docs.html is content truth) ──
   humans stamp with seals (o · y); the house mind writes digests and
   handoffs and signs in its ink. a note is READ (rule 39): the document
   is the body of the sheet, the list is the one tinted zone. */
type By = 'o' | 'y' | 'antevon'
type Note = {
  id: string
  title: string
  by: By
  updated: string /* the short date, list + byline */
  when: string /* the full stamp, hover-tier */
  read: string
  pinned?: boolean
  recent?: boolean
  kind?: 'digest' | 'handoff'
  body: React.ReactNode
}

const PEOPLE = {
  o: { name: 'oleksii', tip: 'o · oleksii · owner' },
  y: { name: 'yurii', tip: 'y · yurii · member' },
} as const

function Sep() {
  return <span className="sep">·</span>
}

/* a claim citation: the sentence is backed; the phrase wears the claim's
   confidence as its ink, the exact numeral rides the title */
function Cite({
  id,
  conf,
  learned,
  children,
}: {
  id: string
  conf: number
  learned: string
  children: React.ReactNode
}) {
  const rung = conf >= 0.9 ? 'conf-1' : conf >= 0.7 ? 'conf-2' : conf >= 0.4 ? 'conf-3' : 'conf-4'
  return (
    <Link
      to="/app/vault"
      className={`cite ${rung}`}
      title={`${id} · ${conf.toFixed(2)} · learned ${learned} · open the claim in the vault`}
    >
      {children}
    </Link>
  )
}

const NOTES: Note[] = [
  {
    id: 'how-we-work',
    title: 'How we work',
    by: 'o',
    updated: 'Aug 12',
    when: '2026-08-12 · 16:40',
    read: '4 min',
    pinned: true,
    body: (
      <>
        <p>
          The first thing an agent reads before it acts in this vault. Short, current, and every
          load-bearing sentence carries its evidence.
        </p>
        <h3>Conventions</h3>
        <p>
          Forecast deliverables ship as briefs, never as loose spreadsheets.{' '}
          <Cite id="cl_44b1" conf={0.91} learned="2026-06-24">
            Client-facing numbers come from the model registry, not from memory
          </Cite>
          .
        </p>
        <p>
          <Cite id="cl_5c02" conf={0.94} learned="2026-05-30">
            Quotes go out within two business days of the ask
          </Cite>
          . Late means we say so before they notice, not after.
        </p>
        <h3>Before a client call</h3>
        <ul>
          <li>Read the org page and the last three threads.</li>
          <li>Check the pipeline stage and the next step written there.</li>
          <li>
            <Cite id="cl_61aa" conf={0.88} learned="2026-07-02">
              Bring the latest brief; the client has already seen the one before it
            </Cite>
            .
          </li>
        </ul>
        <h3>For agents</h3>
        <p>
          Read this note and the pilot scope before touching anything client-facing. Every outbound
          send is a human click. Edits to protected notes land as proposals; a person stamps before
          they commit.
        </p>
      </>
    ),
  },
  {
    id: 'forecast-conventions',
    title: 'Forecast conventions',
    by: 'o',
    updated: 'Jul 19',
    when: '2026-07-19 · 11:02',
    read: '2 min',
    pinned: true,
    body: (
      <>
        <p>How a forecast leaves this office.</p>
        <ul>
          <li>Units: pieces per week, never revenue, unless the client asks.</li>
          <li>Horizons: twelve weeks for a pilot, twenty-six for a contract.</li>
          <li>
            <Cite id="cl_1180" conf={0.93} learned="2026-06-10">
              Every number carries the model version it came from
            </Cite>
            .
          </li>
        </ul>
        <p>A forecast without its error band is a guess. Say the band.</p>
      </>
    ),
  },
  {
    id: 'hokuei-pilot-scope',
    title: 'Hokuei pilot scope',
    by: 'y',
    updated: 'Aug 14',
    when: '2026-08-14 · 18:21',
    read: '3 min',
    recent: true,
    body: (
      <>
        <p>
          What the Hokuei pilot covers, and what it does not. Yurii owns this note; Antevon reads it
          before any Hokuei work.
        </p>
        <h3>Scope</h3>
        <ul>
          <li>Three SKU families, weekly demand, a twelve-week horizon.</li>
          <li>One brief every Monday before 10:00 JST.</li>
          <li>
            <Cite id="cl_7d20" conf={0.95} learned="2026-08-01">
              The pilot runs to 2026-10-31
            </Cite>
            .
          </li>
        </ul>
        <h3>Out of scope</h3>
        <p>Supplier negotiations. Pricing advice. Anything the COO has not asked for in writing.</p>
        <h3>People</h3>
        <p>
          <Cite id="cl_2b91" conf={0.86} learned="2026-07-22">
            Mika Tanaka is the day-to-day contact
          </Cite>
          ; the COO joins the monthly review.
        </p>
      </>
    ),
  },
  {
    id: 'supplier-consolidation',
    title: 'Supplier consolidation, what we know',
    by: 'antevon',
    updated: 'Aug 14',
    when: '2026-08-14 03:12',
    read: '2 min',
    recent: true,
    kind: 'digest',
    body: (
      <>
        <p>
          What the vault holds on the Hokuei supplier question, in one place. Every sentence below
          is a claim you can open.
        </p>
        <h3>What we know</h3>
        <ul>
          <li>
            <Cite id="cl_31f0" conf={0.77} learned="2026-05-14">
              Hokuei has been expanding its supplier base since spring
            </Cite>
            .
          </li>
          <li>
            <Cite id="cl_9d17" conf={0.81} learned="2026-08-13">
              Hokuei may be consolidating suppliers this fiscal year
            </Cite>
            . This contradicts the line above; the newer claim waits in the inbox.
          </li>
          <li>
            <Cite id="cl_4e08" conf={0.90} learned="2026-08-06">
              Fourteen supplier accounts are active today
            </Cite>
            .
          </li>
        </ul>
        <h3>What we do not know</h3>
        <p>
          Which accounts would go first, and whether the COO has said this out loud. Two public
          filings are open; neither says consolidation.
        </p>
        <h3>Suggested next step</h3>
        <p>Ask Mika Tanaka on the Thursday call. A direct answer settles both claims.</p>
      </>
    ),
  },
  {
    id: 'nightly-handoff',
    title: 'Nightly handoff',
    by: 'antevon',
    updated: 'Aug 15',
    when: '2026-08-15 03:12',
    read: '1 min',
    recent: true,
    kind: 'handoff',
    body: (
      <>
        <p>For the next run. What the night did, in the order it did it.</p>
        <ul>
          <li>Forty-two claims went in on their own; two wait for review.</li>
          <li>The LinkedIn import paused itself at 180 writes.</li>
          <li>The Hokuei brief for Thursday is compiled and cites every claim under it.</li>
        </ul>
        <p>Start with the two held claims. Then resume the import once oleksii has cleared it.</p>
      </>
    ),
  },
  {
    id: 'onboarding-a-client',
    title: 'Onboarding a client',
    by: 'o',
    updated: 'Jul 28',
    when: '2026-07-28 · 09:15',
    read: '3 min',
    body: (
      <>
        <p>The first two weeks with a new client, step by step.</p>
        <h3>Week one</h3>
        <ul>
          <li>Sign the data agreement before any file moves.</li>
          <li>Get the last two years of sales, by SKU, by week.</li>
          <li>Name one contact on their side. Write it in the org page.</li>
        </ul>
        <h3>Week two</h3>
        <ul>
          <li>First baseline forecast, shared as a brief.</li>
          <li>One call to walk the brief. Take notes into the thread.</li>
        </ul>
      </>
    ),
  },
  {
    id: 'outreach-voice',
    title: 'Outreach voice',
    by: 'o',
    updated: 'Jun 30',
    when: '2026-06-30 · 22:08',
    read: '2 min',
    body: (
      <>
        <p>How we sound when we reach out. Eiri drafts in this voice; a person sends.</p>
        <ul>
          <li>Short. Two lines before the ask.</li>
          <li>Plain Japanese with the client, plain English inside.</li>
          <li>Name what we noticed about them, then what we offer. Never the other way round.</li>
        </ul>
        <p>Never promise a number in an intro. Numbers come from a brief.</p>
      </>
    ),
  },
  {
    id: 'pricing-notes-2026',
    title: 'Pricing notes 2026',
    by: 'y',
    updated: 'Jul 03',
    when: '2026-07-03 · 14:47',
    read: '2 min',
    body: (
      <>
        <p>Working notes, not a price list. The list lives in the contract template.</p>
        <p>
          <Cite id="cl_0a77" conf={0.74} learned="2026-06-28">
            Pilots run at cost; the contract price starts after week twelve
          </Cite>
          . We say this in the first call.
        </p>
        <p>Do not quote from memory. Ask Yurii, or open the contract template.</p>
      </>
    ),
  },
]

function byName(n: Note) {
  return n.by === 'antevon' ? 'antevon' : PEOPLE[n.by].name
}
function hhmm() {
  const d = new Date()
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
}

/* who wrote it: a seal for a human, the name in ink for the house mind */
function ByMark({ n }: { n: Note }) {
  if (n.by === 'antevon') {
    return (
      <span className="aname" data-agent="antevon" title="Antevon · the house mind">
        Antevon
      </span>
    )
  }
  const p = PEOPLE[n.by]
  return (
    <span className="seal seal-human" title={p.tip}>
      {n.by}
    </span>
  )
}

function Notes() {
  const [notes, setNotes] = React.useState<Note[]>(NOTES)
  const [sel, setSel] = React.useState<string>(NOTES[0].id)
  const [q, setQ] = React.useState('')
  const [editing, setEditing] = React.useState(false)
  const [dirty, setDirty] = React.useState<Record<string, string>>({})
  const [shared, setShared] = React.useState<string | null>(null)
  const [hintOpen, setHintOpen] = React.useState(false)
  const [empty, setEmpty] = React.useState(false)
  const bodyRef = React.useRef<HTMLDivElement>(null)

  /* fixtures always fill the list, so ?empty previews the empty state */
  React.useEffect(() => {
    setEmpty(new URLSearchParams(location.search).has('empty'))
  }, [])

  const note = notes.find((n) => n.id === sel) ?? null

  const select = (id: string) => () => {
    if (id === sel) return
    setSel(id)
    setEditing(false)
    setShared(null)
    cue('toggle')
  }

  /* edit = the body itself, quietly; esc or `done` ends it. the byline
     cools into the receipt: "updated just now" (no toast, ever) */
  const startEdit = (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setEditing(true)
    cue('toggle')
  }
  const endEdit = React.useCallback(() => {
    setEditing((on) => {
      if (on) cue('toggle')
      return false
    })
  }, [])
  React.useEffect(() => {
    if (!editing) return
    const el = bodyRef.current
    if (!el) return
    el.focus()
    /* a fresh note starts on one line: typing replaces it */
    if (note?.id.startsWith('new-') && !dirty[note.id]) {
      const range = document.createRange()
      range.selectNodeContents(el)
      const s = getSelection()
      s?.removeAllRanges()
      s?.addRange(range)
    }
  }, [editing, note, dirty])
  useEscape(() => {
    if (editing) endEdit()
    else setHintOpen(false)
  })

  const share = (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    try {
      navigator.clipboard?.writeText(location.href).catch(() => {
        /* no clipboard · the receipt still lands */
      })
    } catch {
      /* no clipboard · the receipt still lands */
    }
    setShared(hhmm())
    cue('success')
  }

  const newNote = (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    const id = `new-${Date.now()}`
    const fresh: Note = {
      id,
      title: 'Untitled',
      by: 'o',
      updated: hhmm(),
      when: `today ${hhmm()}`,
      read: '1 min',
      recent: true,
      body: <p>Write here.</p>,
    }
    setNotes((ns) => [fresh, ...ns])
    setEmpty(false)
    setSel(id)
    setShared(null)
    setEditing(true)
    cue('toggle')
  }

  /* the filter narrows every group; a group with nothing left hides */
  const needle = q.trim().toLowerCase()
  const match = (n: Note) =>
    !needle || n.title.toLowerCase().includes(needle) || byName(n).toLowerCase().includes(needle)
  const groups = [
    { label: 'pinned', rows: notes.filter((n) => n.pinned && match(n)) },
    { label: 'recent', rows: notes.filter((n) => !n.pinned && n.recent && match(n)) },
    { label: 'earlier', rows: notes.filter((n) => !n.pinned && !n.recent && match(n)) },
  ]
  const nothing = groups.every((g) => g.rows.length === 0)

  const isAgent = note?.by === 'antevon'
  const updatedWord = (note && dirty[note.id]) || note?.updated

  return (
    <main className="pane notes-pane">
      {/* the list · the one tinted zone */}
      <nav className="notes-list" aria-label="notes">
        {empty ? (
          <div className="notes-empty">
            <img className="spot" src="/art/spot-flock.png" width={150} alt="" />
            <span className="lead">No notes yet.</span>
            <a className="act" href="#" title="a blank note · yours" onClick={newNote}>
              + new note
            </a>
          </div>
        ) : (
          <>
            <div className="pane-head">
              <h1>Notes</h1>
            </div>
            <input
              className="notes-filter"
              type="text"
              placeholder="filter"
              aria-label="filter notes"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
            {groups.map(
              (g) =>
                g.rows.length > 0 && (
                  <div className="ngroup" key={g.label} role="group" aria-label={g.label}>
                    <span className="label">{g.label}</span>
                    {g.rows.map((n) => (
                      <button
                        key={n.id}
                        className={n.id === sel ? 'nrow sel' : 'nrow'}
                        aria-current={n.id === sel ? 'true' : undefined}
                        title={`${n.title} · ${byName(n)} · updated ${n.when}${
                          n.kind ? ` · ${n.kind}` : ''
                        }`}
                        onClick={select(n.id)}
                      >
                        <span className="ntitle">{n.title}</span>
                        <ByMark n={n} />
                        <span className="when">{dirty[n.id] || n.updated}</span>
                      </button>
                    ))}
                  </div>
                ),
            )}
            {nothing && <span className="nnone">Nothing matches.</span>}
            <div className="nfoot">
              <a className="act" href="#" title="a blank note · yours" onClick={newNote}>
                + new note
              </a>
            </div>
          </>
        )}
      </nav>

      {/* the document · the main read */}
      <div className="pane-body">
        {note && !empty && (
          <article className={editing ? 'doc editing' : 'doc'} key={note.id} aria-label={note.title}>
            {/* an agent-written note is an instrument: it names its kind */}
            {isAgent && (
              <div
                className="instrument-eyebrow"
                title="agent-rendered · Antevon writes this from the vault's claims"
              >
                <span>{note.kind}</span>
              </div>
            )}
            <div className="pane-head">
              <h1>{note.title}</h1>
              <span className="pane-tools">
                <button
                  className="hint-btn"
                  aria-expanded={hintOpen}
                  aria-controls="notes-why"
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
            {/* the byline: who wrote it, when it last moved, how long the read */}
            <div className="doc-by" title={isAgent ? undefined : `last updated ${note.when}`}>
              {isAgent ? (
                <span className="aname" data-agent="antevon" title="Antevon · the house mind">
                  Antevon
                </span>
              ) : (
                <span>{PEOPLE[note.by as 'o' | 'y'].name}</span>
              )}
              <Sep />
              <span>{isAgent ? `as of ${note.when}` : `updated ${updatedWord}`}</span>
              <Sep />
              <span>{note.read} read</span>
            </div>
            <div className="dial-why" id="notes-why" hidden={!hintOpen}>
              <span className="why-voice">
                Notes are what your agents read before they act. A dotted phrase rests on a claim
                in the vault. Hover it to see how sure the vault is.
              </span>
            </div>

            <div
              className="doc-body"
              ref={bodyRef}
              contentEditable={editing || undefined}
              suppressContentEditableWarning
              spellCheck={editing}
              role={editing ? 'textbox' : undefined}
              aria-multiline={editing || undefined}
              aria-label={editing ? `${note.title} · body` : undefined}
              onInput={() => {
                if (!dirty[note.id]) setDirty((d) => ({ ...d, [note.id]: hhmm() }))
              }}
            >
              {note.body}
            </div>

            <div className="doc-foot">
              {editing ? (
                <>
                  <a className="act" href="#" title="ends editing · esc does too" onClick={(e) => { e.preventDefault(); markCued(e); endEdit() }}>
                    done
                  </a>
                  <span className="meta-line">editing · esc ends</span>
                </>
              ) : (
                <a
                  className="act"
                  href="#"
                  title="edit in place · lands as a new revision, earlier ones stay"
                  onClick={startEdit}
                >
                  edit
                </a>
              )}
              {!editing &&
                (shared ? (
                  <span className="meta-line">link copied {shared}</span>
                ) : (
                  <a className="act" href="#" title="copies a read link" onClick={share}>
                    share
                  </a>
                ))}
              {!editing && (
                <a
                  className="act"
                  href="#"
                  title="opens the chat panel with this note in reach"
                  onClick={(e) => {
                    e.preventDefault()
                    openChat('ask')
                  }}
                >
                  ask about this note
                </a>
              )}
            </div>
          </article>
        )}
      </div>
    </main>
  )
}
