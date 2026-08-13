import * as React from 'react'
import { Chevron, IconHistory } from './icons'
import { Cwidget, Throbber } from './Widgets'
import { cue, useDocumentEvent, useEscape } from './hooks'

/* ── the ground line + the chat PANEL (owner 08-15, the Linear shape):
   the chat floats up from the line's right corner as one elevated
   object over the desk — the full-width unfold read as a wall. "new
   chat" shows the thread + a GenUI block; a run on the line opens the
   SAME panel scoped to that run (its metadata rides the name's
   tooltip). esc, ×, and a click on the desk close it. ── */
const RUNS: Record<string, { name: string; tip: string; doing: string; voice: string; meta: string }> = {
  eiri: {
    name: 'Eiri',
    tip: 'Eiri · outbound',
    doing: 'Drafting the COO intro',
    voice: 'Trimming the intro to two lines; the scope note citation held.',
    meta: '2m 14s · 12k tokens · $0.04',
  },
  tory: {
    name: 'Tory',
    tip: 'Tory · research',
    doing: 'Checking the supplier rumor',
    voice: 'Two filings open so far; neither of them says consolidation.',
    meta: '6m 02s · 31k tokens · $0.11',
  },
}
const AGENTS: Record<string, string> = { eiri: 'Eiri', tory: 'Tory', antevon: 'Antevon' }

/* past chats, by age (the history popover fixture) */
const HISTORY: Array<{ label: string; rows: Array<{ title: string; age: string }> }> = [
  {
    label: 'today',
    rows: [
      { title: 'The Hokuei quote', age: '1h' },
      { title: 'Supplier rumor', age: '3h' },
    ],
  },
  {
    label: 'earlier',
    rows: [
      { title: 'Pilot scope', age: '6d' },
      { title: 'Vault import quotas', age: '12d' },
    ],
  },
]

export function Ground() {
  const inputRef = React.useRef<HTMLInputElement>(null)
  const [openRun, setOpenRun] = React.useState<string | null>(null)
  const openRunRef = React.useRef<string | null>(null)
  /* the threads keep their last scope through the close, exactly as the
     mock did: it only re-points them on the way open */
  const [scope, setScope] = React.useState<string>('ask')
  const [sheetAgent, setSheetAgent] = React.useState<string | undefined>(undefined)
  const [chip, setChip] = React.useState('eiri')
  const [amenuOpen, setAmenuOpen] = React.useState(false)
  const [cmdOpen, setCmdOpen] = React.useState(false)
  const [hmenuOpen, setHmenuOpen] = React.useState(false)
  const [draft, setDraft] = React.useState('')

  React.useEffect(() => {
    openRunRef.current = openRun
  }, [openRun])

  const showRun = React.useCallback((name: string) => {
    const same = openRunRef.current === name
    if (!same) {
      const ask = name === 'ask'
      if (!ask && !RUNS[name]) return
      setScope(name)
      if (!ask) setChip(name)
      setSheetAgent(name)
    }
    const next = same ? null : name
    openRunRef.current = next
    setOpenRun(next)
    if (!same) setTimeout(() => inputRef.current?.focus(), 130)
    cue('toggle')
  }, [])

  const closeRun = React.useCallback(() => {
    setAmenuOpen(false)
    setCmdOpen(false)
    setHmenuOpen(false)
    if (openRunRef.current === null) return
    openRunRef.current = null
    setOpenRun(null)
    cue('toggle')
  }, [])

  useEscape(closeRun)
  useDocumentEvent('click', (e) => {
    if (!(e.target as HTMLElement | null)?.closest('.ground')) closeRun()
  })
  useDocumentEvent('click', (e) => {
    if (!(e.target as HTMLElement | null)?.closest('.agent-chip')) setAmenuOpen(false)
  })
  useDocumentEvent('click', (e) => {
    const target = e.target as HTMLElement | null
    if (!target?.closest('.hmenu') && !target?.closest('.ghist')) setHmenuOpen(false)
  })

  const pick = (agent: string) => {
    setChip(agent)
    setAmenuOpen(false)
    inputRef.current?.focus()
    cue('press')
  }

  const ask = scope === 'ask'
  const run = ask ? undefined : RUNS[scope]

  return (
    <div className="ground">
      <div className={openRun ? 'gsheet on' : 'gsheet'} id="gsheet" data-agent={sheetAgent}>
        <div>
          <div className="ginner" id="gchat">
            {/* the panel head: the scope in one quiet line. a run wears
                its name + what it is doing + the run verbs; × closes. */}
            <div className="chat-head">
              {ask ? (
                <span className="chat-title">new chat</span>
              ) : (
                <>
                  <span
                    className="aname"
                    data-agent={scope}
                    title={run ? `${run.tip} · ${run.meta}` : undefined}
                  >
                    {run?.name}
                  </span>
                  <span className="cdoing">{run?.doing}</span>
                  <Throbber />
                  <span className="chat-acts">
                    <a className="act" href="#" title="verb: pause_run">
                      pause
                    </a>
                    <a className="act" href="#" title="verb: cancel_run">
                      cancel
                    </a>
                  </span>
                </>
              )}
              <button className="chat-close" aria-label="close the chat" title="close · esc" onClick={closeRun}>
                ×
              </button>
            </div>
            {/* new chat: the thread scrolls; an agent can send a widget */}
            <div className="chat-thread" data-thread="ask" hidden={!ask}>
              <div className="cmsg">
                <span className="seal seal-human" title="o · Owen">
                  o
                </span>
                <span className="ctext">When is the Hokuei call?</span>
              </div>
              <div className="cmsg">
                <span className="aname" data-agent="eiri">
                  Eiri
                </span>
                <span className="ctext">Thursday at 10:00. The brief is ready.</span>
              </div>
              <Cwidget
                title="Hokuei pilot call"
                line="Thursday 10:00 · the brief cites its claims"
              >
                <a className="act" href="#">
                  open brief
                </a>
              </Cwidget>
            </div>
            {/* a run on the line opens the SAME chat, scoped to that run */}
            <div className="chat-thread" data-thread="run" hidden={ask}>
              <div className="cmsg">
                <span className="ctext">
                  {run
                    ? run.voice
                    : 'Trimming the intro to two lines; the scope note citation held.'}
                </span>
              </div>
            </div>
            <div className="chat-line">
              <button
                className="agent-chip"
                aria-expanded={amenuOpen}
                aria-haspopup="menu"
                title="who picks this up · click to switch"
                onClick={() => {
                  setAmenuOpen((open) => !open)
                  setCmdOpen(false)
                  cue('toggle')
                }}
              >
                <span className="aname" data-agent={chip}>
                  {AGENTS[chip]}
                </span>
                <Chevron size={8} />
              </button>
              <input
                className="gask-input"
                type="text"
                placeholder={`message ${AGENTS[chip]} · / for commands`}
                aria-label="message the agent"
                ref={inputRef}
                value={draft}
                onChange={(e) => {
                  setDraft(e.target.value)
                  setCmdOpen(e.target.value.startsWith('/'))
                }}
              />
            </div>
          </div>
          {/* the switcher + / commands pop above the input row, anchored
              to the panel itself */}
          <div className="amenu" id="amenu" hidden={!amenuOpen} role="menu" aria-label="agents">
            <span className="label">agents</span>
            <button
              className={chip === 'eiri' ? 'vrow on' : 'vrow'}
              role="menuitem"
              onClick={() => pick('eiri')}
            >
              <span className="aname" data-agent="eiri">
                Eiri
              </span>
              <span className="meta-line">outbound</span>
            </button>
            <button
              className={chip === 'tory' ? 'vrow on' : 'vrow'}
              role="menuitem"
              onClick={() => pick('tory')}
            >
              <span className="aname" data-agent="tory">
                Tory
              </span>
              <span className="meta-line">research</span>
            </button>
            <button
              className={chip === 'antevon' ? 'vrow on' : 'vrow'}
              role="menuitem"
              onClick={() => pick('antevon')}
            >
              <span className="aname" data-agent="antevon">
                Antevon
              </span>
              <span className="meta-line">the vault</span>
            </button>
          </div>
          <div className="cmdpop" id="cmdpop" hidden={!cmdOpen}>
            <span className="label">commands</span>
            <span className="vrow">
              <span className="vname">/recall</span>
              <span className="meta-line">search the vault</span>
            </span>
            <span className="vrow">
              <span className="vname">/brief</span>
              <span className="meta-line">compile a brief</span>
            </span>
            <span className="vrow">
              <span className="vname">/handoff</span>
              <span className="meta-line">give this to another agent</span>
            </span>
          </div>
        </div>
      </div>
      {/* past chats, by age (owner 08-15: history is an icon, far right) */}
      <div className="hmenu" id="hmenu" hidden={!hmenuOpen} role="menu" aria-label="past chats">
        {HISTORY.map((group) => (
          <React.Fragment key={group.label}>
            <span className="label">{group.label}</span>
            {group.rows.map((row) => (
              <button
                key={row.title}
                className="hrow"
                role="menuitem"
                onClick={() => {
                  setHmenuOpen(false)
                  if (openRunRef.current !== 'ask') showRun('ask')
                }}
              >
                <span className="htitle">{row.title}</span>
                <span className="meta-line">{row.age}</span>
              </button>
            ))}
          </React.Fragment>
        ))}
      </div>
      <div className="gline">
        <span className="gspacer"></span>
        <button
          className="grun"
          data-agent="eiri"
          title="Eiri · drafting the COO intro · click: open the run"
          onClick={() => showRun('eiri')}
        >
          <span className="gdot"></span>
          <span>eiri · drafting the COO intro</span>
          <Throbber />
        </button>
        <button
          className="grun"
          data-agent="tory"
          title="Tory · checking the supplier rumor · click: open the run"
          onClick={() => showRun('tory')}
        >
          <span className="gdot"></span>
          <span>tory · checking filings</span>
        </button>
        <button className="grun" data-agent="ask" title="start a new chat" onClick={() => showRun('ask')}>
          <span className="gplus">+</span>
          <span>new chat</span>
        </button>
        <button
          className="grun ghist"
          aria-label="history"
          aria-expanded={hmenuOpen}
          aria-haspopup="menu"
          title="past chats and runs"
          onClick={() => {
            setHmenuOpen((open) => !open)
            cue('toggle')
          }}
        >
          <IconHistory />
        </button>
      </div>
    </div>
  )
}
