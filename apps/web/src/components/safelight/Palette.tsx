import * as React from 'react'
import { useNavigate } from '@tanstack/react-router'
import {
  IconAgents,
  IconBriefs,
  IconChat,
  IconInbox,
  IconNotes,
  IconOrgs,
  IconPipeline,
  IconSearch,
  IconSound,
  IconSupplierWatch,
  IconTasks,
  IconTheme,
  IconThreads,
  IconToday,
  IconTuner,
  IconVault,
} from './icons'
import { Throbber } from './Widgets'
import {
  applyTheme,
  cue,
  openChat,
  readSound,
  readTheme,
  useDocumentEvent,
  useEscape,
  useSound,
  type Theme,
} from './hooks'

/* ── the command palette (owner 08-18, ruling 9 + the search ruling):
   ⌘K, `/`, or the rail's search icon open the SAME card. a floating card
   over the desk, NOT a modal — no backdrop, click outside or Esc closes.
   one serif field; the pages, the claims and the acts filter as you type,
   and an ask row is always there: the question you typed, handed to
   Antevon. Enter on it turns the card into the answer. ── */

type Group = 'pages' | 'claims' | 'acts' | 'ask'

type Item = {
  id: string
  group: Group
  title: string
  keys?: string       /* extra words the filter may match */
  icon?: React.ReactNode
  conf?: 1 | 2 | 3 | 4
  meta?: string       /* mono, right-aligned; the act's current state */
  run: () => void
}

/* the vault's claims — the same six fixtures the ledger carries */
const CLAIMS: { text: string; conf: 1 | 2 | 3 | 4; pred: string }[] = [
  { text: 'Sasha moved from Berlin to Lisbon', conf: 1, pred: 'person.location' },
  { text: 'Yuki prefers async reviews over live calls', conf: 1, pred: 'person.preference' },
  { text: 'Antevon pilot decision expected by July 18', conf: 2, pred: 'org.milestone' },
  { text: 'Prefers briefing digests merged, not one ping per item', conf: 2, pred: 'person.preference' },
  { text: 'May be allergic to shellfish', conf: 3, pred: 'person.health' },
  { text: 'Runs the weather book on Polymarket with a hard daily loss cap', conf: 1, pred: 'person.venture' },
]

const PAGES: { to: string; title: string; icon: React.ReactNode; keys?: string }[] = [
  { to: '/app/inbox', title: 'inbox', icon: <IconInbox /> },
  { to: '/app/vault', title: 'vault', icon: <IconVault />, keys: 'ledger claims board graph' },
  { to: '/app/agents', title: 'agents', icon: <IconAgents />, keys: 'eiri tory antevon runs' },
  { to: '/app/pipeline', title: 'pipeline', icon: <IconPipeline />, keys: 'crm deals board' },
  { to: '/app/today', title: 'today', icon: <IconToday />, keys: 'crm' },
  { to: '/app/orgs', title: 'orgs', icon: <IconOrgs />, keys: 'crm companies' },
  { to: '/app/notes', title: 'notes', icon: <IconNotes />, keys: 'office' },
  { to: '/app/briefs', title: 'briefs', icon: <IconBriefs />, keys: 'office' },
  { to: '/app/tasks', title: 'tasks', icon: <IconTasks />, keys: 'office' },
  { to: '/app/threads', title: 'threads', icon: <IconThreads />, keys: 'channels slack line mail' },
  { to: '/app/lens/supplier-watch', title: 'supplier watch', icon: <IconSupplierWatch />, keys: 'lens' },
  { to: '/app/recall', title: 'search the vault', icon: <IconSearch />, keys: 'recall find answer ask /' },
]

const THEME_NEXT: Record<Theme, Theme> = { system: 'light', light: 'dark', dark: 'system' }
const THEME_GLYPH: Record<Theme, string> = { light: '○ light', system: '◐ system', dark: '● dark' }

/* ── the answer the card prints. the cast is recall's: the same claims,
   the same clock, the same two states. the card carries the short form;
   recall stays the full read. ── */
const AS_OF = '08-13 14:02'

type Stand = { id: string; conf: number; claim: string; to: string; title: string }
type Answer = { prose: string; stands: Stand[]; stood: string }

const HOKUEI: Answer = {
  prose:
    'A six-week pilot, starting the first week of September. Yuki owes Mika the formal quote by Tuesday. The scope stands at the ¥380,000 desk floor agreed in May.',
  stood: 'what it stands on',
  stands: [
    {
      id: 'cl_9f21',
      conf: 0.94,
      claim: 'The pilot runs six weeks from the first week of September',
      to: '/app/vault',
      title: 'cl_9f21 · 0.94 · occurred 08-08 · the call note',
    },
    {
      id: 'cl_a04c',
      conf: 0.91,
      claim: 'Yuki sends the formal quote by Tuesday',
      to: '/app/vault',
      title: 'cl_a04c · 0.91 · occurred 08-12 · the LINE thread',
    },
    {
      id: 'cl_77b8',
      conf: 0.84,
      claim: 'The desk floor is ¥380,000 a month, scoped',
      to: '/app/vault',
      title: 'cl_77b8 · 0.84 · occurred 05-30 · learned 08-05 · the mail archive',
    },
  ],
}

const THIN: Answer = {
  prose:
    'No committed record. One proposed claim waits in the inbox. Until you accept it, this answer stays empty.',
  stood: 'what waits',
  stands: [
    {
      id: 'cl_58aa',
      conf: 0.52,
      claim: 'May be allergic to shellfish',
      to: '/app/inbox',
      title: 'cl_58aa · 0.52 · one mention, April · held for review',
    },
  ],
}

/* the fixture vault answers the Hokuei ask in full; everything else
   prints thin and true, exactly as recall does */
function answerFor(q: string): Answer {
  const s = q.toLowerCase()
  if (/shellfish|allerg/.test(s)) return THIN
  return /hokuei|promise|pilot|timeline|quote/.test(s) ? HOKUEI : THIN
}

/* confidence = ink (silver-1 ≥.9 · silver-2 .7–.89 · silver-3 .4–.69 · silver-4 <.4) */
function confClass(conf: number) {
  return conf >= 0.9 ? 'conf-1' : conf >= 0.7 ? 'conf-2' : conf >= 0.4 ? 'conf-3' : 'conf-4'
}

type Phase = 'list' | 'thinking' | 'answer'

export function Palette({
  open,
  onClose,
  onTuner,
}: {
  open: boolean
  onClose: () => void
  onTuner?: () => void
}) {
  const navigate = useNavigate()
  const toggleSound = useSound()
  const inputRef = React.useRef<HTMLInputElement>(null)
  const listRef = React.useRef<HTMLDivElement>(null)
  const ansRef = React.useRef<HTMLDivElement>(null)
  const cameFrom = React.useRef<HTMLElement | null>(null)
  const timer = React.useRef<ReturnType<typeof setTimeout> | null>(null)
  const [q, setQ] = React.useState('')
  const [sel, setSel] = React.useState(0)
  /* the card has three states: the list you type into, the moment the
     house mind reads, and the answer it prints */
  const [phase, setPhase] = React.useState<Phase>('list')
  const [asked, setAsked] = React.useState('')
  /* the theme's state is read from <html> after mount; SSR renders 'system' */
  const [theme, setTheme] = React.useState<Theme>('system')
  const [sound, setSound] = React.useState(true)

  const stopThinking = React.useCallback(() => {
    if (timer.current) clearTimeout(timer.current)
    timer.current = null
  }, [])
  React.useEffect(() => stopThinking, [stopThinking])

  /* opening: a clean field, the current states, the caret. closing: the
     work you were in gets its focus back, so ⌘K never costs your place. */
  React.useEffect(() => {
    if (!open) {
      /* dismissed mid-read: the answer never lands behind a closed card */
      stopThinking()
      const back = cameFrom.current
      cameFrom.current = null
      if (back && back.isConnected) back.focus()
      return
    }
    const active = document.activeElement
    cameFrom.current = active instanceof HTMLElement && active !== document.body ? active : null
    stopThinking()
    setQ('')
    setSel(0)
    setPhase('list')
    setAsked('')
    setTheme(readTheme())
    setSound(readSound())
    requestAnimationFrame(() => inputRef.current?.focus())
  }, [open, stopThinking])

  /* the answer takes the keys when it lands, so Tab reaches its doors */
  React.useEffect(() => {
    if (!open || phase === 'list') return
    requestAnimationFrame(() => ansRef.current?.focus())
  }, [open, phase])

  /* the ask: the typed question goes to the house mind, the card reads
     for a moment, then it prints. an empty field opens the chat instead. */
  const ask = React.useCallback(() => {
    const question = q.trim()
    if (!question) {
      onClose()
      openChat('ask')
      return
    }
    cue('press')
    setAsked(question)
    setPhase('thinking')
    stopThinking()
    timer.current = setTimeout(() => {
      timer.current = null
      setPhase('answer')
      cue('success')
    }, 700)
  }, [q, onClose, stopThinking])

  /* back to the list, with what you typed still in the field */
  const toList = React.useCallback(() => {
    stopThinking()
    setPhase('list')
    setSel(0)
    requestAnimationFrame(() => inputRef.current?.focus())
  }, [stopThinking])

  /* Esc peels one layer: the answer first, then the card */
  useEscape(() => {
    if (!open) return
    if (phase !== 'list') toList()
    else onClose()
  })
  useDocumentEvent('click', (e) => {
    if (!open) return
    const t = e.target as HTMLElement | null
    if (t?.closest('.palette')) return
    onClose()
  })

  const go = React.useCallback(
    (to: string) => {
      onClose()
      if (location.pathname + location.search !== to) navigate({ href: to })
    },
    [navigate, onClose],
  )

  const items = React.useMemo<Item[]>(() => {
    const pages: Item[] = PAGES.map((p) => ({
      id: `page:${p.to}`,
      group: 'pages',
      title: p.title,
      keys: p.keys,
      icon: p.icon,
      run: () => go(p.to),
    }))
    const claims: Item[] = CLAIMS.map((c, i) => ({
      id: `claim:${i}`,
      group: 'claims',
      title: c.text,
      keys: c.pred,
      conf: c.conf,
      run: () => go('/app/vault'),
    }))
    const acts: Item[] = [
      {
        id: 'act:chat',
        group: 'acts',
        title: 'new chat',
        keys: 'ask agent eiri tory',
        icon: <IconChat />,
        run: () => {
          onClose()
          openChat('ask')
        },
      },
      {
        id: 'act:theme',
        group: 'acts',
        title: 'theme',
        keys: 'light dark system room',
        icon: <IconTheme />,
        meta: THEME_GLYPH[theme],
        run: () => {
          const next = THEME_NEXT[readTheme()]
          applyTheme(next)
          setTheme(next)
          cue('toggle')
        },
      },
      {
        id: 'act:sound',
        group: 'acts',
        title: 'sound',
        keys: 'mute cue',
        icon: <IconSound />,
        meta: sound ? 'on' : 'off',
        run: () => {
          toggleSound()
          setSound((s) => !s)
        },
      },
    ]
    if (onTuner) {
      acts.push({
        id: 'act:tuner',
        group: 'acts',
        title: 'tuner',
        keys: 'dev instrument measures',
        icon: <IconTuner />,
        run: () => {
          onClose()
          onTuner()
        },
      })
    }
    return [...pages, ...claims, ...acts]
  }, [go, onClose, onTuner, theme, sound, toggleSound])

  const needle = q.trim().toLowerCase()

  const matches = React.useMemo(() => {
    if (!needle) return items
    return items.filter(
      (it) =>
        it.title.toLowerCase().includes(needle) ||
        (it.keys ?? '').toLowerCase().includes(needle) ||
        /* a group name matches only from three letters, or one letter
           would drag in every claim ("claims" holds an a, an i, an s) */
        (needle.length > 2 && it.group.includes(needle)),
    )
  }, [items, needle])

  /* the ask row is always in the list. it leads while you are writing a
     question; it steps aside the moment you have named a page or an act. */
  const named = matches.some(
    (it) => (it.group === 'pages' || it.group === 'acts') && it.title.toLowerCase() === needle,
  )
  const askItem: Item = { id: 'ask', group: 'ask', title: 'ask', run: ask }
  const leads = needle.length >= 3 && !named
  const shown = leads ? [askItem, ...matches] : [...matches, askItem]

  /* the selection never points past the list */
  const selIndex = shown.length ? Math.min(sel, shown.length - 1) : -1

  React.useEffect(() => {
    if (selIndex < 0 || phase !== 'list') return
    const el = listRef.current?.querySelector<HTMLElement>(`[data-i="${selIndex}"]`)
    el?.scrollIntoView({ block: 'nearest' })
  }, [selIndex, phase])

  const onKey = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (phase !== 'list') return
    /* ⌘↵ asks from anywhere in the card, whatever row is under the caret */
    if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
      e.preventDefault()
      ask()
      return
    }
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      if (shown.length) setSel((s) => (Math.min(s, shown.length - 1) + 1) % shown.length)
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      if (shown.length) setSel((s) => (Math.min(s, shown.length - 1) - 1 + shown.length) % shown.length)
    } else if (e.key === 'Home') {
      e.preventDefault()
      setSel(0)
    } else if (e.key === 'End') {
      e.preventDefault()
      if (shown.length) setSel(shown.length - 1)
    } else if (e.key === 'Enter') {
      e.preventDefault()
      if (selIndex >= 0) {
        if (shown[selIndex].group !== 'ask') cue('press')
        shown[selIndex].run()
      }
    }
  }

  /* group the visible rows, keeping the flat index for the keys */
  const groups: { name: Group; rows: { it: Item; i: number }[] }[] = []
  shown.forEach((it, i) => {
    const last = groups[groups.length - 1]
    if (last && last.name === it.group) last.rows.push({ it, i })
    else groups.push({ name: it.group, rows: [{ it, i }] })
  })

  const answer = answerFor(asked)

  return (
    <div
      className="palette"
      hidden={!open}
      role="dialog"
      aria-label="search or ask"
      onKeyDown={onKey}
    >
      {phase === 'list' ? (
        <>
          <input
            ref={inputRef}
            className="pal-input"
            type="text"
            value={q}
            placeholder="search or ask Antevon"
            aria-label="search or ask Antevon"
            autoComplete="off"
            spellCheck={false}
            role="combobox"
            aria-autocomplete="list"
            aria-expanded={open}
            aria-controls="pal-list"
            aria-activedescendant={selIndex >= 0 ? `prow-${selIndex}` : undefined}
            onChange={(e) => {
              setQ(e.target.value)
              setSel(0)
            }}
          />
          <div className="pal-list" id="pal-list" ref={listRef} role="listbox" aria-label="results">
            {groups.map((g) => (
              <div className="pal-group" key={g.name} role="group" aria-label={g.name}>
                {/* the ask row names itself; it needs no label above it */}
                {g.name !== 'ask' ? (
                  <span className="label" aria-hidden="true">{g.name}</span>
                ) : null}
                {g.rows.map(({ it, i }) => (
                  <button
                    key={it.id}
                    type="button"
                    role="option"
                    id={`prow-${i}`}
                    aria-selected={i === selIndex}
                    aria-label={it.group === 'ask' ? `ask Antevon ${q.trim()}`.trim() : undefined}
                    tabIndex={-1}
                    data-i={i}
                    className={`prow${i === selIndex ? ' sel' : ''}${it.conf ? ` claim conf-${it.conf}` : ''}${it.group === 'ask' ? ' ask' : ''}`}
                    onMouseMove={() => {
                      if (sel !== i) setSel(i)
                    }}
                    /* the caret never leaves the field: the row acts, the
                       field keeps the keys */
                    onMouseDown={(e) => e.preventDefault()}
                    onClick={() => {
                      if (it.group !== 'ask') cue('press')
                      it.run()
                    }}
                  >
                    {it.group === 'ask' ? (
                      <>
                        <span className="pverb">ask</span>
                        <span className="aname" data-agent="antevon">
                          Antevon
                        </span>
                        {q.trim() ? (
                          <>
                            <span className="psep" aria-hidden="true">·</span>
                            <span className="pq">{`“${q.trim()}”`}</span>
                          </>
                        ) : null}
                        <kbd>⌘↵</kbd>
                      </>
                    ) : (
                      <>
                        {it.icon ? (
                          <span className="vico" aria-hidden="true">
                            {it.icon}
                          </span>
                        ) : null}
                        <span className="ptitle">{it.title}</span>
                        {it.meta ? <span className="meta-line">{it.meta}</span> : null}
                      </>
                    )}
                  </button>
                ))}
              </div>
            ))}
            {matches.length === 0 ? <p className="pal-empty">Nothing matches.</p> : null}
          </div>
        </>
      ) : (
        <div
          className="pal-answer"
          ref={ansRef}
          tabIndex={-1}
          role="region"
          aria-live="polite"
          aria-label="the answer"
        >
          <h2 className="pa-q">{asked}</h2>

          {phase === 'thinking' ? (
            <p className="pa-think">
              <Throbber />{' '}
              <span className="aname" data-agent="antevon">
                Antevon
              </span>{' '}
              is reading the vault
            </p>
          ) : (
            <>
              <span className="pa-by" title="Antevon · the house mind rendered this answer">
                <span className="aname" data-agent="antevon">
                  Antevon
                </span>
                {` · as of ${AS_OF}`}
              </span>

              <p className="pa-prose">{answer.prose}</p>

              <div className="pa-stood">
                <span className="label">{answer.stood}</span>
                {answer.stands.map((s) => (
                  <a
                    key={s.id}
                    className={`pa-claim ${confClass(s.conf)}`}
                    href={s.to}
                    title={s.title}
                    onClick={(e) => {
                      e.preventDefault()
                      go(s.to)
                    }}
                  >
                    <span className="pc-text">{s.claim}</span>
                    <span className="pc-conf">{s.conf.toFixed(2)}</span>
                  </a>
                ))}
              </div>

              <div className="pa-foot">
                <a
                  className="act"
                  href={`/app/recall?q=${encodeURIComponent(asked)}`}
                  title="the full read: what made the cut, what was withheld, the receipt"
                  onClick={(e) => {
                    e.preventDefault()
                    go(`/app/recall?q=${encodeURIComponent(asked)}`)
                  }}
                >
                  open in recall
                </a>
                <a
                  className="act"
                  href="#"
                  title="carry this question into the chat"
                  onClick={(e) => {
                    e.preventDefault()
                    onClose()
                    openChat('ask')
                  }}
                >
                  ask in chat
                </a>
                <button className="act" type="button" onClick={toList}>
                  back
                </button>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}

/* ── the shortcut sheet: hold ⌘ for a moment and the keys show, bottom
   right above the agent line; let go and it is gone. ── */
const KEYS: [string, string][] = [
  ['/', 'search or ask'],
  ['⌘K', 'palette'],
  ['t', 'theme'],
  ['m', 'sound'],
  ['Esc', 'close'],
  ['↑↓', 'move'],
  ['⏎', 'open'],
  ['[', 'fold the rail'],
]

export function ShortcutSheet({ shown, includeRail = true }: { shown: boolean; includeRail?: boolean }) {
  /* the chat panel owns the bottom right corner. when it is open the
     sheet steps to its left instead of landing on top of it. */
  const [beside, setBeside] = React.useState(false)
  React.useEffect(() => {
    if (shown) setBeside(!!document.querySelector('.gsheet.on'))
  }, [shown])

  return (
    <div
      className={beside ? 'keysheet beside-chat' : 'keysheet'}
      hidden={!shown}
      aria-hidden={!shown}
    >
      {KEYS.filter(([k]) => includeRail || k !== '[').map(([k, what]) => (
        <div className="krow" key={k}>
          <kbd>{k}</kbd>
          <span className="kwhat">{what}</span>
        </div>
      ))}
    </div>
  )
}
