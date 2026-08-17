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

/* ── the command palette (owner 08-18, ruling 9): ⌘K from anywhere.
   a floating card over the desk, NOT a modal — no backdrop, click
   outside or Esc closes. one serif field; three groups: the pages of
   the rail (their icons), the claims of the vault in confidence ink,
   the acts. typing filters, ↑/↓ moves, Enter runs. ── */

type Group = 'pages' | 'claims' | 'acts'

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
  { text: 'Yurii prefers async reviews over live calls', conf: 1, pred: 'person.preference' },
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
  { to: '/app/recall', title: 'search the vault', icon: <IconSearch />, keys: 'recall find /' },
]

const THEME_NEXT: Record<Theme, Theme> = { system: 'light', light: 'dark', dark: 'system' }
const THEME_GLYPH: Record<Theme, string> = { light: '○ light', system: '◐ system', dark: '● dark' }

export function Palette({
  open,
  onClose,
  onTuner,
}: {
  open: boolean
  onClose: () => void
  onTuner: () => void
}) {
  const navigate = useNavigate()
  const toggleSound = useSound()
  const inputRef = React.useRef<HTMLInputElement>(null)
  const listRef = React.useRef<HTMLDivElement>(null)
  const cameFrom = React.useRef<HTMLElement | null>(null)
  const [q, setQ] = React.useState('')
  const [sel, setSel] = React.useState(0)
  /* the theme's state is read from <html> after mount; SSR renders 'system' */
  const [theme, setTheme] = React.useState<Theme>('system')
  const [sound, setSound] = React.useState(true)

  /* opening: a clean field, the current states, the caret. closing: the
     work you were in gets its focus back, so ⌘K never costs your place. */
  React.useEffect(() => {
    if (!open) {
      const back = cameFrom.current
      cameFrom.current = null
      if (back && back.isConnected) back.focus()
      return
    }
    const active = document.activeElement
    cameFrom.current = active instanceof HTMLElement && active !== document.body ? active : null
    setQ('')
    setSel(0)
    setTheme(readTheme())
    setSound(readSound())
    requestAnimationFrame(() => inputRef.current?.focus())
  }, [open])

  useEscape(() => {
    if (open) onClose()
  })
  useDocumentEvent('click', (e) => {
    if (!open) return
    const t = e.target as HTMLElement | null
    if (t?.closest('.palette')) return
    onClose()
  })

  const items = React.useMemo<Item[]>(() => {
    const go = (to: string) => () => {
      onClose()
      if (location.pathname !== to) navigate({ href: to })
    }
    const pages: Item[] = PAGES.map((p) => ({
      id: `page:${p.to}`,
      group: 'pages',
      title: p.title,
      keys: p.keys,
      icon: p.icon,
      run: go(p.to),
    }))
    const claims: Item[] = CLAIMS.map((c, i) => ({
      id: `claim:${i}`,
      group: 'claims',
      title: c.text,
      keys: c.pred,
      conf: c.conf,
      run: go('/app/vault'),
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
      {
        id: 'act:tuner',
        group: 'acts',
        title: 'tuner',
        keys: 'dev instrument measures',
        icon: <IconTuner />,
        run: () => {
          onClose()
          onTuner()
        },
      },
    ]
    return [...pages, ...claims, ...acts]
  }, [navigate, onClose, onTuner, theme, sound, toggleSound])

  const shown = React.useMemo(() => {
    const needle = q.trim().toLowerCase()
    if (!needle) return items
    return items.filter(
      (it) =>
        it.title.toLowerCase().includes(needle) ||
        (it.keys ?? '').toLowerCase().includes(needle) ||
        /* a group name matches only from three letters, or one letter
           would drag in every claim ("claims" holds an a, an i, an s) */
        (needle.length > 2 && it.group.includes(needle)),
    )
  }, [items, q])

  /* the selection never points past the list */
  const selIndex = shown.length ? Math.min(sel, shown.length - 1) : -1

  React.useEffect(() => {
    if (selIndex < 0) return
    const el = listRef.current?.querySelector<HTMLElement>(`[data-i="${selIndex}"]`)
    el?.scrollIntoView({ block: 'nearest' })
  }, [selIndex])

  const onKey = (e: React.KeyboardEvent<HTMLDivElement>) => {
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
        cue('press')
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

  return (
    <div
      className="palette"
      hidden={!open}
      role="dialog"
      aria-label="command palette"
      onKeyDown={onKey}
    >
      <input
        ref={inputRef}
        className="pal-input"
        type="text"
        value={q}
        placeholder="search the vault, a page, an act"
        aria-label="search the vault, a page, an act"
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
            <span className="label" aria-hidden="true">{g.name}</span>
            {g.rows.map(({ it, i }) => (
              <button
                key={it.id}
                type="button"
                role="option"
                id={`prow-${i}`}
                aria-selected={i === selIndex}
                tabIndex={-1}
                data-i={i}
                className={`prow${i === selIndex ? ' sel' : ''}${it.conf ? ` claim conf-${it.conf}` : ''}`}
                onMouseMove={() => {
                  if (sel !== i) setSel(i)
                }}
                /* the caret never leaves the field: the row acts, the
                   field keeps the keys */
                onMouseDown={(e) => e.preventDefault()}
                onClick={() => {
                  cue('press')
                  it.run()
                }}
              >
                {it.icon ? (
                  <span className="vico" aria-hidden="true">
                    {it.icon}
                  </span>
                ) : null}
                <span className="ptitle">{it.title}</span>
                {it.meta ? <span className="meta-line">{it.meta}</span> : null}
              </button>
            ))}
          </div>
        ))}
        {shown.length === 0 ? <p className="pal-empty">Nothing matches.</p> : null}
      </div>
    </div>
  )
}

/* ── the shortcut sheet: hold ⌘ for a moment and the keys show, bottom
   right above the agent line; let go and it is gone. ── */
const KEYS: [string, string][] = [
  ['/', 'search'],
  ['⌘K', 'palette'],
  ['t', 'theme'],
  ['m', 'sound'],
  ['Esc', 'close'],
  ['↑↓', 'move'],
  ['⏎', 'open'],
  ['[', 'fold the rail'],
]

export function ShortcutSheet({ shown }: { shown: boolean }) {
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
      {KEYS.map(([k, what]) => (
        <div className="krow" key={k}>
          <kbd>{k}</kbd>
          <span className="kwhat">{what}</span>
        </div>
      ))}
    </div>
  )
}
