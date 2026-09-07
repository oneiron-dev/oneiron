import * as React from 'react'
import { Link, useRouterState } from '@tanstack/react-router'
import {
  Chevron,
  IconBriefs,
  IconInbox,
  IconMint,
  IconNotes,
  IconOrgs,
  IconPipeline,
  IconSearch,
  IconSettings,
  IconSupplierWatch,
  IconTasks,
  IconThreads,
  IconToday,
  IconUsage,
  IconVault,
  IconVaultAntevon,
  IconVaultFieldNotes,
  LogoMark,
  PanelGlyph,
} from './icons'
import {
  cue,
  openPalette,
  useDocumentEvent,
  useEscape,
  useGlobalKeys,
  usePackFolds,
  useRailFold,
  type PackName,
} from './hooks'

/* v2 IA · 12 icons · core / pack / yours. every row is icon + label open,
   icon alone folded. the icon team is ratified (08-14): assets/icons-v2.html
   is the single source, copied verbatim.
   The masthead is dead (owner 08-14 night): the rail owns the mark and the
   vault chip; the sheet reaches the top of the page. The vmenu is fixed so
   the rail's overflow never clips it. */
/* the rail picker (owner 09-08, an option beside the roster column): the
   agents as rows under `agents`, the Slack shape — one sidebar, the room
   is ?with=. Hidden unless html[data-picker="rail"]. The bench fixture. */
const RAIL_AGENTS: Array<{ key: 'eiri' | 'tory' | 'antevon' | 'house' | 'new'; ink?: 'eiri' | 'tory' | 'antevon'; name: string; tip: string }> = [
  { key: 'eiri', ink: 'eiri', name: 'eiri', tip: 'Eiri · open the room' },
  { key: 'tory', ink: 'tory', name: 'tory', tip: 'Tory · open the room' },
  { key: 'antevon', ink: 'antevon', name: 'antevon', tip: 'Antevon · nights' },
  { key: 'new', name: 'new agent', tip: 'a new agent · by conversation with Antevon' },
]

export function Rail() {
  const loc = useRouterState({ select: (st) => st.location })
  const onAgents = loc.pathname.startsWith('/app/agents')
  const withKey = (loc.search as { with?: string }).with ?? 'eiri'
  const railRef = React.useRef<HTMLElement>(null)
  const chipRef = React.useRef<HTMLButtonElement>(null)
  const menuRef = React.useRef<HTMLDivElement>(null)
  const { folded, toggleFold } = useRailFold(railRef)
  const packs = usePackFolds()
  const [vmenuOpen, setVmenuOpen] = React.useState(false)

  useGlobalKeys({ '[': toggleFold })

  /* closing hands the focus back to the chip you opened it from — but
     only if it was still inside the menu, so an outside click is left
     where it landed */
  const closeVmenu = React.useCallback(() => {
    setVmenuOpen(false)
    const active = document.activeElement
    if (active instanceof HTMLElement && active.closest('.vmenu')) chipRef.current?.focus()
  }, [])

  /* the open menu takes the focus, so the keyboard reaches it: the menu
     sits before the rail in the DOM and Tab alone would walk past it. */
  React.useEffect(() => {
    if (!vmenuOpen) return
    menuRef.current?.querySelector<HTMLElement>('.vrow')?.focus()
  }, [vmenuOpen])

  const onMenuKey = (e: React.KeyboardEvent<HTMLDivElement>) => {
    /* Tab leaves the menu: it closes and the chip takes the focus back,
       so the next Tab carries on down the rail */
    if (e.key === 'Tab') {
      e.preventDefault()
      closeVmenu()
      return
    }
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp' && e.key !== 'Home' && e.key !== 'End') return
    e.preventDefault()
    const rows = Array.from(menuRef.current?.querySelectorAll<HTMLElement>('.vrow') ?? [])
    if (!rows.length) return
    const here = rows.indexOf(document.activeElement as HTMLElement)
    const down = e.key === 'ArrowDown'
    const next =
      e.key === 'Home' ? 0
      : e.key === 'End' ? rows.length - 1
      : here < 0 ? (down ? 0 : rows.length - 1)
      : (here + (down ? 1 : rows.length - 1)) % rows.length
    rows[next]?.focus()
  }

  useEscape(() => {
    if (vmenuOpen) closeVmenu()
  })
  useDocumentEvent('click', (e) => {
    const target = e.target as HTMLElement | null
    /* the mock leaned on stopPropagation from the chip's own handler;
       React delegates, so the chip has to be named here instead */
    if (target?.closest('.vmenu') || target?.closest('[data-vswitch]')) return
    if (vmenuOpen) closeVmenu()
  })

  const foldTitle = folded ? 'open the rail · [' : 'fold the rail · ['
  const foldLabel = folded ? 'open the rail' : 'fold the rail'

  return (
    <>
      {/* the chip menu (owner 08-18, ruling 9): every row wears a mark;
          the vaults, then a separator (a menu may carry one rule), then
          settings · usage · the human. settings is its own area now
          (/settings/*), reached by plain href: those routes are being
          built beside this one. */}
      <div
        className="vmenu"
        id="vmenu"
        ref={menuRef}
        hidden={!vmenuOpen}
        role="menu"
        aria-label="vaults and settings"
        onKeyDown={onMenuKey}
      >
        <span className="label">vaults</span>
        <Link
          className="vrow on"
          activeProps={{}}
          to="/app/vault"
          role="menuitem"
          onClick={closeVmenu}
        >
          <span className="vico" aria-hidden="true">
            <IconVaultAntevon />
          </span>
          <span className="vname">antevon</span>
          <span className="meta-line">open now</span>
        </Link>
        {/* the second vault switches in place; it is not a page, so it is
            a button, not an href to nowhere */}
        <button
          className="vrow"
          type="button"
          role="menuitem"
          title="switch to field-notes"
          onClick={() => {
            cue('toggle')
            closeVmenu()
          }}
        >
          <span className="vico" aria-hidden="true">
            <IconVaultFieldNotes />
          </span>
          <span className="vname">field-notes</span>
          <span className="meta-line">yours</span>
        </button>
        <a className="vrow" href="/mint" role="menuitem" onClick={closeVmenu}>
          <span className="vico" aria-hidden="true">
            <IconMint />
          </span>
          <span className="vname">mint a new vault</span>
        </a>
        <div className="vsep" role="separator" />
        <a
          className="vrow"
          href="/settings"
          role="menuitem"
          title="settings · theme · members · grants · connectors · packs · vault"
          onClick={closeVmenu}
        >
          <span className="vico" aria-hidden="true">
            <IconSettings />
          </span>
          <span className="vname">settings</span>
        </a>
        <a
          className="vrow"
          href="/settings/usage"
          role="menuitem"
          title="usage · billing"
          onClick={closeVmenu}
        >
          <span className="vico" aria-hidden="true">
            <IconUsage />
          </span>
          <span className="vname">usage</span>
        </a>
        <a
          className="vrow"
          href="/settings/account"
          role="menuitem"
          title="o · Owen · owner · account"
          onClick={closeVmenu}
        >
          <span className="seal seal-human">o</span>
          <span className="vname">Owen</span>
        </a>
      </div>

      <nav className="rail" aria-label="workbench" ref={railRef}>
        <div className="group">
          <div className="head-row">
            {/* one mark: the logo at rest, the panel glyph on hover — click
                folds the rail. the vault chip is the switcher. */}
            <button
              className="mark-fold"
              aria-expanded={!folded}
              aria-label={foldLabel}
              title={foldTitle}
              onClick={toggleFold}
            >
              <LogoMark />
              <PanelGlyph />
            </button>
            <button
              className="vault-chip"
              data-vswitch
              ref={chipRef}
              aria-expanded={vmenuOpen}
              aria-haspopup="menu"
              aria-controls="vmenu"
              title="antevon · vaults · settings · account"
              onClick={() => {
                setVmenuOpen((open) => !open)
                cue('toggle')
              }}
            >
              <span className="name">antevon</span>
              <Chevron size={8} />
            </button>
            {/* search left the rows (owner 08-18): one icon beside the
                vault name. it opens the palette, where searching and asking
                are the same field — the same door as / and ⌘K. */}
            <button
              className="search-btn"
              type="button"
              aria-label="search or ask"
              title="search · ask · / · ⌘K"
              onClick={() => {
                cue('press')
                openPalette()
              }}
            >
              <IconSearch />
            </button>
          </div>
        </div>

        <div className="group">
          {/* the router marks the active row: class `active` + aria-current,
              exactly what the mock hand-wrote on the current page */}
          <Link to="/app/inbox" title="inbox · the one number: things waiting for your click">
            <span className="ico" aria-hidden="true">
              <IconInbox />
            </span>
            <span className="txt">inbox</span> <span className="count">5</span>
          </Link>
          <Link to="/app/vault" title="vault · board · graph live inside">
            <span className="ico" aria-hidden="true">
              <IconVault />
            </span>
            <span className="txt">vault</span>
          </Link>
        </div>

        {/* agents (owner 09-08): the section IS the base's agents row — every
            agent's room, the house, a new agent — between the base and the
            lenses. Selection lives here; status stays on the ground line, so
            no live dot on a row. The fold key stays `rooms`. */}
        <Pack name="rooms" label="agents" packs={packs}>
          {RAIL_AGENTS.map((a) => (
            <Link
              key={a.key}
              to="/app/agents"
              search={{ with: a.key }}
              className={onAgents && withKey === a.key ? 'active' : undefined}
              title={a.tip}
            >
              <span className="ico" aria-hidden="true">
                {a.ink ? <span className="face mark" data-agent={a.ink} /> : <span className="rail-plus">+</span>}
              </span>
              <span className={a.ink ? 'txt aname' : 'txt'} data-agent={a.ink}>
                {a.name}
              </span>
            </Link>
          ))}
        </Pack>

        <Pack name="channels" packs={packs}>
          <Link to="/app/threads" title="threads">
            <span className="ico" aria-hidden="true">
              <IconThreads />
            </span>
            <span className="txt">threads</span>
          </Link>
          <Link
            to="/app/agents"
            search={{ with: 'house' }}
            className={onAgents && withKey === 'house' ? 'active' : undefined}
            title="the house · every agent and you in one room"
          >
            <span className="ico" aria-hidden="true"></span>
            <span className="txt">the house</span>
          </Link>
        </Pack>

        <Pack name="crm" packs={packs}>
          <Link to="/app/pipeline" title="pipeline">
            <span className="ico" aria-hidden="true">
              <IconPipeline />
            </span>
            <span className="txt">pipeline</span>
          </Link>
          <Link to="/app/today" title="today">
            <span className="ico" aria-hidden="true">
              <IconToday />
            </span>
            <span className="txt">today</span>
          </Link>
          <Link to="/app/orgs" title="orgs">
            <span className="ico" aria-hidden="true">
              <IconOrgs />
            </span>
            <span className="txt">orgs</span>
          </Link>
        </Pack>

        <Pack name="office" packs={packs}>
          <Link to="/app/notes" title="notes">
            <span className="ico" aria-hidden="true">
              <IconNotes />
            </span>
            <span className="txt">notes</span>
          </Link>
          <Link to="/app/briefs" title="briefs">
            <span className="ico" aria-hidden="true">
              <IconBriefs />
            </span>
            <span className="txt">briefs</span>
          </Link>
          <Link to="/app/tasks" title="tasks · what waits lands in the inbox, not on a badge">
            <span className="ico" aria-hidden="true">
              <IconTasks />
            </span>
            <span className="txt">tasks</span>
          </Link>
        </Pack>

        {/* custom lenses wear the same pack grammar (owner 08-14 night):
            a "lenses" head with the disclosure chevron, rows inside */}
        <Pack name="lenses" lensesId="lenses-yours" packs={packs}>
          <Link
            to="/app/lens/supplier-watch"
            title="supplier watch · custom lens · icon assigned by the agent from the kit set · override in lens settings">
            <span className="ico" aria-hidden="true">
              <IconSupplierWatch />
            </span>
            <span className="txt">supplier watch</span>
          </Link>
        </Pack>

      </nav>
    </>
  )
}

/* pack head · ONE target (owner 08-15): the whole title is the fold —
   label + chevron in a single button, no separate door. The bubbled sum
   stays empty: no lens carries a count any more (FLOWS §3c rule 4 — the
   inbox number is the one number), so `.pack-sum:empty` keeps it out of
   the strip. */
function Pack({
  name,
  label,
  lensesId = `lenses-${name}`,
  packs,
  children,
}: {
  name: PackName
  /* the word a person reads; the key stays the fold's name (owner 09-08:
     "rooms" is our word, not theirs) */
  label?: string
  lensesId?: string
  packs: ReturnType<typeof usePackFolds>
  children: React.ReactNode
}) {
  const isFolded = !!packs.folded[name]
  return (
    <div className="group pack" data-pack={name}>
      <button
        className="pack-head"
        aria-expanded={!isFolded}
        aria-controls={lensesId}
        title={isFolded ? `open ${label ?? name}` : `fold ${label ?? name} · its lenses keep working`}
        onClick={() => packs.toggle(name)}
      >
        <span className="label">{label ?? name}</span>
        <span className="pack-fold" aria-hidden="true">
          <Chevron />
        </span>
        <span className="count pack-sum"></span>
      </button>
      <div className="lenses" id={lensesId}>
        <div className="lens-col">{children}</div>
      </div>
    </div>
  )
}
