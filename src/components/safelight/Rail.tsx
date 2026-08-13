import * as React from 'react'
import { Link } from '@tanstack/react-router'
import {
  Chevron,
  IconAgents,
  IconBriefs,
  IconInbox,
  IconNotes,
  IconOrgs,
  IconPipeline,
  IconSearch,
  IconSupplierWatch,
  IconTasks,
  IconThreads,
  IconToday,
  IconVault,
  LogoMark,
  PanelGlyph,
} from './icons'
import {
  cue,
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
export function Rail() {
  const railRef = React.useRef<HTMLElement>(null)
  const { folded, toggleFold } = useRailFold(railRef)
  const packs = usePackFolds()
  const [vmenuOpen, setVmenuOpen] = React.useState(false)

  useGlobalKeys({ '[': toggleFold })

  const closeVmenu = React.useCallback(() => setVmenuOpen(false), [])
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
      <div className="vmenu" id="vmenu" hidden={!vmenuOpen} role="menu" aria-label="vaults and settings">
        <span className="label">vaults</span>
        <Link
          className="vrow on"
          activeProps={{}}
          to="/app/vault"
          role="menuitem"
          onClick={closeVmenu}
        >
          <span className="vname">ops</span>
          <span className="meta-line">open now</span>
        </Link>
        <a className="vrow" href="#" role="menuitem" onClick={closeVmenu}>
          <span className="vname">field-notes</span>
          <span className="meta-line">yours</span>
        </a>
        <a className="vrow" href="#" role="menuitem" onClick={closeVmenu}>
          <span className="vname">+ mint a new vault</span>
        </a>
        {/* settings + the account door live here now (owner 08-15, the
            Linear pattern): the rail foot is dead. space divides. */}
        <a
          className="vrow vsplit"
          href="#"
          role="menuitem"
          title="settings · packs · billing · grants · receipts · policy live here"
          onClick={closeVmenu}
        >
          <span className="vname">settings</span>
        </a>
        <a
          className="vrow"
          href="#"
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
              aria-expanded={vmenuOpen}
              aria-haspopup="menu"
              title="antevon · vaults · settings · account"
              onClick={() => {
                setVmenuOpen((open) => !open)
                cue('toggle')
              }}
            >
              <span className="name">antevon</span>
              <Chevron size={8} />
            </button>
          </div>
        </div>

        <div className="group">
          <a href="#" className="search-row" role="search" title="search the vault · /">
            <span className="ico" aria-hidden="true">
              <IconSearch />
            </span>
            <span className="txt">search</span> <kbd>/</kbd>
          </a>
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
          <a href="#" title="agents">
            <span className="ico" aria-hidden="true">
              <IconAgents />
            </span>
            <span className="txt">agents</span>
          </a>
        </div>

        <Pack name="crm" packs={packs}>
          <a href="#" title="pipeline">
            <span className="ico" aria-hidden="true">
              <IconPipeline />
            </span>
            <span className="txt">pipeline</span>
          </a>
          <a href="#" title="today">
            <span className="ico" aria-hidden="true">
              <IconToday />
            </span>
            <span className="txt">today</span>
          </a>
          <a href="#" title="orgs">
            <span className="ico" aria-hidden="true">
              <IconOrgs />
            </span>
            <span className="txt">orgs</span>
          </a>
        </Pack>

        <Pack name="office" packs={packs}>
          <a href="#" title="notes">
            <span className="ico" aria-hidden="true">
              <IconNotes />
            </span>
            <span className="txt">notes</span>
          </a>
          <a href="#" title="briefs">
            <span className="ico" aria-hidden="true">
              <IconBriefs />
            </span>
            <span className="txt">briefs</span>
          </a>
          <a href="#" title="tasks · what waits lands in the inbox, not on a badge">
            <span className="ico" aria-hidden="true">
              <IconTasks />
            </span>
            <span className="txt">tasks</span>
          </a>
        </Pack>

        <Pack name="channels" packs={packs}>
          <a href="#" title="threads">
            <span className="ico" aria-hidden="true">
              <IconThreads />
            </span>
            <span className="txt">threads</span>
          </a>
        </Pack>

        {/* custom lenses wear the same pack grammar (owner 08-14 night):
            a "lenses" head with the disclosure chevron, rows inside */}
        <Pack name="lenses" lensesId="lenses-yours" packs={packs}>
          <a
            href="#"
            title="supplier watch · custom lens · icon assigned by the agent from the kit set · override in lens settings"
          >
            <span className="ico" aria-hidden="true">
              <IconSupplierWatch />
            </span>
            <span className="txt">supplier watch</span>
          </a>
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
  lensesId = `lenses-${name}`,
  packs,
  children,
}: {
  name: PackName
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
        title={isFolded ? `open ${name}` : `fold ${name} · its lenses keep working`}
        onClick={() => packs.toggle(name)}
      >
        <span className="label">{name}</span>
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
