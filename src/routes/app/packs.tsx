import * as React from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { Chevron } from '~/components/safelight/icons'
import { Throbber } from '~/components/safelight/Widgets'
import { cue, markCued, useEscape } from '~/components/safelight/hooks'
import packsCss from '~/styles/packs.css?url'

export const Route = createFileRoute('/app/packs')({
  head: () => ({
    links: [{ rel: 'stylesheet', href: packsCss }],
  }),
  component: Packs,
})

/* ── fixtures · the rail packs ARE these (crm · office · channels · lenses)
   plus the catalog rows from app-packs.html ── */
type PackId = 'crm' | 'office' | 'channels' | 'lenses' | 'campaign' | 'repo' | 'psych'

type Pack = {
  id: PackId
  name: string
  what: string
  ver: string
  verTip: string
  by: 'oneiron' | 'antevon'
  byTip: string
  first: string
  firstTip: string
  /* the record, condensed from pack-home.html */
  crumb: string
  body: string
  pages: { name: string; href: string; what: string }[]
  scopes: { scope: string; what: string }[]
  receipts: { date: string; what: string }[]
  source: string
}

const INSTALLED: Pack[] = [
  {
    id: 'crm',
    name: 'crm',
    what: 'pipeline · today · orgs',
    ver: 'v0.2',
    verTip: 'crm v0.2 · installed 06-30 · v0.3 vetted, its diff waits for your stamp',
    by: 'oneiron',
    byTip: 'oneiron · open source · github.com/oneiron-dev/pack-crm',
    first: '/app/pipeline',
    firstTip: 'open the pipeline · the pack’s first page',
    crumb: 'pack · crm v0.2 · by oneiron',
    body: 'Pipeline board, today view, org dossiers. Agents propose rows, you stamp them.',
    pages: [
      { name: 'pipeline', href: '/app/pipeline', what: 'open deals, staged toward decision' },
      { name: 'today', href: '/app/today', what: 'what needs a hand today' },
      { name: 'orgs', href: '/app/orgs', what: 'a dossier per organization' },
    ],
    scopes: [
      { scope: 'crm.read', what: 'full vault · read only' },
      { scope: 'outbound.email', what: '20/mo · 7 used · expires 2026-10-07' },
    ],
    receipts: [
      { date: '07-05', what: 'Regenerated. Three lenses recompiled, checksum verified.' },
      { date: '06-28', what: 'Grant minted: outbound.email, 20 a month, by your click.' },
      { date: '06-28', what: 'Installed from the catalog. crm v0.2, open source.' },
    ],
    source: 'github.com/oneiron-dev/pack-crm',
  },
  {
    id: 'office',
    name: 'office',
    what: 'notes · briefs · tasks',
    ver: 'v0.1',
    verTip: 'office v0.1 · installed 06-30',
    by: 'oneiron',
    byTip: 'oneiron · open source · github.com/oneiron-dev/pack-office',
    first: '/app/notes',
    firstTip: 'open notes · the pack’s first page',
    crumb: 'pack · office v0.1 · by oneiron',
    body: 'Notes agents read before acting, briefs that cite their claims, tasks that close on evidence. Protected notes take proposals, never silent edits.',
    pages: [
      { name: 'notes', href: '/app/notes', what: 'what agents read before they act' },
      { name: 'briefs', href: '/app/briefs', what: 'every sentence cites its claims' },
      { name: 'tasks', href: '/app/tasks', what: 'close on evidence' },
    ],
    scopes: [{ scope: 'office.read', what: 'full vault · read only' }],
    receipts: [
      { date: '07-05', what: 'Regenerated. Checksum verified.' },
      { date: '06-30', what: 'Installed from the catalog. office v0.1, open source.' },
    ],
    source: 'github.com/oneiron-dev/pack-office',
  },
  {
    id: 'channels',
    name: 'channels',
    what: 'threads · LINE, Slack, email and LinkedIn in one thread',
    ver: 'v0.1',
    verTip: 'channels v0.1 · installed 06-30',
    by: 'oneiron',
    byTip: 'oneiron · open source · github.com/oneiron-dev/pack-channels',
    first: '/app/threads',
    firstTip: 'open threads · the pack’s first page',
    crumb: 'pack · channels v0.1 · by oneiron',
    body: 'Cross-channel threads and agent presences. Every send verifies and receipts.',
    pages: [{ name: 'threads', href: '/app/threads', what: 'one thread across every channel' }],
    scopes: [
      { scope: 'line.oa', what: 'read + send · every send is your click' },
      { scope: 'slack', what: 'read + post · #ops' },
      { scope: 'gmail', what: 'read + send' },
      { scope: 'linkedin', what: 'read · send under the outreach grant' },
    ],
    receipts: [
      { date: '07-05', what: 'Regenerated. Checksum verified.' },
      { date: '06-30', what: 'Installed from the catalog. channels v0.1, open source.' },
    ],
    source: 'github.com/oneiron-dev/pack-channels',
  },
  {
    id: 'lenses',
    name: 'lenses',
    what: 'supplier watch',
    ver: 'v0.1',
    verTip: 'your custom lenses · Antevon regenerates them when their claims change',
    by: 'antevon',
    byTip: 'Antevon · the house mind · made from your vault',
    first: '/app/lens/supplier-watch',
    firstTip: 'open supplier watch · the one lens so far',
    crumb: 'pack · lenses · by antevon',
    body: 'Lenses the house mind made from this vault. They read; they never write.',
    pages: [
      { name: 'supplier watch', href: '/app/lens/supplier-watch', what: 'Hokuei and its suppliers, from claims' },
    ],
    scopes: [{ scope: 'vault.read', what: 'clients world · read only' }],
    receipts: [
      { date: '07-05', what: 'Regenerated. The supplier claim changed the Hokuei row.' },
      { date: '07-01', what: 'Supplier watch made, from your ask in chat.' },
    ],
    source: 'this vault',
  },
]

const AVAILABLE: Pack[] = [
  {
    id: 'campaign',
    name: 'creative campaign',
    what: 'ads pipeline with metrics and a swipe file',
    ver: 'v0.4',
    verTip: 'creative campaign v0.4 · catalog verified 07-07',
    by: 'oneiron',
    byTip: 'oneiron · open source · github.com/oneiron-dev/pack-campaign',
    first: '#',
    firstTip: 'open the campaign lens · it appears in your rail once the engine wires it',
    crumb: 'catalog · creative campaign v0.4 · by oneiron',
    body: 'Campaigns, creatives with their provenance, and performance claims your agents can read.',
    pages: [
      { name: 'campaigns', href: '#', what: 'every campaign, its spend and its claims' },
      { name: 'swipe file', href: '#', what: 'creatives with their provenance' },
    ],
    scopes: [
      { scope: 'meta ads', what: 'read campaigns · read metrics' },
      { scope: 'google ads', what: 'read campaigns · read metrics' },
      { scope: 'x ads', what: 'read · needs an account first' },
    ],
    receipts: [{ date: '07-07', what: 'Catalog check. Connectors green, checksum verified.' }],
    source: 'github.com/oneiron-dev/pack-campaign',
  },
  {
    id: 'repo',
    name: 'repo world',
    what: 'a repository as a memory scope',
    ver: 'v0.2',
    verTip: 'repo world v0.2 · catalog verified 07-07',
    by: 'oneiron',
    byTip: 'oneiron · open source · github.com/oneiron-dev/pack-repo',
    first: '#',
    firstTip: 'open the repo lens · it appears in your rail once the engine wires it',
    crumb: 'catalog · repo world v0.2 · by oneiron',
    body: 'Snapshots, a symbol graph, session claims, agent diffs behind review. Code history you can ask about.',
    pages: [
      { name: 'repo', href: '#', what: 'the repository as a scope' },
      { name: 'diffs', href: '#', what: 'agent diffs behind review' },
    ],
    scopes: [{ scope: 'github', what: 'read repository · read history' }],
    receipts: [{ date: '07-07', what: 'Catalog check. Connector green, checksum verified.' }],
    source: 'github.com/oneiron-dev/pack-repo',
  },
  {
    id: 'psych',
    name: 'psych mirror',
    what: 'personality profiles over your own history, three depths',
    ver: 'v0.1',
    verTip: 'psych mirror v0.1 · preview · verified 07-05',
    by: 'oneiron',
    byTip: 'oneiron · open source · github.com/oneiron-dev/pack-psych',
    first: '#',
    firstTip: '',
    crumb: 'catalog · psych mirror v0.1 · by oneiron',
    body: 'Private to the owner. Agents see only what you grant. It does not install on a shared vault.',
    pages: [{ name: 'mirror', href: '#', what: 'three depths over your own history' }],
    scopes: [{ scope: 'owner.read', what: 'your personal vault only' }],
    receipts: [{ date: '07-05', what: 'Preview build. Verified on a personal vault.' }],
    source: 'github.com/oneiron-dev/pack-psych',
  },
]

/* the one pack this vault cannot take: shared vault, owner-only pack */
const OWNER_ONLY: PackId = 'psych'

/* ── the install ladder: reading the pack → granting scopes → done.
   timers stand in for the engine; the row keeps the record after. ── */
type Ladder = 0 | 1 | 2 | 3 /* 0 = not started · 3 = done */

function useInstall() {
  const [rung, setRung] = React.useState<Ladder>(0)
  const timers = React.useRef<ReturnType<typeof setTimeout>[]>([])
  React.useEffect(
    () => () => {
      timers.current.forEach(clearTimeout)
    },
    [],
  )
  const start = (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    markCued(e)
    cue('press')
    setRung(1)
    timers.current.push(setTimeout(() => setRung(2), 1100))
    timers.current.push(setTimeout(() => setRung(3), 2300))
    timers.current.push(setTimeout(() => cue('success'), 2300))
  }
  return { rung, start }
}

function stepClass(rung: Ladder, at: 1 | 2 | 3) {
  if (rung > at) return 'step step-done'
  if (rung === at) return 'step step-live'
  return 'step step-wait'
}
function Mark({ rung, at }: { rung: Ladder; at: 1 | 2 | 3 }) {
  if (rung > at) return <span className="s-mark">●</span>
  if (rung === at)
    return (
      <span className="s-mark">
        <Throbber initial="⠧" />
      </span>
    )
  return <span className="s-mark">○</span>
}

/* the "done" rung settles at once with the receipt: it is the last mark */
function doneClass(rung: Ladder) {
  return rung >= 3 ? 'step step-done' : 'step step-wait'
}

/* ── remove settles in place: the verb quiets, the receipt lands ── */
function useRemove() {
  const [gone, setGone] = React.useState(false)
  const act = (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    markCued(e)
    setGone(true)
    cue('press')
  }
  return { gone, act }
}

/* headings collapse in place (rule 10) */
function Bundle({
  label,
  title,
  meta,
  children,
}: {
  label: string
  title: string
  meta: React.ReactNode
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
        {meta}
      </div>
      {children}
    </section>
  )
}

/* one installed pack, one line: name · what · version · by · open · remove */
function InstalledRow({
  pack,
  sel,
  onSelect,
}: {
  pack: Pack
  sel: boolean
  onSelect: () => void
}) {
  const r = useRemove()
  const cls = ['prow', sel ? 'sel' : '', r.gone ? 'gone' : ''].filter(Boolean).join(' ')
  const onLine = (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest('a,button')) return
    if (r.gone) return
    onSelect()
  }
  return (
    <div
      className={cls}
      tabIndex={0}
      role="button"
      aria-pressed={sel}
      onKeyDown={(e) => {
        if ((e.key === 'Enter' || e.key === ' ') && e.target === e.currentTarget) {
          e.preventDefault()
          if (!r.gone) onSelect()
        }
      }}
    >
      <div className="prow-line" onClick={onLine}>
        <span className="p-name" title={r.gone ? `${pack.name} · removed` : `${pack.name} · the record opens on the right`}>
          {pack.name}
        </span>
        <span className="p-what" title={r.gone ? 'the receipt holds what it wrote' : pack.what}>
          {r.gone ? 'The rail forgets it. The receipt landed.' : pack.what}
        </span>
        <span className="p-ver" title={pack.verTip}>
          {pack.ver}
        </span>
        <span className="p-by" title={pack.byTip}>
          {pack.by}
        </span>
        <span className="p-acts">
          {r.gone ? (
            <>
              <span className="meta-line">removed 14:12</span>
              <a className="act" href="#" title="the receipt · what the pack wrote stays; the rail row is gone">
                receipt
              </a>
            </>
          ) : (
            <>
              <a className="act" href={pack.first} title={pack.firstTip}>
                open
              </a>
              <button
                type="button"
                className="act arm"
                title="verb: remove_pack · the rail forgets its pages · every claim it wrote stays · receipted"
                onClick={r.act}
              >
                remove
              </button>
            </>
          )}
        </span>
      </div>
    </div>
  )
}

/* one catalog pack, one line: name · what · version · by · add.
   add settles THROUGH the ladder, in place. */
function AvailableRow({
  pack,
  sel,
  onSelect,
}: {
  pack: Pack
  sel: boolean
  onSelect: () => void
}) {
  const inst = useInstall()
  const ownerOnly = pack.id === OWNER_ONLY
  const open = inst.rung > 0
  const done = inst.rung >= 3
  const cls = ['prow', sel ? 'sel' : '', open ? 'open' : '', done ? 'added' : '']
    .filter(Boolean)
    .join(' ')
  const onLine = (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest('a,button')) return
    onSelect()
  }
  const scopes = pack.scopes.map((s) => s.scope).join(' · ')
  return (
    <div
      className={cls}
      tabIndex={0}
      role="button"
      aria-pressed={sel}
      onKeyDown={(e) => {
        if ((e.key === 'Enter' || e.key === ' ') && e.target === e.currentTarget) {
          e.preventDefault()
          onSelect()
        }
      }}
    >
      <div className="prow-line" onClick={onLine}>
        <span className="p-name" title={`${pack.name} · the record opens on the right`}>
          {pack.name}
        </span>
        <span className="p-what" title={pack.what}>
          {pack.what}
        </span>
        <span className="p-ver" title={pack.verTip}>
          {pack.ver}
        </span>
        <span className="p-by" title={pack.byTip}>
          {pack.by}
        </span>
        <span className="p-acts">
          {ownerOnly ? (
            <span className="quiet" title="not installable on a shared vault · it wants your personal vault">
              owner vault only
            </span>
          ) : done ? (
            <span className="meta-line">installed 14:12</span>
          ) : open ? (
            <span className="meta-line">
              installing <Throbber initial="⠧" />
            </span>
          ) : (
            <button
              type="button"
              className="act"
              title={`verb: install_pack · reads the pack, then asks for: ${scopes} · every grant is revocable in settings`}
              onClick={inst.start}
            >
              add
            </button>
          )}
        </span>
      </div>
      {!ownerOnly && (
        <div className="prow-detail" aria-live="polite">
          <div className="ladder">
            <span className="label">installing</span>
            <div className={stepClass(inst.rung, 1)}>
              <Mark rung={inst.rung} at={1} />
              <span className="s-text">reading the pack</span>
              <span className="meta-line" title="manifest read before anything ran · checksum against the catalog">
                {pack.ver} · checksum {inst.rung > 1 ? 'verified' : 'checking'}
              </span>
            </div>
            <div className={stepClass(inst.rung, 2)}>
              <Mark rung={inst.rung} at={2} />
              <span className="s-text">granting scopes</span>
              <span className="meta-line" title="read scopes only · nothing writes until you grant it">
                {scopes}
              </span>
            </div>
            <div className={doneClass(inst.rung)}>
              <Mark rung={inst.rung} at={3} />
              <span className="s-text">done</span>
            </div>
            {done && (
              <div className="ladder-foot">
                <span className="said" title="the install is receipted">
                  Its pages are in your rail.
                </span>
                <a className="act" href={pack.first} title={pack.firstTip}>
                  open
                </a>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function Packs() {
  const [hintOpen, setHintOpen] = React.useState(false)
  const [ctx, setCtx] = React.useState<PackId | null>(null)
  useEscape(() => setCtx(null))

  const select = (id: PackId) => () => {
    setCtx((cur) => (cur === id ? null : id))
    cue('toggle')
  }
  const all = [...INSTALLED, ...AVAILABLE]
  const c = ctx ? all.find((p) => p.id === ctx) ?? null : null
  const cInstalled = c ? INSTALLED.some((p) => p.id === c.id) : false

  return (
    <main className={ctx ? 'pane packs ctx-on' : 'pane packs'} id="pane">
      <div className="pane-body">
        <div className="pane-head">
          <h1>Packs</h1>
          <span className="pane-tools">
            <button
              className="hint-btn"
              aria-expanded={hintOpen}
              aria-controls="packs-why"
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
        <div className="dial-why" id="packs-why" hidden={!hintOpen}>
          <span className="why-voice">
            Installed packs put their pages in your rail. Adding one reads the pack, then grants
            its scopes. Removing one keeps every claim it wrote.
          </span>
        </div>

        {/* INSTALLED · the rail packs are these */}
        <Bundle
          label="installed packs"
          title="Installed"
          meta={
            <span className="meta-line" title="crm · office · channels · lenses">
              {INSTALLED.length} packs
            </span>
          }
        >
          <div className="prows">
            {INSTALLED.map((p) => (
              <InstalledRow key={p.id} pack={p} sel={ctx === p.id} onSelect={select(p.id)} />
            ))}
          </div>
        </Bundle>

        {/* AVAILABLE · the catalog, kept green */}
        <Bundle
          label="available packs"
          title="Available"
          meta={
            <span className="meta-line" title="catalog verified nightly · 07-07 03:10">
              {AVAILABLE.length} packs
            </span>
          }
        >
          <div className="sec-voice">
            <span
              className="aname"
              data-agent="antevon"
              title="Antevon · the house mind · checks the catalog nightly · last 07-07 03:10"
            >
              Antevon
            </span>
            <span>Every pack is open source. I check the catalog each night. All three are green.</span>
          </div>
          <div className="prows">
            {AVAILABLE.map((p) => (
              <AvailableRow key={p.id} pack={p} sel={ctx === p.id} onSelect={select(p.id)} />
            ))}
          </div>
        </Bundle>

        <p className="foot-note">Packs add pages and verbs. They never write to the vault without a grant.</p>
      </div>

      {/* the context column: a pack's record is something you READ */}
      <aside className="context" hidden={!c} aria-label="the pack's record">
        {c && (
          <>
            <div className="ctx-head">
              <span className="ctx-crumb">{c.crumb}</span>
              <button
                className="chat-close"
                aria-label="close the record"
                title="close · esc"
                onClick={() => setCtx(null)}
              >
                ×
              </button>
            </div>
            <div className="ctx-title">{c.name}</div>
            <span className="ctx-body">{c.body}</span>

            <div className="ctx-sec">
              <span className="label">{cInstalled ? 'pages' : 'pages it adds'}</span>
              {c.pages.map((pg) => (
                <div className="ctx-row" key={pg.name}>
                  {cInstalled && pg.href !== '#' ? (
                    <a className="door" href={pg.href} title={`open ${pg.name}`}>
                      {pg.name}
                    </a>
                  ) : (
                    <span className="door" title={pg.name}>
                      {pg.name}
                    </span>
                  )}
                  <span className="ctx-what">{pg.what}</span>
                </div>
              ))}
            </div>

            <div className="ctx-sec">
              <span className="label">{cInstalled ? 'grants held' : 'scopes it asks for'}</span>
              {c.scopes.map((s) => (
                <div className="ctx-row" key={s.scope}>
                  <a className="door" href="/app/settings" title="the grant record · scope, budget, expiry · revoke in settings">
                    {s.scope}
                  </a>
                  <span className="ctx-what">{s.what}</span>
                </div>
              ))}
            </div>

            <div className="ctx-sec">
              <span className="label">receipts</span>
              {c.receipts.map((r, i) => (
                <div className="ctx-row" key={i}>
                  <span className="r-date">{r.date}</span>
                  <span className="r-what">{r.what}</span>
                </div>
              ))}
            </div>

            <span className="ctx-acts">
              <a className="act" href="#" title={c.source}>
                {c.source === 'this vault' ? 'the vault' : 'open source'}
              </a>
              {cInstalled && (
                <a className="act" href="/app/settings" title="grants · receipts · policy live in settings">
                  settings
                </a>
              )}
            </span>
          </>
        )}
      </aside>
    </main>
  )
}
