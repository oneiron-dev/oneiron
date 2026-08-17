import * as React from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { Throbber } from '~/components/safelight/Widgets'
import { cue, markCued } from '~/components/safelight/hooks'
import { CLOCK, Empty, Fold, LedgerHead, PaneHead, Sec, Sheet, useEscLayer, useLedger, type Col } from './-shared'

export const Route = createFileRoute('/settings/packs')({
  component: PacksPage,
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
    pages: [{ name: 'supplier watch', href: '/app/lens/supplier-watch', what: 'Hokuei and its suppliers, from claims' }],
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
/* the one update waiting: crm v0.3 */
const UPDATE_WAITS: PackId = 'crm'

const COLS: Col<Pack>[] = [
  { id: 'name', header: 'name', accessor: (p) => p.name, size: 150 },
  { id: 'what', header: 'what', accessor: (p) => p.what },
  { id: 'ver', header: 'version', accessor: (p) => p.ver, size: 72 },
  { id: 'by', header: 'by', accessor: (p) => p.by, size: 80 },
  { id: 'acts', header: '', size: 190 },
]

/* ── the install ladder: reading the pack → granting scopes → done.
   timers stand in for the engine; the row keeps the record after. ── */
type Ladder = 0 | 1 | 2 | 3
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

/* the under-glance for any row: pages (doors) · scopes · last receipt */
function Glance({ p, installed }: { p: Pack; installed: boolean }) {
  return (
    <div className="pk-glance">
      <span className="gk">
        <span className="k">{installed ? 'pages' : 'pages it adds'}</span>
        <span className="v doors">
          {p.pages.map((pg) =>
            installed && pg.href !== '#' ? (
              <a className="door" key={pg.name} href={pg.href} title={pg.what}>
                {pg.name}
              </a>
            ) : (
              <span className="door still" key={pg.name} title={pg.what}>
                {pg.name}
              </span>
            ),
          )}
        </span>
      </span>
      <span className="gk">
        <span className="k">{installed ? 'scopes' : 'scopes it asks for'}</span>
        <span className="v">{p.scopes.map((s) => s.scope).join(' · ')}</span>
      </span>
      <span className="gk">
        <span className="k">last receipt</span>
        <span className="v serif">
          <span className="rc-time">{p.receipts[0].date}</span> {p.receipts[0].what}
        </span>
      </span>
    </div>
  )
}

function PacksPage() {
  const [ctx, setCtx] = React.useState<PackId | null>(null)
  useEscLayer(!!ctx, () => setCtx(null))

  const inst = useLedger<Pack>({ rows: INSTALLED, columns: COLS, getId: (p) => p.id, searchable: (p) => `${p.name} ${p.what} ${p.ver} ${p.by}` })
  const avail = useLedger<Pack>({ rows: AVAILABLE, columns: COLS, getId: (p) => p.id, searchable: (p) => `${p.name} ${p.what} ${p.ver} ${p.by}` })
  const setQuery = (v: string) => {
    inst.setQuery(v)
    avail.setQuery(v)
  }
  /* one selection across the two ledgers */
  const clickInst = (id: string, e?: React.SyntheticEvent) => {
    avail.clear()
    inst.clickRow(id, e)
  }
  const clickAvail = (id: string, e?: React.SyntheticEvent) => {
    inst.clear()
    avail.clickRow(id, e)
  }

  /* per-row settle state: removed · updated · the ladder rung */
  const [removed, setRemoved] = React.useState<PackId[]>([])
  const [updating, setUpdating] = React.useState<'idle' | 'busy' | 'done'>('idle')
  const [rungs, setRungs] = React.useState<Partial<Record<PackId, Ladder>>>({})
  const timers = React.useRef<ReturnType<typeof setTimeout>[]>([])
  React.useEffect(
    () => () => {
      timers.current.forEach(clearTimeout)
    },
    [],
  )
  const wait = (fn: () => void, ms: number) => {
    const t = setTimeout(fn, matchMedia('(prefers-reduced-motion: reduce)').matches ? 0 : ms)
    timers.current.push(t)
  }
  const remove = (id: PackId) => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setRemoved((r) => (r.includes(id) ? r : [...r, id]))
    if (ctx === id) setCtx(null)
    cue('press')
  }
  const update = (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setUpdating('busy')
    cue('press')
    wait(() => {
      setUpdating('done')
      cue('success')
    }, 1400)
  }
  const add = (id: PackId) => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    cue('press')
    setRungs((r) => ({ ...r, [id]: 1 }))
    avail.setSel(id)
    avail.setOpen(id)
    wait(() => setRungs((r) => ({ ...r, [id]: 2 })), 1100)
    wait(() => {
      setRungs((r) => ({ ...r, [id]: 3 }))
      cue('success')
    }, 2300)
  }

  const all = [...INSTALLED, ...AVAILABLE]
  const c = ctx ? all.find((p) => p.id === ctx) ?? null : null
  const cInstalled = c ? INSTALLED.some((p) => p.id === c.id) : false

  const renderRow = (
    p: Pack,
    installed: boolean,
    ledger: typeof inst,
    click: (id: string, e?: React.SyntheticEvent) => void,
  ) => {
    const isSel = ledger.sel === p.id || ctx === p.id
    const isOpen = ledger.open === p.id
    const gone = removed.includes(p.id)
    const rung = rungs[p.id] ?? 0
    const ownerOnly = p.id === OWNER_ONLY
    const done = rung >= 3
    const cls = ['row', gone ? 'gone' : '', isSel ? 'selected' : '', done ? 'added' : ''].filter(Boolean).join(' ')
    const scopes = p.scopes.map((s) => s.scope).join(' · ')
    const ver = p.id === UPDATE_WAITS && updating === 'done' ? 'v0.3' : p.ver
    return (
      <React.Fragment key={p.id}>
        <tr
          className={cls}
          aria-selected={isSel}
          aria-expanded={isOpen}
          onClick={(e) => {
            if ((e.target as HTMLElement).closest('a, button')) return
            click(p.id, e)
          }}
        >
          <td>
            <span className="p-name">{p.name}</span>
          </td>
          <td>
            <span className="p-what" title={p.what}>
              {p.what}
            </span>
          </td>
          <td>
            <span className="p-ver" title={p.verTip}>
              {ver}
            </span>
          </td>
          <td>
            <span className="p-by" title={p.byTip}>
              {p.by}
            </span>
          </td>
          <td>
            <span className="racts">
              {installed ? (
                gone ? (
                  <>
                    <span className="settled">removed {CLOCK}</span>
                    <a className="act" href="#" title="the receipt · what the pack wrote stays; the rail row is gone" onClick={(e) => e.preventDefault()}>
                      receipt
                    </a>
                  </>
                ) : (
                  <>
                    {p.id === UPDATE_WAITS &&
                      (updating === 'idle' ? (
                        <a className="act" href="#" title="verb: update_pack · v0.3 vetted; the diff waits for your stamp" onClick={update}>
                          update
                        </a>
                      ) : updating === 'busy' ? (
                        <span className="settled">
                          <Throbber initial="⠧" /> v0.3
                        </span>
                      ) : (
                        <span className="settled">v0.3 · updated {CLOCK}</span>
                      ))}
                    <button
                      className="act"
                      aria-expanded={ctx === p.id}
                      aria-controls="pack-record"
                      title="the full record · opens on the right"
                      onClick={(e) => {
                        markCued(e)
                        setCtx((cur) => (cur === p.id ? null : p.id))
                        cue('toggle')
                      }}
                    >
                      open
                    </button>
                    <a
                      className="act"
                      href="#"
                      data-danger
                      title="verb: remove_pack · the rail forgets its pages · every claim it wrote stays · receipted"
                      onClick={remove(p.id)}
                    >
                      remove
                    </a>
                  </>
                )
              ) : ownerOnly ? (
                <span className="quiet" title="not installable on a shared vault · it wants your personal vault">
                  owner vault only
                </span>
              ) : done ? (
                <span className="settled">installed {CLOCK}</span>
              ) : rung > 0 ? (
                <span className="settled">
                  installing <Throbber initial="⠧" />
                </span>
              ) : (
                <>
                  <button
                    className="act"
                    aria-expanded={ctx === p.id}
                    aria-controls="pack-record"
                    title="the full record · opens on the right"
                    onClick={(e) => {
                      markCued(e)
                      setCtx((cur) => (cur === p.id ? null : p.id))
                      cue('toggle')
                    }}
                  >
                    open
                  </button>
                  <a
                    className="act"
                    href="#"
                    title={`verb: install_pack · reads the pack, then asks for: ${scopes} · every grant is revocable on grants`}
                    onClick={add(p.id)}
                  >
                    add
                  </a>
                </>
              )}
            </span>
          </td>
        </tr>
        <Fold open={isOpen} cols={COLS.length}>
          {rung > 0 ? (
            <div className="ladder" aria-live="polite">
              <span className="label">installing</span>
              <div className={stepClass(rung, 1)}>
                <Mark rung={rung} at={1} />
                <span className="s-text">reading the pack</span>
                <span className="meta-line" title="manifest read before anything ran · checksum against the catalog">
                  {p.ver} · checksum {rung > 1 ? 'verified' : 'checking'}
                </span>
              </div>
              <div className={stepClass(rung, 2)}>
                <Mark rung={rung} at={2} />
                <span className="s-text">granting scopes</span>
                <span className="meta-line" title="read scopes only · nothing writes until you grant it">
                  {scopes}
                </span>
              </div>
              <div className={rung >= 3 ? 'step step-done' : 'step step-wait'}>
                <Mark rung={rung} at={3} />
                <span className="s-text">done</span>
              </div>
              {done && (
                <div className="ladder-foot">
                  <span className="said" title="the install is receipted">
                    Its pages are in your rail.
                  </span>
                </div>
              )}
            </div>
          ) : (
            <Glance p={p} installed={installed || done} />
          )}
        </Fold>
      </React.Fragment>
    )
  }

  return (
    <Sheet
      page="packs"
      ctx={!!c}
      aside={
        <aside className="context" id="pack-record" hidden={!c} aria-label="the pack's record">
          {c && (
            <>
              <div className="ctx-head">
                <span className="ctx-crumb">{c.crumb}</span>
                <button className="ctx-close" aria-label="close the record" title="close · esc" onClick={() => setCtx(null)}>
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
                    <a className="door" href="/settings/grants" title="the grant record · scope, budget, expiry · revoke on grants">
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
                <a className="act" href="#" title={c.source} onClick={(e) => e.preventDefault()}>
                  {c.source === 'this vault' ? 'the vault' : 'open source'}
                </a>
                {cInstalled && c.first !== '#' && (
                  <a className="act" href={c.first} title={c.firstTip}>
                    open {c.pages[0].name}
                  </a>
                )}
              </span>
            </>
          )}
        </aside>
      }
    >
      <PaneHead
        title="packs"
        hint="Installed packs put their pages in your rail. Adding one reads the pack, then grants its scopes. Removing one keeps every claim it wrote."
        search={{ value: inst.query, onChange: setQuery, onKeyDown: inst.onKeyDown }}
      />

      <Sec
        label="installed packs"
        title="Installed"
        meta={
          <span className="meta-line" title="crm · office · channels · lenses">
            {INSTALLED.length - removed.length} packs
          </span>
        }
      >
        <div className="ledger-wrap" tabIndex={-1} onKeyDown={inst.onKeyDown}>
          <table className="ledger p-ledger">
            <LedgerHead columns={COLS} sort={inst.sort} onSort={inst.toggleSort} />
            <tbody>
              {inst.view.length === 0 && <Empty cols={COLS.length} what="No installed pack matches that." />}
              {inst.view.map((p) => renderRow(p, true, inst, clickInst))}
            </tbody>
          </table>
        </div>
      </Sec>

      <Sec
        label="available packs"
        title="Available"
        meta={
          <span className="meta-line" title="catalog verified nightly · 07-07 03:10">
            {AVAILABLE.length} packs
          </span>
        }
      >
        <div className="sec-voice">
          <span className="aname" data-agent="antevon" title="Antevon · the house mind · checks the catalog nightly · last 07-07 03:10">
            Antevon
          </span>
          <span>Every pack is open source. I check the catalog each night. All three are green.</span>
        </div>
        <div className="ledger-wrap" tabIndex={-1} onKeyDown={avail.onKeyDown}>
          <table className="ledger p-ledger">
            <LedgerHead columns={COLS} sort={avail.sort} onSort={avail.toggleSort} />
            <tbody>
              {avail.view.length === 0 && <Empty cols={COLS.length} what="No catalog pack matches that." />}
              {avail.view.map((p) => renderRow(p, false, avail, clickAvail))}
            </tbody>
          </table>
        </div>
      </Sec>
    </Sheet>
  )
}
