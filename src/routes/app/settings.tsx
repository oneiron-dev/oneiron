import * as React from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { Chevron } from '~/components/safelight/icons'
import { Throbber } from '~/components/safelight/Widgets'
import {
  applyTheme,
  cue,
  markCued,
  readTheme,
  useEscape,
  useSound,
  type Theme,
} from '~/components/safelight/hooks'
import settingsCss from '~/styles/settings.css?url'

export const Route = createFileRoute('/app/settings')({
  head: () => ({
    links: [{ rel: 'stylesheet', href: settingsCss }],
  }),
  component: Settings,
})

/* ── fixtures (FLOWS §2 cast · the mock's numbers) ── */
const CLOCK = '14:07'
const TODAY = '2026-08-15'
const HASH_GROUPS = ['a7f3', '9c21', '4b8e', '0d55', '6e12', '33af', '90c4', '7b1d']
const HASH_FULL = HASH_GROUPS.join('')
const HASH_SHORT = `${HASH_GROUPS[0]}…${HASH_GROUPS[HASH_GROUPS.length - 1]}`

/* ── the genesis seal: a 7×7 kakuin pressed from the vault's name. mirrored
   glyph from an fnv hash of "antevon-ops", ~14% dropout as the pressure
   texture. pure, so SSR and the client press the same stamp. ── */
function fnv(s: string) {
  let h = 2166136261
  for (const c of s) {
    h ^= c.charCodeAt(0)
    h = Math.imul(h, 16777619)
  }
  return h >>> 0
}
function prng(seed: number) {
  return () => {
    seed = Math.imul(seed ^ (seed >>> 15), seed | 1)
    seed ^= seed + Math.imul(seed ^ (seed >>> 7), seed | 61)
    return ((seed ^ (seed >>> 14)) >>> 0) / 4294967296
  }
}
function sealCells(key: string): boolean[] {
  const r = prng(fnv(key))
  const G = 4
  const H = 7
  const half: boolean[] = []
  for (let i = 0; i < G * H; i++) half.push(r() > 0.34)
  const cells: boolean[] = []
  for (let y = 0; y < H; y++)
    for (let x = 0; x < 7; x++) {
      const mx = x < G ? x : 6 - x
      cells.push(half[y * G + mx] && r() > 0.14)
    }
  return cells
}
const SEAL = sealCells('antevon-ops')

function GenesisSeal() {
  return (
    <svg
      className="seal-genesis"
      viewBox="0 0 7 7"
      width="28"
      height="28"
      shapeRendering="crispEdges"
      role="img"
      aria-label="genesis seal"
    >
      <title>genesis seal · pressed from the first block · the same stamp lands on every receipt, pack and export</title>
      {SEAL.map((on, i) =>
        on ? <rect key={i} x={i % 7} y={Math.floor(i / 7)} width="1" height="1" fill="currentColor" /> : null,
      )}
    </svg>
  )
}

/* ── headings collapse in place (rule 10); the count only when closed ── */
function Bundle({
  label,
  title,
  meta,
  children,
}: {
  label: string
  title: string
  meta?: React.ReactNode
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
      <div className="body">{children}</div>
    </section>
  )
}

/* ── the receipts door: unfolds under its row, never a modal ── */
function ReceiptsFold({ id, open, lines }: { id: string; open: boolean; lines: [string, string][] }) {
  return (
    <tr>
      <td className="foldcell" colSpan={6}>
        <div className={open ? 'fold on' : 'fold'} id={id}>
          <div className="fold-in">
            <div className="fold-body">
              {lines.map(([time, what], i) => (
                <span className="rc-line" key={i}>
                  <span className="rc-time">{time}</span>
                  <span className="rc-what">{what}</span>
                </span>
              ))}
            </div>
          </div>
        </div>
      </td>
    </tr>
  )
}

/* ── members ── */
type Role = 'owner' | 'member' | 'guest'
type Member = {
  id: string
  seal: string
  name: string
  cls?: string
  role: Role
  reach: string
  reachTip: string
  seen: string
}
const MEMBERS: Member[] = [
  {
    id: 'o',
    seal: 'o',
    name: 'oleksii',
    role: 'owner',
    reach: 'everything',
    reachTip: 'every world, plus grants, export and forget',
    seen: `today ${CLOCK}`,
  },
  {
    id: 'y',
    seal: 'y',
    name: 'yurii',
    role: 'member',
    reach: 'base · clients',
    reachTip: 'worlds base and clients · writes land, sends still ask',
    seen: 'today 11:04',
  },
  {
    id: 'm',
    seal: 'm',
    name: 'Mika Tanaka',
    cls: 'seal-class',
    role: 'guest',
    reach: 'clients/hokuei · read',
    reachTip: 'one org, read only · the pass expires 2026-09-30, then she is a contact again',
    seen: '08-12 10:41',
  },
]

function MemberRow({ m, escTick, onGone }: { m: Member; escTick: number; onGone: (id: string) => void }) {
  const [role, setRole] = React.useState<Role>(m.role)
  const [choosing, setChoosing] = React.useState(false)
  const [settled, setSettled] = React.useState<string | null>(null)
  const [gone, setGone] = React.useState(false)
  React.useEffect(() => {
    setChoosing(false)
  }, [escTick])

  const pick = (next: Role) => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setRole(next)
    setChoosing(false)
    setSettled(`${role} → ${next} · ${CLOCK} · receipted`)
    cue('success')
  }
  const remove = (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setGone(true)
    onGone(m.id)
    setChoosing(false)
    setSettled(`removed · ${CLOCK} · receipted`)
    cue('press')
  }
  const others = (['member', 'guest'] as Role[]).filter((r) => r !== role)

  return (
    <tr className={gone ? 'row gone' : 'row'}>
      <td>
        <span className="who">
          <span className={`seal seal-human${m.cls ? ` ${m.cls}` : ''}`} title={`${m.seal} · ${m.name} · ${role}`}>
            {m.seal}
          </span>
          <span className={role === 'guest' ? 'nm guest' : 'nm'}>{m.name}</span>
        </span>
      </td>
      <td>
        <span className="role">{role}</span>
      </td>
      <td>
        <a className="scope" href="#" title={m.reachTip} onClick={(e) => e.preventDefault()}>
          {m.reach}
        </a>
      </td>
      <td>
        <span className="meta-line" title="last here">
          {m.seen}
        </span>
      </td>
      <td>
        <span className="racts">
          {m.role === 'owner' ? null : settled ? (
            <span className="settled">{settled}</span>
          ) : choosing ? (
            <span className="chooser" role="group" aria-label={`new role for ${m.name}`}>
              <span className="label">role</span>
              {others.map((r) => (
                <a className="act" href="#" key={r} title={`verb: set_role · ${m.name} becomes ${r}`} onClick={pick(r)}>
                  {r}
                </a>
              ))}
              <a
                className="act"
                href="#"
                title="keep the role"
                onClick={(e) => {
                  e.preventDefault()
                  markCued(e)
                  setChoosing(false)
                  cue('toggle')
                }}
              >
                keep
              </a>
            </span>
          ) : (
            <>
              <button
                className="act"
                aria-expanded={choosing}
                title={`verb: set_role · ${m.name} is a ${role}`}
                onClick={(e) => {
                  markCued(e)
                  setChoosing(true)
                  cue('toggle')
                }}
              >
                change role
              </button>
              <a
                className="act"
                href="#"
                data-danger
                title={`verb: remove_member · ${m.name} loses reach now; what they did keeps its receipts`}
                onClick={remove}
              >
                remove
              </a>
            </>
          )}
        </span>
      </td>
    </tr>
  )
}

/* ── grants ── */
type Grant = {
  id: string
  who: React.ReactNode
  scope: string
  scopeTip: string
  budget: string
  expires: string
  receipts: [string, string][]
  revocable: boolean
  gone?: { line: string; receipts: [string, string][] }
}
const GRANTS: Grant[] = [
  {
    id: 'eiri',
    who: (
      <span className="aname" data-agent="eiri" title="Eiri · outbound companion · bound to oleksii">
        Eiri
      </span>
    ),
    scope: 'outbound.email · hokuei.co.jp',
    scopeTip: 'send email as antevon, to one domain, nothing else',
    budget: '20 sends a month · 6 used',
    expires: '2026-10-07',
    receipts: [
      ['08-12 16:20', 'Sent the pilot quote to mika@hokuei.co.jp. You approved it in the inbox.'],
      ['08-06 09:41', 'Sent the audit summary. Delivery verified, then receipted.'],
    ],
    revocable: true,
  },
  {
    id: 'tory',
    who: (
      <span className="aname" data-agent="tory" title="Tory · research companion">
        Tory
      </span>
    ),
    scope: 'read.web · read.world:clients',
    scopeTip: 'public web plus the clients world, read only · it never writes a claim without review',
    budget: '$4 a day · $0.31 today',
    expires: 'open',
    receipts: [
      ['08-13 13:14', 'Read 6 public filings for the supplier rumor. Two proposed claims wait in the inbox.'],
      ['08-11 08:02', 'Read the clients world, 41 claims. Nothing written.'],
    ],
    revocable: true,
  },
  {
    id: 'antevon',
    who: (
      <span className="aname" data-agent="antevon" title="Antevon · the house mind · local model">
        Antevon
      </span>
    ),
    scope: 'read.vault · write.summary',
    scopeTip: 'reads the vault, writes summaries only · summaries recompile, they never overwrite a claim',
    budget: 'local model · ¥0',
    expires: 'open',
    receipts: [
      ['08-13 13:44', 'Recompiled 2 summaries whose evidence moved. Nothing left the machine.'],
      ['08-13 03:12', 'Nightly consolidation. One summary retired, its claims kept.'],
    ],
    revocable: true,
  },
  {
    id: 'importer',
    who: (
      <span className="who">
        <span className="seal seal-system" title="im · importer · system actor">
          im
        </span>
        <span className="nm">importer</span>
      </span>
    ),
    scope: 'import.mail · fastmail archive',
    scopeTip: 'one pass over one mailbox · credentials discarded after it, so a spent grant cannot be used twice',
    budget: 'one pass · 11,204 messages',
    expires: 'spent 08-05',
    receipts: [['08-05 22:40', '318 sources read. 96 claims proposed, 61 accepted. Learned dates set to the import.']],
    revocable: false,
  },
  {
    id: 'slack',
    who: (
      <span className="who">
        <span className="seal seal-system" title="sl · slack connector · system actor">
          sl
        </span>
        <span className="nm">slack connector</span>
      </span>
    ),
    scope: 'read.messages · #ops',
    scopeTip: 'revoked · the scope is dead, the reading it did is not',
    budget: 'was 2 GB·days a month',
    expires: 'revoked 08-11',
    receipts: [],
    revocable: false,
    gone: {
      line: 'revoked · 08-11 16:20 · receipted',
      receipts: [
        ['08-11 16:20', 'Revoked by oleksii. The workspace moved to a new plan.'],
        ['', '41 receipts stay. 12 claims it brought in keep their sources and their learned dates.'],
      ],
    },
  },
]

function GrantRow({ g, onRevoked }: { g: Grant; onRevoked: (id: string) => void }) {
  const [open, setOpen] = React.useState(!!g.gone)
  const [revoked, setRevoked] = React.useState<string | null>(g.gone?.line ?? null)
  const [lines, setLines] = React.useState<[string, string][]>(g.gone ? g.gone.receipts : g.receipts)
  const foldId = `g-${g.id}`

  const revoke = (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setRevoked(`revoked · ${CLOCK} · receipted`)
    onRevoked(g.id)
    setLines((l) => [[`${TODAY.slice(5)} ${CLOCK}`, 'Revoked by oleksii. The reach ends now; the receipts stay.'], ...l])
    setOpen(true)
    cue('press')
  }
  const gone = !!revoked
  return (
    <>
      <tr className={gone ? 'row gone' : 'row'} data-grant={g.id}>
        <td>{g.who}</td>
        <td>
          {gone ? (
            <span className="scope" title={g.scopeTip}>
              {g.scope}
            </span>
          ) : (
            <a className="scope" href="#" title={g.scopeTip} onClick={(e) => e.preventDefault()}>
              {g.scope}
            </a>
          )}
        </td>
        <td>
          <span className="meta-line">{g.budget}</span>
        </td>
        <td>
          <span className="meta-line">{g.expires}</span>
        </td>
        <td>
          <span className="racts">
            {revoked && <span className="settled">{revoked}</span>}
            <button
              className="act"
              aria-expanded={open}
              aria-controls={foldId}
              title={open ? 'fold the receipts back' : 'verb: open_receipts · what this grant paid for, in place'}
              onClick={(e) => {
                markCued(e)
                setOpen((o) => !o)
                cue('toggle')
              }}
            >
              receipts
            </button>
            {g.revocable && !revoked && (
              <a
                className="act"
                href="#"
                data-danger
                title="verb: revoke_grant · the reach ends at once; what it already did stays on the record"
                onClick={revoke}
              >
                revoke
              </a>
            )}
          </span>
        </td>
      </tr>
      <ReceiptsFold id={foldId} open={open} lines={lines} />
    </>
  )
}

/* ── the deletion receipts ── */
type Erased = { stamp: string; what: string; why: string; seal: string; sealTip: string; sweep: 'due' | string }
const ERASED: Erased[] = [
  {
    stamp: 'ERASED · 2026-08-13 · reason on record',
    what: 'A supplier rumor and the thread under it.',
    why: 'Retracted at source.',
    seal: 'y',
    sealTip: 'y · yurii · member',
    sweep: 'due',
  },
  {
    stamp: 'ERASED · 2026-08-11 · reason on record',
    what: "Mika Tanaka's home address, and the two claims that carried it.",
    why: 'Asked for by the contact.',
    seal: 'o',
    sealTip: 'o · oleksii · owner',
    sweep: 'swept 08-12 03:12',
  },
  {
    stamp: 'ERASED · 2026-07-29 · reason on record',
    what: 'The 2025 payroll import, all 402 rows.',
    why: 'Landed in the wrong vault.',
    seal: 'o',
    sealTip: 'o · oleksii · owner',
    sweep: 'swept 07-30 03:12',
  },
]

function Settings() {
  const [hintOpen, setHintOpen] = React.useState(false)
  const [escTick, setEscTick] = React.useState(0)
  useEscape(() => {
    setHintOpen(false)
    setEscTick((t) => t + 1)
  })

  /* the closed head shows a count, so the count must stay true (rule 12:
     one place per fact) — removals and revokes move it */
  const [goneMembers, setGoneMembers] = React.useState<string[]>([])
  const [revokedGrants, setRevokedGrants] = React.useState<string[]>(
    GRANTS.filter((g) => g.gone).map((g) => g.id),
  )

  /* the vault fingerprint: copy settles to "copied" */
  const [copied, setCopied] = React.useState(false)
  const copyHash = (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    try {
      void navigator.clipboard?.writeText(HASH_FULL)
    } catch {
      /* no clipboard · the hash is on the screen */
    }
    setCopied(true)
    cue('success')
  }

  /* appearance: the theme is a class on <html> (readTheme/applyTheme);
     read on mount, and follow the `t` key so the row never lies */
  const [theme, setTheme] = React.useState<Theme>('system')
  React.useEffect(() => {
    setTheme(readTheme())
    const mo = new MutationObserver(() => setTheme(readTheme()))
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
    return () => mo.disconnect()
  }, [])
  const pickTheme = (next: Theme) => (e: React.MouseEvent) => {
    markCued(e)
    if (next !== readTheme()) {
      applyTheme(next)
      setTheme(next)
    }
    cue('toggle')
  }

  /* sound: useSound() gives the toggle; the row mirrors localStorage */
  const toggleSound = useSound()
  const [sound, setSound] = React.useState(true)
  const readSound = () => {
    try {
      return localStorage.getItem('oneiron-mock-sound') !== 'off'
    } catch {
      return true
    }
  }
  React.useEffect(() => {
    setSound(readSound())
  }, [])
  const pickSound = (want: boolean) => (e: React.MouseEvent) => {
    markCued(e)
    if (readSound() !== want) {
      toggleSound()
      if (readSound() !== want) toggleSound()
    }
    setSound(want)
    if (!want) cue('press')
  }

  /* export: requested → sealing → sealed package + a download door */
  const [exp, setExp] = React.useState<'idle' | 'sealing' | 'sealed'>('idle')
  const expTimer = React.useRef<ReturnType<typeof setTimeout> | null>(null)
  React.useEffect(
    () => () => {
      if (expTimer.current) clearTimeout(expTimer.current)
    },
    [],
  )
  const requestExport = (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setExp('sealing')
    cue('press')
    const wait = matchMedia('(prefers-reduced-motion: reduce)').matches ? 0 : 1400
    expTimer.current = setTimeout(() => {
      setExp('sealed')
      cue('success')
    }, wait)
  }

  /* forget: the act arms only once there is a reason; the receipt lands
     into the ledger below, stamped */
  const [reason, setReason] = React.useState('')
  const [erased, setErased] = React.useState<Erased[]>(ERASED)
  const [landed, setLanded] = React.useState(0)
  const armed = reason.trim().length > 0
  const commitForget = () => {
    setErased((rows) => [
      {
        stamp: `ERASED · ${TODAY} · reason on record`,
        what: reason.trim(),
        why: '',
        seal: 'o',
        sealTip: 'o · oleksii · owner',
        sweep: 'due',
      },
      ...rows,
    ])
    setLanded((n) => n + 1)
    setReason('')
    cue('success')
  }
  const forget = (e: React.MouseEvent) => {
    e.preventDefault()
    if (!armed) return
    markCued(e)
    commitForget()
  }

  return (
    <main className="pane settings" id="pane">
      <div className="pane-body">
        <div className="pane-head">
          <h1>Settings</h1>
          <span className="pane-tools">
            <button
              className="hint-btn"
              aria-expanded={hintOpen}
              aria-controls="settings-why"
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
        <div className="dial-why" id="settings-why" hidden={!hintOpen}>
          <span className="why-voice">
            Everything about this vault. Who reaches it, what may act on it, how it leaves. Every
            change here lands as a receipt.
          </span>
        </div>

        {/* ── 1 · vault: the seal is THE resting red of the viewport ── */}
        <Bundle label="vault fingerprint" title="Vault">
          <div className="fp">
            <GenesisSeal />
            <span className="gh" title={`genesis hash · sha256 of the first block · ${HASH_GROUPS.join(' ')}`}>
              {HASH_SHORT}
            </span>
            <span className="acts">
              {copied ? (
                <span className="settled">copied</span>
              ) : (
                <a className="act" href="#" title="verb: copy_genesis_hash · the full hash goes to the clipboard" onClick={copyHash}>
                  copy
                </a>
              )}
            </span>
          </div>
          <div className="fp-path">
            <span className="meta-line" title="one file, yours · minted 2026-03-02 09:14">
              ~/vaults/antevon-ops.oneiron
            </span>
          </div>
          <div className="crea">
            <img src="/art/creatures/antevon.png" width={60} height={32} alt="the antevon moth" title="the moth · the face this vault wears wherever it appears" />
            <span className="c-col">
              <span className="nm">antevon · ops</span>
              <span className="sub">the mascot is the address</span>
            </span>
          </div>
        </Bundle>

        {/* ── 2 · appearance: theme + sound live HERE (rules 2, 25, 37) ── */}
        <Bundle label="appearance" title="Appearance">
          <div className="srow">
            <span className="key">theme</span>
            <span className="acts" role="group" aria-label="theme">
              <button className={theme === 'light' ? 'act on' : 'act'} aria-pressed={theme === 'light'} title="the reading room" onClick={pickTheme('light')}>
                <span className="glyph" aria-hidden="true">○</span> light
              </button>
              <button className={theme === 'system' ? 'act on' : 'act'} aria-pressed={theme === 'system'} title="follow the system" onClick={pickTheme('system')}>
                <span className="glyph" aria-hidden="true">◐</span> system
              </button>
              <button className={theme === 'dark' ? 'act on' : 'act'} aria-pressed={theme === 'dark'} title="the film black desk" onClick={pickTheme('dark')}>
                <span className="glyph" aria-hidden="true">●</span> dark
              </button>
            </span>
          </div>
          <div className="srow">
            <span className="key">sound</span>
            <span className="acts" role="group" aria-label="sound">
              <button className={sound ? 'act on' : 'act'} aria-pressed={sound} title="cues on acts, folds and the theme" onClick={pickSound(true)}>
                on
              </button>
              <button className={!sound ? 'act on' : 'act'} aria-pressed={!sound} title="every cue is a no-op" onClick={pickSound(false)}>
                off
              </button>
            </span>
          </div>
        </Bundle>

        {/* ── 3 · members ── */}
        <Bundle label="members" title="Members" meta={<span className="meta-line">{MEMBERS.length - goneMembers.length}</span>}>
          <div className="ledger-wrap">
            <table className="ledger m-ledger">
              <thead>
                <tr>
                  <th className="c-who"></th>
                  <th className="c-role">role</th>
                  <th>reach</th>
                  <th className="c-seen">last here</th>
                  <th className="c-acts"></th>
                </tr>
              </thead>
              <tbody>
                {MEMBERS.map((m) => (
                  <MemberRow
                    key={m.id}
                    m={m}
                    escTick={escTick}
                    onGone={(id) => setGoneMembers((g) => (g.includes(id) ? g : [...g, id]))}
                  />
                ))}
              </tbody>
            </table>
          </div>
        </Bundle>

        {/* ── 4 · grants: the load-bearing ledger ── */}
        <Bundle
          label="grants"
          title="Grants"
          meta={
            <span className="meta-line">
              {GRANTS.length - revokedGrants.length} live · {revokedGrants.length} revoked
            </span>
          }
        >
          <div className="ledger-wrap">
            <table className="ledger g-ledger">
              <thead>
                <tr>
                  <th className="c-who"></th>
                  <th>scope</th>
                  <th className="c-budget">budget</th>
                  <th className="c-exp">expires</th>
                  <th className="c-acts"></th>
                </tr>
              </thead>
              <tbody>
                {GRANTS.map((g) => (
                  <GrantRow
                    key={g.id}
                    g={g}
                    onRevoked={(id) => setRevokedGrants((r) => (r.includes(id) ? r : [...r, id]))}
                  />
                ))}
              </tbody>
            </table>
          </div>
          <span className="note">Revoking is not erasing. The reach ends now. What the grant already did keeps its receipts.</span>
        </Bundle>

        {/* ── 5 · export with provenance: one row that settles ── */}
        <Bundle label="export" title="Export">
          <div className="exp">
            {exp === 'idle' && (
              <>
                <a
                  className="act"
                  href="#"
                  title="verb: request_export · worlds base, clients and internal, with every source and receipt"
                  onClick={requestExport}
                >
                  export with provenance
                </a>
                <span className="meta-line" title="the last export left on 08-06 09:02">
                  base · clients · internal
                </span>
              </>
            )}
            {exp === 'sealing' && (
              <>
                <span className="settled">requested · {CLOCK}</span>
                <Throbber />
              </>
            )}
            {exp === 'sealed' && (
              <>
                <span className="settled">sealed · 12,408 claims · 812 MB</span>
                <a
                  className="act"
                  href="#"
                  title="antevon-ops-20260815.tar.zst · 812 MB · stamped with the genesis seal"
                  onClick={(e) => e.preventDefault()}
                >
                  download
                </a>
              </>
            )}
          </div>
        </Bundle>

        {/* ── 6 · forget: the ceremony ── */}
        <Bundle label="forget" title="Forget" meta={<span className="meta-line">{erased.length} erased</span>}>
          <div className="ceremony">
            <span className="two-phase">Forgetting has two phases. The record goes now. The sweep clears the history at 03:12.</span>
            <input
              className="reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="what goes away, and why"
              aria-label="reason for the deletion"
              onKeyDown={(e) => {
                if (e.key === 'Enter' && armed) {
                  e.preventDefault()
                  commitForget()
                }
              }}
            />
            <div className="c-go">
              <a
                className={armed ? 'act' : 'act disarmed'}
                href="#"
                data-danger
                aria-disabled={!armed}
                title={armed ? 'verb: forget · tombstones the record now and queues the history sweep' : 'say why first'}
                onClick={forget}
              >
                forget
              </a>
            </div>
          </div>
          <div className="ledger-wrap">
            <table className="ledger f-ledger" aria-label="deletion receipts">
              <thead>
                <tr>
                  <th className="c-stamp"></th>
                  <th>record</th>
                  <th className="c-seal"></th>
                  <th className="c-sweep">sweep</th>
                </tr>
              </thead>
              <tbody>
                {erased.map((r, i) => (
                  <tr className={i < landed ? 'row landed' : 'row'} key={`${r.stamp}-${r.what}`}>
                    <td>
                      <span className="stamp" title="erased · the record is gone; the fact that it was erased is not">
                        {r.stamp}
                      </span>
                    </td>
                    <td>
                      <span className="claim">
                        {r.what}
                        {r.why && <span className="why"> {r.why}</span>}
                      </span>
                    </td>
                    <td>
                      <span className="seal seal-human" title={r.sealTip}>
                        {r.seal}
                      </span>
                    </td>
                    <td>
                      <span
                        className="meta-line"
                        title={
                          r.sweep === 'due'
                            ? 'the record is gone now · the sweep clears the history at 03:12'
                            : 'the history is swept'
                        }
                      >
                        {r.sweep === 'due' ? 'due 03:12' : r.sweep}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Bundle>

        {/* ── 7 · account ── */}
        <Bundle label="account" title="Account">
          <div className="srow acct">
            <span className="seal seal-human" title="o · oleksii · owner">
              o
            </span>
            <span className="val">oleksii</span>
            <span className="addr" title="the account address">
              olety7@gmail.com
            </span>
            <span className="acts tail">
              <a className="act" href="/signin" title="verb: sign_out · the vault stays where it is">
                sign out
              </a>
            </span>
          </div>
        </Bundle>

        {/* ── 8 · the doors at the foot ── */}
        <div className="doors" aria-label="doors">
          <a className="door" href="/app/packs" title="packs · what is installed, what wants updating">
            <span className="d-name">packs</span>
            <span className="d-sub">crm, office and channels are installed. One update waits.</span>
          </a>
          <a className="door" href="/app/billing" title="billing · meters, invoices and the spend cap">
            <span className="d-name">billing</span>
            <span className="d-sub">Meters, invoices and the spend cap.</span>
          </a>
          <div className="door">
            <span className="d-name">policy</span>
            <span className="d-sub">Retention, worlds, and what an agent may never touch.</span>
            <a className="act" href="#" title="verb: open_policy · the policy file, as the engine reads it" onClick={(e) => e.preventDefault()}>
              read it
            </a>
          </div>
        </div>
      </div>
    </main>
  )
}
