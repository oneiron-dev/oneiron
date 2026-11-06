import * as React from 'react'
import { Link, createFileRoute } from '@tanstack/react-router'
import { LogoMark } from '~/components/safelight/icons'
import { Throbber } from '~/components/safelight/Widgets'
import { cue } from '~/components/safelight/hooks'
import mintCss from '~/styles/mint.css?url'

export const Route = createFileRoute('/mint')({
  head: () => ({
    links: [{ rel: 'stylesheet', href: mintCss }],
  }),
  component: Mint,
})

/* ── fixtures (FLOWS §2: the fresh personal vault) ── */
const GENESIS = '8f3a91c47d0e6b25'
const GENESIS_SHOWN = '8f3a 91c4 7d0e 6b25'
const DEFAULT_NAME = 'field-notes'
const pathFor = (name: string) => `~/vaults/${name || 'vault'}.oneiron`

type SourceId = 'notes' | 'chat' | 'slack'
const SOURCES: { id: SourceId; name: string; detail: string; tip: string }[] = [
  { id: 'notes', name: '~/notes', detail: '214 files', tip: 'notes folder · reads, never writes · revocable at any time' },
  { id: 'chat', name: 'claude-2026-07.json', detail: '612 conversations', tip: 'chat export · one read, then the grant closes behind it' },
  { id: 'slack', name: 'slack workspace', detail: '3 channels', tip: 'slack · it asks for the workspace scope first' },
]

const INDEX_TARGET = { sources: 3, claims: 148, review: 2 }
const INDEX_MS = 2400
const MINT_MS = 700

/* ── the genesis seal: a 7×7 hash-cell mark drawn from the genesis hash.
   FNV-1a seeds an xorshift; the left four columns mirror to the right, so
   this hash always draws this stamp. Pure, so SSR and hydration agree. ── */
function fnv(s: string) {
  let h = 2166136261
  for (const c of s) {
    h ^= c.charCodeAt(0)
    h = Math.imul(h, 16777619)
  }
  return h >>> 0
}
function sealCells(seed: string): [number, number][] {
  let s = fnv(seed) || 1
  const rnd = () => {
    s ^= s << 13
    s >>>= 0
    s ^= s >> 17
    s ^= s << 5
    s >>>= 0
    return s / 4294967296
  }
  const on: boolean[] = []
  for (let y = 0; y < 7; y++) for (let x = 0; x < 4; x++) on.push(rnd() > 0.46)
  const cells: [number, number][] = []
  for (let y = 0; y < 7; y++)
    for (let x = 0; x < 7; x++) {
      const mx = x < 4 ? x : 6 - x
      if (on[y * 4 + mx]) cells.push([x, y])
    }
  return cells
}
const SEAL = sealCells(GENESIS)

function GenesisSeal() {
  return (
    <svg
      className="gseal in"
      viewBox="0 0 7 7"
      width="36"
      height="36"
      role="img"
      aria-label={`genesis seal for ${DEFAULT_NAME}`}
      shapeRendering="crispEdges"
    >
      <title>genesis seal · drawn from the hash beside it · this hash always draws this stamp</title>
      {SEAL.map(([x, y]) => (
        <rect key={`${x}-${y}`} x={x} y={y} width="1" height="1" fill="currentColor" />
      ))}
    </svg>
  )
}

const clock = () => {
  const d = new Date()
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
}
const reduced = () =>
  typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches

/* ── the walk ── */
type Phase = 'name' | 'minting' | 'minted' | 'indexing' | 'indexed' | 'answered'
type StepState = 'done' | 'live' | 'wait'
const ORDER: Phase[] = ['name', 'minting', 'minted', 'indexing', 'indexed', 'answered']
const at = (p: Phase) => ORDER.indexOf(p)

/* a live step that waits on YOU wears a still mark; a live PROCESS
   (minting, the first read) wears the throbber */
function Step({
  state,
  title,
  index,
  busy = false,
  children,
}: {
  state: StepState
  title: string
  index: number
  busy?: boolean
  children?: React.ReactNode
}) {
  return (
    <div
      className={`step step-${state} dev`}
      style={{ '--i': index } as React.CSSProperties}
      aria-current={state === 'live' ? 'step' : undefined}
    >
      <span className="s-mark" aria-hidden="true">
        {state === 'done' ? '●' : state === 'wait' ? '○' : busy ? <Throbber /> : '●'}
      </span>
      <div className="s-body">
        <span className="s-title">{title}</span>
        {children}
      </div>
    </div>
  )
}

function Mint() {
  const [phase, setPhase] = React.useState<Phase>('name')
  const [name, setName] = React.useState(DEFAULT_NAME)
  const [path, setPath] = React.useState(pathFor(DEFAULT_NAME))
  const [pathTouched, setPathTouched] = React.useState(false)
  const [mintedAt, setMintedAt] = React.useState('')
  const [copied, setCopied] = React.useState(false)
  const [granted, setGranted] = React.useState<Partial<Record<SourceId, string>>>({})
  const [counts, setCounts] = React.useState({ sources: 0, claims: 0, review: 0 })
  const [question, setQuestion] = React.useState('Where do I keep my notes?')
  const [answeredAt, setAnsweredAt] = React.useState('')

  /* develop-on-load: arm before first paint, then let it develop */
  const [arm, setArm] = React.useState(false)
  const [developed, setDeveloped] = React.useState(false)
  React.useLayoutEffect(() => {
    setArm(true)
    let r2 = 0
    const r1 = requestAnimationFrame(() => {
      r2 = requestAnimationFrame(() => setDeveloped(true))
    })
    return () => {
      cancelAnimationFrame(r1)
      cancelAnimationFrame(r2)
    }
  }, [])

  const timers = React.useRef<ReturnType<typeof setTimeout>[]>([])
  const later = (fn: () => void, ms: number) => {
    timers.current.push(setTimeout(fn, ms))
  }
  React.useEffect(() => () => timers.current.forEach(clearTimeout), [])

  /* 1 → 2: mint. 700ms of throbber, then the seal stamps in */
  const mint = () => {
    if (!name.trim()) return
    cue('press')
    setPhase('minting')
    later(() => {
      setMintedAt(clock())
      setPhase('minted')
      cue('success')
    }, MINT_MS)
  }

  const copyHash = () => {
    try {
      navigator.clipboard?.writeText(GENESIS).catch(() => {})
    } catch {
      /* no clipboard · the hash is on the page */
    }
    setCopied(true)
    cue('success')
  }

  /* 3: each grant lands its receipt; the third opens the first read */
  const grant = (id: SourceId) => {
    cue('press')
    const next = { ...granted, [id]: clock() }
    setGranted(next)
    if (SOURCES.every((s) => next[s.id])) later(() => setPhase('indexing'), 420)
  }

  /* 4: the counts tick, then the step settles */
  React.useEffect(() => {
    if (phase !== 'indexing') return
    if (reduced()) {
      setCounts(INDEX_TARGET)
      setPhase('indexed')
      return
    }
    const t0 = performance.now()
    let raf = 0
    const tick = () => {
      const k = Math.min(1, (performance.now() - t0) / INDEX_MS)
      const ease = 1 - Math.pow(1 - k, 2)
      setCounts({
        sources: Math.min(INDEX_TARGET.sources, Math.floor(ease * INDEX_TARGET.sources + 0.999)),
        claims: Math.round(ease * INDEX_TARGET.claims),
        review: k > 0.85 ? INDEX_TARGET.review : k > 0.55 ? 1 : 0,
      })
      if (k < 1) raf = requestAnimationFrame(tick)
      else {
        setCounts(INDEX_TARGET)
        setPhase('indexed')
        cue('success')
      }
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [phase])

  /* 5: Enter → the first recall, thin and true */
  const ask = (e: React.FormEvent) => {
    e.preventDefault()
    if (!question.trim()) return
    cue('press')
    setAnsweredAt(clock())
    setPhase('answered')
  }

  const p = at(phase)
  const allGranted = SOURCES.every((s) => granted[s.id])
  const s1: StepState = phase === 'name' ? 'live' : 'done'
  const s2: StepState = phase === 'name' ? 'wait' : phase === 'minting' ? 'live' : 'done'
  const s3: StepState = p < at('minted') ? 'wait' : allGranted ? 'done' : 'live'
  const s4: StepState = p < at('indexing') ? 'wait' : phase === 'indexing' ? 'live' : 'done'
  const s5: StepState = p < at('indexed') ? 'wait' : phase === 'indexed' ? 'live' : 'done'
  const s6: StepState = phase === 'answered' ? 'live' : 'wait'

  return (
    <>
      <div className="grain" aria-hidden="true"></div>
      <div className="mint-desk">
        <main className={`mint${arm ? ' arm' : ''}${developed ? ' developed' : ''}`}>
          <header className="mint-mast dev" style={{ '--i': 0 } as React.CSSProperties}>
            <Link to="/" className="brand" title="oneiron">
              <LogoMark />
              <span className="word">oneiron</span>
            </Link>
          </header>

          <section className="mint-sheet" aria-label="mint a vault">
            <div className="mint-head dev" style={{ '--i': 1 } as React.CSSProperties}>
              <img className="spot" src="/art/spot-flock.png" width={120} alt="" />
              <h1>Mint a vault</h1>
              <p className="voice">
                A vault is one file on your disk. It reads only what you point it at. It keeps the
                source of every line it learns. When it does not know, it says so.
              </p>
            </div>

            <div className="steps">
              {/* 1 · name the vault + its home path */}
              <Step state={s1} title="Name the vault" index={2}>
                {s1 === 'live' ? (
                  <div className="name-row">
                    <label className="fld">
                      <span className="label">name</span>
                      <input
                        className="mfield"
                        value={name}
                        onChange={(e) => {
                          setName(e.target.value)
                          if (!pathTouched) setPath(pathFor(e.target.value.trim()))
                        }}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') mint()
                        }}
                        spellCheck={false}
                        aria-label="vault name"
                      />
                    </label>
                    <label className="fld">
                      <span className="label">home</span>
                      <input
                        className="mfield"
                        value={path}
                        onChange={(e) => {
                          setPathTouched(true)
                          setPath(e.target.value)
                        }}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') mint()
                        }}
                        spellCheck={false}
                        aria-label="vault home path"
                      />
                    </label>
                  </div>
                ) : (
                  <div className="named">
                    <span className="vname" title="the vault's name">
                      {name}
                    </span>
                    <span className="vpath" title="one file · copy it anywhere">
                      {path}
                    </span>
                  </div>
                )}
                <span className="s-note">One portable file, yours.</span>
              </Step>

              {/* 2 · mint → the seal moment · THE resting red */}
              <Step state={s2} title="The seal" index={3} busy={phase === 'minting'}>
                {phase === 'name' && (
                  <div className="s-row">
                    <button
                      className="act lead"
                      onClick={mint}
                      disabled={!name.trim()}
                      title="verb: mint · writes the file and stamps its genesis seal"
                    >
                      mint
                    </button>
                  </div>
                )}
                {phase === 'minting' && (
                  <span className="minting" aria-live="polite">
                    <span className="label">writing</span>
                    <span className="mpath">{path}</span>
                  </span>
                )}
                {p >= at('minted') && (
                  <div className="seal-row">
                    <GenesisSeal />
                    <div className="gen">
                      <div className="hash-row">
                        <span className="hash" title="genesis hash · the vault's name to every other machine">
                          {GENESIS_SHOWN}
                        </span>
                        {copied ? (
                          <span className="meta-line" aria-live="polite">
                            copied
                          </span>
                        ) : (
                          <button className="act" onClick={copyHash} title="copy the genesis hash">
                            copy
                          </button>
                        )}
                      </div>
                      <div className="receipt">
                        <span className="seal seal-human" title="o · oleksii · owner">
                          o
                        </span>
                        <span className="meta-line">minted {mintedAt}</span>
                      </div>
                      <span className="s-note">The first record in the file.</span>
                    </div>
                  </div>
                )}
              </Step>

              {/* 3 · connect sources · each lands a receipt */}
              <Step state={s3} title="What it may read" index={4}>
                <div className="srcs">
                  {SOURCES.map((s) => {
                    const when = granted[s.id]
                    return (
                      <div key={s.id} className={`src-row${when ? ' granted' : ''}`}>
                        <span className="sname" title={s.tip}>
                          {s.name}
                        </span>
                        <span className="sdet">{s.detail}</span>
                        <span className="sact">
                          {when ? (
                            <span
                              className="rcpt"
                              title={`granted ${when} · reads, never writes · revocable at any time`}
                            >
                              granted · read-only
                            </span>
                          ) : s3 === 'live' ? (
                            <button
                              className="act"
                              onClick={() => grant(s.id)}
                              title="verb: connect_source · read-only, revocable"
                            >
                              connect
                            </button>
                          ) : null}
                        </span>
                      </div>
                    )
                  })}
                </div>
              </Step>

              {/* 4 · the first read, live */}
              <Step state={s4} title="The first read" index={5} busy={phase === 'indexing'}>
                {s4 !== 'wait' && (
                  <div className="counts">
                    <span className="c">
                      sources read <span className="n">{counts.sources}</span>
                    </span>
                    <span className="c">
                      claims proposed <span className="n">{counts.claims}</span>
                    </span>
                    {s4 === 'done' ? (
                      <a className="c" href="/app/inbox" title="they wait in the inbox">
                        for review <span className="n">{counts.review}</span>
                      </a>
                    ) : (
                      <span className="c">
                        for review <span className="n">{counts.review}</span>
                      </span>
                    )}
                  </div>
                )}
                {s4 === 'done' && (
                  <span className="s-note" aria-live="polite">
                    Read on this machine. Nothing was sent anywhere.
                  </span>
                )}
              </Step>

              {/* 5 · the first question → thin and true */}
              <Step state={s5} title="The first question" index={6}>
                {s5 !== 'wait' && (
                  <form className="ask-row" onSubmit={ask}>
                    <input
                      className="mfield"
                      value={question}
                      onChange={(e) => setQuestion(e.target.value)}
                      placeholder="ask the vault"
                      aria-label="ask the vault"
                      spellCheck={false}
                      autoFocus={s5 === 'live'}
                    />
                    <button className="act" type="submit" title="verb: recall · Enter asks">
                      ask
                    </button>
                  </form>
                )}
                {phase === 'answered' && (
                  <section className="instrument answer" aria-label="the first answer" key={answeredAt}>
                    <span className="label">recall · as of {answeredAt}</span>
                    <p className="claim conf-3" title="0.62 · one source · ~/notes">
                      You keep notes in ~/notes since 2024.
                    </p>
                    <span
                      className="meta-line withheld"
                      title="0.19 and 0.14 · one mention each · not enough to print"
                    >
                      2 candidates withheld · below the evidence floor
                    </span>
                    <p className="voice">The vault holds little on this yet. It will say so, every time.</p>
                  </section>
                )}
              </Step>

              {/* 6 · the vault is yours */}
              <Step state={s6} title="The vault is yours" index={7}>
                {s6 === 'live' && (
                  <div className="s-row">
                    <a className="cta" href="/app/recall" title="recall · ask the vault anything" onClick={() => cue('press')}>
                      open the vault
                    </a>
                  </div>
                )}
              </Step>
            </div>
          </section>
        </main>
      </div>
    </>
  )
}
