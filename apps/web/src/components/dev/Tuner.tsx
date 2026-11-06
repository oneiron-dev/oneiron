import * as React from 'react'
import { clampTunerY } from '~/runtime/window-chrome'

/* the tuner · a DEV instrument, not product (owner 08-15 eve). sliders
   bound to the chassis measures and the light-room paper; the math lives
   in public/tune.js (it also restores before first paint), this panel
   only drives it. toggled with ` from the app layout. */

type Values = Record<string, number>
declare global {
  interface Window {
    oneironTune?: {
      DEFAULTS: Values
      PRESETS: Record<string, Partial<Values>>
      apply: (v: Partial<Values>) => Values
      clear: () => void
      save: (v: Values) => void
      load: () => Values | null
      reset: () => void
    }
  }
}

type Row = { key: string; label: string; min: number; max: number; step: number; fmt?: (n: number) => string }
type Section = { title: string; rows: Row[] }

const px = (n: number) => `${n}`
const SECTIONS: Section[] = [
  {
    title: 'sheet',
    rows: [
      { key: 'sheetLeft', label: 'gap · rail open', min: 0, max: 40, step: 1, fmt: px },
      { key: 'sheetLeftFolded', label: 'gap · rail folded', min: 0, max: 40, step: 1, fmt: px },
      { key: 'sheetBottom', label: 'gap · line', min: 28, max: 64, step: 1, fmt: px },
      { key: 'sheetTop', label: 'gap · top', min: 0, max: 32, step: 1, fmt: px },
      { key: 'sheetRight', label: 'gap · right', min: 0, max: 40, step: 1, fmt: px },
      { key: 'sheetRadius', label: 'radius', min: 0, max: 16, step: 1, fmt: px },
      { key: 'panePadX', label: 'inset · x', min: 8, max: 48, step: 1, fmt: px },
      { key: 'panePadY', label: 'inset · y', min: 8, max: 40, step: 1, fmt: px },
    ],
  },
  {
    title: 'rail',
    rows: [{ key: 'railW', label: 'width', min: 150, max: 260, step: 2, fmt: px }],
  },
  {
    title: 'column',
    rows: [
      { key: 'ctxW', label: 'width', min: 240, max: 440, step: 4, fmt: px },
      { key: 'ctxTint', label: 'tint', min: 0, max: 1, step: 0.05, fmt: (n) => n.toFixed(2) },
    ],
  },
  {
    title: 'paper · light room',
    rows: [
      { key: 'paperL', label: 'lightness', min: 0.86, max: 0.99, step: 0.002, fmt: (n) => n.toFixed(3) },
      { key: 'paperC', label: 'cream', min: 0, max: 0.03, step: 0.0005, fmt: (n) => n.toFixed(4) },
      { key: 'paperH', label: 'warmth', min: 40, max: 300, step: 1, fmt: (n) => `${n}°` },
      { key: 'sheetLift', label: 'sheet lift', min: 0, max: 0.06, step: 0.002, fmt: (n) => n.toFixed(3) },
      { key: 'wellDrop', label: 'well drop', min: 0, max: 0.08, step: 0.002, fmt: (n) => n.toFixed(3) },
      { key: 'inkShift', label: 'ink', min: -0.08, max: 0.08, step: 0.005, fmt: (n) => (n > 0 ? '+' : '') + n.toFixed(3) },
    ],
  },
  {
    title: 'texture',
    rows: [
      { key: 'grain', label: 'grain', min: 0, max: 0.14, step: 0.005, fmt: (n) => n.toFixed(3) },
      { key: 'plate', label: 'desk plate', min: 0, max: 0.6, step: 0.01, fmt: (n) => n.toFixed(2) },
    ],
  },
]

function clearWindowChrome(y: number): number {
  if (typeof document === 'undefined') return y
  const root = document.documentElement
  if (root.dataset.windowChrome !== 'macos') return y
  return clampTunerY(y, root.dataset.windowChrome, getComputedStyle(root).getPropertyValue('--desktop-top-inset'))
}

export function Tuner({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [values, setValues] = React.useState<Values | null>(null)
  const [copied, setCopied] = React.useState(false)
  /* drag by the head; the spot is remembered */
  const [pos, setPos] = React.useState<{ x: number; y: number } | null>(null)
  const panel = React.useRef<HTMLElement>(null)
  React.useEffect(() => {
    try {
      const p = JSON.parse(localStorage.getItem('oneiron-tune-pos') || 'null')
      if (p && typeof p.x === 'number') setPos({ ...p, y: clearWindowChrome(p.y) })
    } catch {
      /* default corner */
    }
  }, [])
  const onDrag = React.useCallback((e: React.PointerEvent) => {
    if ((e.target as HTMLElement).closest('button')) return
    const el = panel.current
    if (!el) return
    const r = el.getBoundingClientRect()
    const dx = e.clientX - r.left
    const dy = e.clientY - r.top
    const move = (ev: PointerEvent) => {
      const x = Math.max(0, Math.min(innerWidth - r.width, ev.clientX - dx))
      const y = clearWindowChrome(Math.max(0, Math.min(innerHeight - 40, ev.clientY - dy)))
      setPos({ x, y })
    }
    const up = () => {
      removeEventListener('pointermove', move)
      removeEventListener('pointerup', up)
      setPos((p) => {
        try { if (p) localStorage.setItem('oneiron-tune-pos', JSON.stringify(p)) } catch { /* */ }
        return p
      })
    }
    addEventListener('pointermove', move)
    addEventListener('pointerup', up)
    e.preventDefault()
  }, [])

  /* read the store on mount (window-only) */
  React.useEffect(() => {
    const t = window.oneironTune
    if (!t) return
    setValues({ ...t.DEFAULTS, ...(t.load() ?? {}) })
  }, [])

  const set = React.useCallback((key: string, n: number) => {
    setValues((prev) => {
      const t = window.oneironTune
      if (!prev || !t) return prev
      const next = { ...prev, [key]: n }
      t.apply(next)
      t.save(next)
      return next
    })
  }, [])

  const preset = React.useCallback((name: string) => {
    const t = window.oneironTune
    if (!t) return
    const next: Values = { ...t.DEFAULTS, ...(t.PRESETS[name] as Values) }
    t.apply(next)
    t.save(next)
    setValues(next)
  }, [])

  const reset = React.useCallback(() => {
    const t = window.oneironTune
    if (!t) return
    t.reset()
    setValues({ ...t.DEFAULTS })
  }, [])

  const copy = React.useCallback(async () => {
    if (!values) return
    const t = window.oneironTune
    const diff: Values = {}
    for (const k of Object.keys(values)) if (!t || values[k] !== t.DEFAULTS[k]) diff[k] = values[k]
    try {
      await navigator.clipboard.writeText(JSON.stringify(diff, null, 2))
      setCopied(true)
      setTimeout(() => setCopied(false), 1200)
    } catch {
      /* clipboard denied · the values stay in localStorage */
    }
  }, [values])

  /* the open law (rule 39, owner picks by feel): stored, broadcast */
  const [openLaw, setOpenLaw] = React.useState<'gesture' | 'column' | 'kind'>('kind')
  React.useEffect(() => {
    try {
      const v = localStorage.getItem('oneiron-open-law')
      if (v === 'gesture' || v === 'column' || v === 'kind') setOpenLaw(v)
    } catch {
      /* default */
    }
  }, [])
  const setLaw = React.useCallback((k: 'gesture' | 'column' | 'kind') => {
    setOpenLaw(k)
    try {
      localStorage.setItem('oneiron-open-law', k)
    } catch {
      /* session only */
    }
    dispatchEvent(new CustomEvent('oneiron:openlaw', { detail: k }))
  }, [])

  /* the roster face (owner 08-18: unsure about the portrait in the table) */
  const [rosterFace, setRosterFaceState] = React.useState<'portrait' | 'mark' | 'none'>('none')
  React.useEffect(() => {
    try {
      const v = localStorage.getItem('oneiron-roster-face')
      if (v === 'portrait' || v === 'mark' || v === 'none') {
        setRosterFaceState(v)
        document.documentElement.setAttribute('data-roster-face', v)
      }
    } catch {
      /* default */
    }
  }, [])
  const setRosterFace = React.useCallback((k: 'portrait' | 'mark' | 'none') => {
    setRosterFaceState(k)
    document.documentElement.setAttribute('data-roster-face', k)
    try {
      localStorage.setItem('oneiron-roster-face', k)
    } catch {
      /* session only */
    }
  }, [])

  /* the portrait style (owner 09-07, A): the gods on the sheet; cut is the default, the others ride for the pick */
  type FaceStyle = 'cut' | 'base' | 'trink' | 'dream'
  const [faceStyle, setFaceStyleState] = React.useState<FaceStyle>('cut')
  React.useEffect(() => {
    try {
      const v = localStorage.getItem('oneiron-face-style')
      if (v === 'base' || v === 'trink' || v === 'dream') setFaceStyleState(v)
    } catch {
      /* default */
    }
  }, [])
  const setFaceStyle = React.useCallback((k: FaceStyle) => {
    setFaceStyleState(k)
    if (k === 'cut') document.documentElement.removeAttribute('data-face-style')
    else document.documentElement.setAttribute('data-face-style', k)
    try {
      if (k === 'cut') localStorage.removeItem('oneiron-face-style')
      else localStorage.setItem('oneiron-face-style', k)
    } catch {
      /* session only */
    }
  }, [])

  /* your voice in the room (owner 09-08: never a name; position or type carries it) */
  type Voice = 'right' | 'indent' | 'mono' | 'glyph'
  const [voice, setVoiceState] = React.useState<Voice>('right')
  React.useEffect(() => {
    try {
      const v = localStorage.getItem('oneiron-voice')
      if (v === 'indent' || v === 'mono' || v === 'glyph') setVoiceState(v)
    } catch {
      /* default */
    }
  }, [])
  const setVoice = React.useCallback((k: Voice) => {
    setVoiceState(k)
    if (k === 'right') document.documentElement.removeAttribute('data-voice')
    else document.documentElement.setAttribute('data-voice', k)
    try {
      if (k === 'right') localStorage.removeItem('oneiron-voice')
      else localStorage.setItem('oneiron-voice', k)
    } catch {
      /* session only */
    }
  }, [])

  /* the ground under your turns: none · well · hairline (the surface ladder's rungs) */
  type Ground = 'well' | 'none' | 'hairline'
  const [ground, setGroundState] = React.useState<Ground>('well')
  React.useEffect(() => {
    try {
      const v = localStorage.getItem('oneiron-voice-ground')
      if (v === 'none' || v === 'hairline') setGroundState(v)
    } catch {
      /* default */
    }
  }, [])
  const setGround = React.useCallback((k: Ground) => {
    setGroundState(k)
    if (k === 'well') document.documentElement.removeAttribute('data-voice-ground')
    else document.documentElement.setAttribute('data-voice-ground', k)
    try {
      if (k === 'well') localStorage.removeItem('oneiron-voice-ground')
      else localStorage.setItem('oneiron-voice-ground', k)
    } catch {
      /* session only */
    }
  }, [])

  /* the selected row's chrome (owner 09-07: the rounded well reads as slop; he picks by feel) */
  type SelChrome = 'rounded' | 'square' | 'gutter' | 'box'
  const [selChrome, setSelChromeState] = React.useState<SelChrome>('rounded')
  React.useEffect(() => {
    try {
      const v = localStorage.getItem('oneiron-select-chrome')
      if (v === 'square' || v === 'gutter' || v === 'box') setSelChromeState(v)
    } catch {
      /* default */
    }
  }, [])
  const setSelChrome = React.useCallback((k: SelChrome) => {
    setSelChromeState(k)
    if (k === 'rounded') document.documentElement.removeAttribute('data-select-chrome')
    else document.documentElement.setAttribute('data-select-chrome', k)
    try {
      if (k === 'rounded') localStorage.removeItem('oneiron-select-chrome')
      else localStorage.setItem('oneiron-select-chrome', k)
    } catch {
      /* session only */
    }
  }, [])

  /* the picker (owner 09-08): where the agent list lives */
  type Picker = 'well' | 'sidebar' | 'rail' | 'ground'
  const [picker, setPickerState] = React.useState<Picker>('rail')
  React.useEffect(() => {
    try {
      const v = localStorage.getItem('oneiron-picker')
      if (v === 'well' || v === 'sidebar' || v === 'ground') setPickerState(v)
    } catch {
      /* default */
    }
  }, [])
  const setPicker = React.useCallback((k: Picker) => {
    setPickerState(k)
    if (k === 'rail') document.documentElement.removeAttribute('data-picker')
    else document.documentElement.setAttribute('data-picker', k)
    try {
      if (k === 'rail') localStorage.removeItem('oneiron-picker')
      else localStorage.setItem('oneiron-picker', k)
    } catch {
      /* session only */
    }
  }, [])
  /* the work (owner 09-08): where an agent's live work prints */
  type Work = 'thread' | 'pane'
  const [work, setWorkState] = React.useState<Work>('thread')
  React.useEffect(() => {
    try {
      const v = localStorage.getItem('oneiron-work')
      if (v === 'pane') setWorkState(v)
    } catch {
      /* default */
    }
  }, [])
  const setWork = React.useCallback((k: Work) => {
    setWorkState(k)
    if (k === 'thread') document.documentElement.removeAttribute('data-work-axis')
    else document.documentElement.setAttribute('data-work-axis', k)
    try {
      if (k === 'thread') localStorage.removeItem('oneiron-work')
      else localStorage.setItem('oneiron-work', k)
    } catch {
      /* session only */
    }
  }, [])

  /* the column's place (owner 09-08): left · center · dock */
  type RoomCol = 'left' | 'center' | 'dock'
  const [roomCol, setRoomColState] = React.useState<RoomCol>('left')
  React.useEffect(() => {
    try {
      const v = localStorage.getItem('oneiron-room-column')
      if (v === 'center' || v === 'dock') setRoomColState(v)
    } catch {
      /* default */
    }
  }, [])
  const setRoomCol = React.useCallback((k: RoomCol) => {
    setRoomColState(k)
    if (k === 'left') document.documentElement.removeAttribute('data-room-column')
    else document.documentElement.setAttribute('data-room-column', k)
    try {
      if (k === 'left') localStorage.removeItem('oneiron-room-column')
      else localStorage.setItem('oneiron-room-column', k)
    } catch {
      /* session only */
    }
  }, [])

  /* your turn in a group room (owner 09-08, "show both"): well = right, on a
     well, no name (as ruled) · stack = a head row that says you, the words
     under it, like everyone else (Slack) */
  type MyTurn = 'well' | 'stack'
  const [myTurn, setMyTurnState] = React.useState<MyTurn>('well')
  React.useEffect(() => {
    try {
      if (localStorage.getItem('oneiron-my-turn') === 'stack') setMyTurnState('stack')
    } catch {
      /* default */
    }
  }, [])
  const setMyTurn = React.useCallback((k: MyTurn) => {
    setMyTurnState(k)
    if (k === 'well') document.documentElement.removeAttribute('data-my-turn')
    else document.documentElement.setAttribute('data-my-turn', k)
    try {
      if (k === 'well') localStorage.removeItem('oneiron-my-turn')
      else localStorage.setItem('oneiron-my-turn', k)
    } catch {
      /* session only */
    }
  }, [])

  /* reset all (owner 09-08): every switch and dial back to the defaults.
     The switch keys are cleared here, the dials by the store; a reload
     lets prepaint restore the defaults in one pass. */
  const resetAll = React.useCallback(() => {
    const t = window.oneironTune
    t?.reset()
    try {
      for (const k of ['oneiron-face-style', 'oneiron-my-turn', 'oneiron-open-law', 'oneiron-picker', 'oneiron-room-column', 'oneiron-roster-face', 'oneiron-select-chrome', 'oneiron-tune-pos', 'oneiron-voice-ground', 'oneiron-voice', 'oneiron-work'])
        localStorage.removeItem(k)
    } catch {
      /* session only */
    }
    location.reload()
  }, [])
  /* the dials fold (owner 09-08: "the tuner is long") — the switches stand
     first; the measures and the paper open on demand */
  const [dialsOpen, setDialsOpen] = React.useState(false)
  const [settledOpen, setSettledOpen] = React.useState(false)

  if (!values) return null
  return (
    <aside
      ref={panel}
      className="tuner"
      hidden={!open}
      aria-label="tuner"
      style={pos ? { left: pos.x, top: clearWindowChrome(pos.y), right: 'auto' } : undefined}
    >
      <div className="t-head" onPointerDown={onDrag}>
        <span className="label">tune</span>
        <button type="button" className="act" title="every switch and dial back to the defaults · reloads" onClick={resetAll}>
          reset all
        </button>
        <button type="button" className="chat-close" onClick={onClose} aria-label="close">
          ×
        </button>
      </div>
      <div className="t-sec">picker</div>
      <div className="t-acts">
        {(['rail', 'well', 'sidebar', 'ground'] as const).map((k) => (
          <button
            key={k}
            type="button"
            className={picker === k ? 'act on' : 'act'}
            title={k === 'rail' ? 'the rooms section in the rail (the pick, 09-08)' : k === 'well' ? 'bench: the roster as a well column beside the room' : k === 'sidebar' ? 'bench: the roster flush to the sheet edge' : 'bench: the ground line as the picker on this page'}
            onClick={() => setPicker(k)}
          >
            {k}
          </button>
        ))}
      </div>
      <div className="t-sec">work</div>
      <div className="t-acts">
        {(['thread', 'pane'] as const).map((k) => (
          <button
            key={k}
            type="button"
            className={work === k ? 'act on' : 'act'}
            title={k === 'thread' ? 'the live run as a card at the foot of the conversation + the agent bar (as built)' : 'one mark at the room’s top right · click docks the work pane (the Codex shape)'}
            onClick={() => setWork(k)}
          >
            {k}
          </button>
        ))}
      </div>
      <div className="t-sec">room column</div>
      <div className="t-acts">
        {(['left', 'center', 'dock'] as const).map((k) => (
          <button
            key={k}
            type="button"
            className={roomCol === k ? 'act on' : 'act'}
            title={k === 'left' ? 'the column at the left, the pane at the far right (as built)' : k === 'center' ? 'the column centers in the space beside the pane, in the whole room while it is closed (Claude, ChatGPT)' : 'the pane docks beside the column at the left; the air stays right'}
            onClick={() => setRoomCol(k)}
          >
            {k}
          </button>
        ))}
      </div>
      <div className="t-sec">your turn · house</div>
      <div className="t-acts">
        {(['well', 'stack'] as const).map((k) => (
          <button
            key={k}
            type="button"
            className={myTurn === k ? 'act on' : 'act'}
            title={k === 'well' ? 'right, on a well, no name (as ruled)' : 'stacked like everyone: a head row that says you, the words under it (Slack)'}
            onClick={() => setMyTurn(k)}
          >
            {k}
          </button>
        ))}
      </div>
      <button type="button" className="t-fold" aria-expanded={settledOpen} onClick={() => setSettledOpen((o) => !o)}>
        <span className="t-sec">settled · earlier picks</span>
        <span className="chev" aria-hidden="true">
          {settledOpen ? '▾' : '›'}
        </span>
      </button>
      {settledOpen ? (
        <>
      <div className="t-sec">open law · rule 39</div>
      <div className="t-acts">
        {(['gesture', 'column', 'kind'] as const).map((k) => (
          <button
            key={k}
            type="button"
            className={openLaw === k ? 'act on' : 'act'}
            title={
              k === 'gesture'
                ? 'click = under the row · open = the column (reads only)'
                : k === 'column'
                  ? 'every row opens the column, drafts too'
                  : 'acts under the row · records in the column (as built)'
            }
            onClick={() => setLaw(k)}
          >
            {k}
          </button>
        ))}
      </div>
      <div className="t-sec">roster face</div>
      <div className="t-acts">
        {(['portrait', 'mark', 'none'] as const).map((k) => (
          <button
            key={k}
            type="button"
            className={rosterFace === k ? 'act on' : 'act'}
            title={k === 'portrait' ? 'the portrait at 32px in the row' : k === 'mark' ? 'the attribute mark beside the name' : 'no face in the roster · the name in its ink (A, owner 09-07)'}
            onClick={() => setRosterFace(k)}
          >
            {k}
          </button>
        ))}
      </div>
      <div className="t-sec">portrait style</div>
      <div className="t-acts">
        {(['cut', 'base', 'trink', 'dream'] as const).map((k) => (
          <button
            key={k}
            type="button"
            className={faceStyle === k ? 'act on' : 'act'}
            title={k === 'cut' ? 'linocut · solid ink, holds at 24' : k === 'base' ? 'the 08-18 riso reference' : k === 'trink' ? 'two inks · the red is lost in a mask' : 'dream print · edges dissolve'}
            onClick={() => setFaceStyle(k)}
          >
            {k}
          </button>
        ))}
      </div>
      <div className="t-sec">your voice</div>
      <div className="t-acts">
        {(['right', 'indent', 'mono', 'glyph'] as const).map((k) => (
          <button
            key={k}
            type="button"
            className={voice === k ? 'act on' : 'act'}
            title={k === 'right' ? 'your turns end at the text column’s right edge (his pick)' : k === 'indent' ? 'your turns start a fifth of the way in, same serif' : k === 'mono' ? 'you type in mono, the agent writes in serif' : 'a silver › opens your turns at the margin'}
            onClick={() => setVoice(k)}
          >
            {k}
          </button>
        ))}
      </div>
      <div className="t-sec">your ground</div>
      <div className="t-acts">
        {(['well', 'none', 'hairline'] as const).map((k) => (
          <button
            key={k}
            type="button"
            className={ground === k ? 'act on' : 'act'}
            title={k === 'well' ? 'a tinted zone under your turns · flat, 3px, no tail (his pick)' : k === 'none' ? 'position alone carries your turns' : 'a hairline frame under your turns'}
            onClick={() => setGround(k)}
          >
            {k}
          </button>
        ))}
      </div>
      <div className="t-sec">select chrome</div>
      <div className="t-acts">
        {(['rounded', 'square', 'gutter', 'box'] as const).map((k) => (
          <button
            key={k}
            type="button"
            className={selChrome === k ? 'act on' : 'act'}
            title={k === 'rounded' ? 'the well on a 5px radius (as built)' : k === 'square' ? 'the well, square corners' : k === 'gutter' ? 'no fill · a hair of ink at the left edge' : 'no fill where a checkbox already says it (the vault); the open row keeps its bar'}
            onClick={() => setSelChrome(k)}
          >
            {k}
          </button>
        ))}
      </div>
        </>
      ) : null}
      <button type="button" className="t-fold" aria-expanded={dialsOpen} onClick={() => setDialsOpen((o) => !o)}>
        <span className="t-sec">dials · measures and paper</span>
        <span className="chev" aria-hidden="true">
          {dialsOpen ? '▾' : '›'}
        </span>
      </button>
      {dialsOpen ? (
        <>
      {SECTIONS.map((sec) => (
        <React.Fragment key={sec.title}>
          <div className="t-sec">{sec.title}</div>
          {sec.rows.map((r) => (
            <label key={r.key} className="t-row">
              <span>{r.label}</span>
              <input
                type="range"
                min={r.min}
                max={r.max}
                step={r.step}
                value={values[r.key]}
                onChange={(e) => set(r.key, Number(e.target.value))}
              />
              <span>{r.fmt ? r.fmt(values[r.key]) : values[r.key]}</span>
            </label>
          ))}
        </React.Fragment>
      ))}
      <div className="t-sec">presets</div>
      <div className="t-acts">
        <button type="button" className="act" onClick={() => preset('current')}>current</button>
        <button type="button" className="act" onClick={() => preset('paper')}>paper</button>
        <button type="button" className="act" onClick={() => preset('stock')}>stock</button>
        <button type="button" className="act" onClick={() => preset('neutral')}>neutral</button>
      </div>
      <div className="t-acts">
        <button type="button" className={copied ? 'act on' : 'act'} onClick={copy}>{copied ? 'copied' : 'copy values'}</button>
        <button type="button" className="act" onClick={reset}>reset</button>
      </div>
        </>
      ) : null}
    </aside>
  )
}
