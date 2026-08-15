import * as React from 'react'

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

export function Tuner({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [values, setValues] = React.useState<Values | null>(null)
  const [copied, setCopied] = React.useState(false)
  /* drag by the head; the spot is remembered */
  const [pos, setPos] = React.useState<{ x: number; y: number } | null>(null)
  const panel = React.useRef<HTMLElement>(null)
  React.useEffect(() => {
    try {
      const p = JSON.parse(localStorage.getItem('oneiron-tune-pos') || 'null')
      if (p && typeof p.x === 'number') setPos(p)
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
      const y = Math.max(0, Math.min(innerHeight - 40, ev.clientY - dy))
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

  if (!values) return null
  return (
    <aside
      ref={panel}
      className="tuner"
      hidden={!open}
      aria-label="tuner"
      style={pos ? { left: pos.x, top: pos.y, right: 'auto' } : undefined}
    >
      <div className="t-head" onPointerDown={onDrag}>
        <span className="label">tune</span>
        <button type="button" className="chat-close" onClick={onClose} aria-label="close">
          ×
        </button>
      </div>
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
    </aside>
  )
}
