import * as React from 'react'
import { resolvedColor } from '../lib/field-art'
import { cx } from '../lib/react-utils'
import { useResolvedScheme } from '../lib/scheme'
import { devicePixelRatioRounded, paintSeal, type GlyphName } from '../lib/seal-art'
import { GuestRing } from './GuestRing'

export type GlyphState = 'idle' | 'working' | 'waiting' | 'done'
export type GlyphShape = 'square' | 'rounded' | 'round'

const STATE_WORD: Record<GlyphState, string> = {
  idle: 'idle',
  working: 'working',
  waiting: 'waits on you',
  done: 'done',
}

type GlyphIdentity =
  | { /* A resident: its printed glyph. */ glyph: GlyphName; initial?: never }
  | { /* A person: their initial. */ initial: string; glyph?: never }

export type GlyphProps = GlyphIdentity &
  Omit<React.ComponentPropsWithRef<'span'>, 'children'> & {
    /* Who this is: the accessible name. */
    label: string
    size?: 18 | 24 | 32
    /* Defaults: residents square, people round. */
    shape?: GlyphShape
    /* Presence, derived by the caller from the process. Absent: no mark. */
    state?: GlyphState
    /* From another vault: the ring at the corner. */
    guest?: boolean
  }

/* A resident's printed glyph or a person's initial. The glyph itself never
   animates; a working state breathes on the dot beside it. */
export function Glyph({
  glyph,
  initial,
  label,
  size = 24,
  shape,
  state,
  guest = false,
  className,
  ...props
}: GlyphProps) {
  const kind = glyph ? 'resident' : 'person'
  const canvasRef = React.useRef<HTMLCanvasElement | null>(null)
  const scheme = useResolvedScheme()

  React.useEffect(() => {
    const canvas = canvasRef.current
    if (!glyph || !canvas || !scheme) return
    paintSeal(canvas, glyph, size, resolvedColor(canvas), devicePixelRatioRounded())
  }, [glyph, size, scheme])

  const name = [label, guest ? 'a guest' : null, state ? STATE_WORD[state] : null].filter(Boolean).join(', ')

  return (
    <span
      role="img"
      aria-label={name}
      className={cx('sl-glyph', className)}
      data-kind={kind}
      data-size={size}
      data-shape={shape ?? (kind === 'resident' ? 'square' : 'round')}
      {...props}
    >
      {glyph ? (
        <canvas ref={canvasRef} className="sl-glyph-print" aria-hidden="true" />
      ) : (
        <span className="sl-glyph-initial" aria-hidden="true">
          {initial}
        </span>
      )}
      {state ? (
        <span className="sl-glyph-state" data-state={state} aria-hidden="true">
          {state === 'done' ? (
            <svg viewBox="0 0 8 8" focusable="false">
              <path d="M1.4 4.2 3.2 6 6.6 2.2" />
            </svg>
          ) : null}
        </span>
      ) : null}
      {guest ? <GuestRing className="sl-glyph-guest" /> : null}
    </span>
  )
}
