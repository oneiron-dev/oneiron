import * as React from 'react'
import { resolvedColor } from '../lib/field-art'
import { cx } from '../lib/react-utils'
import { useResolvedScheme } from '../lib/scheme'
import { devicePixelRatioRounded, paintInitialPortrait, paintPortrait, type GlyphName } from '../lib/seal-art'
import { GuestRing } from './GuestRing'

/* Printed size of the plate's picture, by portrait size. */
const PRINT_SIZE = { profile: 140, stack: 40 } as const

type PortraitIdentity =
  | { /* A resident: its glyph, printed large. */ glyph: GlyphName; initial?: never }
  | { /* A person: their initial, printed. */ initial: string; glyph?: never }

export type PortraitProps = PortraitIdentity &
  Omit<React.ComponentPropsWithRef<'span'>, 'children'> & {
    label: string
    /* `profile` heads a profile page; `stack` heads a crew popover. */
    size?: 'profile' | 'stack'
    guest?: boolean
  }

/* The dithered portrait plate. Painted once, fully exposed; it never moves. */
export function Portrait({ glyph, initial, label, size = 'profile', guest = false, className, ...props }: PortraitProps) {
  const canvasRef = React.useRef<HTMLCanvasElement | null>(null)
  const scheme = useResolvedScheme()

  React.useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas || !scheme) return
    const css = PRINT_SIZE[size]
    const dpr = devicePixelRatioRounded()
    if (glyph) {
      paintPortrait(canvas, glyph, css, resolvedColor(canvas), dpr)
      return
    }
    if (!initial) return
    let alive = true
    const family = getComputedStyle(canvas).fontFamily
    const paint = () => {
      if (!alive) return
      paintInitialPortrait(
        canvas,
        initial,
        css,
        resolvedColor(canvas),
        resolvedColor(canvas, 'textDecorationColor'),
        family,
        dpr,
      )
    }
    const fonts = document.fonts
    if (fonts) fonts.load(`500 ${css}px ${family}`).then(paint, paint)
    else paint()
    return () => {
      alive = false
    }
  }, [glyph, initial, size, scheme])

  return (
    <span
      role="img"
      aria-label={guest ? `${label}, a guest` : label}
      className={cx('sl-portrait', className)}
      data-size={size}
      {...props}
    >
      <canvas ref={canvasRef} className="sl-portrait-print" aria-hidden="true" />
      {guest ? <GuestRing className="sl-portrait-guest" /> : null}
    </span>
  )
}
