import * as React from 'react'
import { resolvedColor } from '../lib/field-art'
import { cx } from '../lib/react-utils'
import { useResolvedScheme } from '../lib/scheme'
import { devicePixelRatioRounded, paintInitialPortrait, paintPortrait, type GlyphName } from '../lib/seal-art'
import { GuestRing } from './GuestRing'

/* Printed size of the plate's picture, by portrait size. */
const PRINT_SIZE = { profile: 140, stack: 40 } as const

/* A face beside a name: in a message row, a crew stack, a list. */
export type PortraitFaceSize = 16 | 18 | 20 | 22 | 24 | 28 | 32

type PortraitForm =
  | {
      /* A resident's printed plate: its glyph, printed large. */
      glyph: GlyphName
      initial?: never
      src?: never
      /* `profile` heads a profile page; `stack` heads a crew popover. */
      size?: 'profile' | 'stack'
    }
  | {
      /* A person's printed plate: their initial, printed. */
      initial: string
      glyph?: never
      src?: never
      size?: 'profile' | 'stack'
    }
  | {
      /* A face as a picture, cropped round. If the picture cannot load,
         the initial shows on a disc (the label's first letter without one). */
      src: string
      initial?: string
      glyph?: never
      size: PortraitFaceSize
    }
  | {
      /* A person with no picture: the initial on a disc. */
      initial: string
      glyph?: never
      src?: never
      size: PortraitFaceSize
    }

export type PortraitProps = PortraitForm &
  Omit<React.ComponentPropsWithRef<'span'>, 'children'> & {
    label: string
    guest?: boolean
  }

/* A portrait. At `profile` and `stack` sizes, the dithered plate, painted
   once and fully exposed. At a face size (16 to 32 px), a picture cropped
   round with the image line inside its edge, or for a person with no
   picture the initial on a disc. Glyph stays the drawn mark of a resident.
   A portrait never moves. */
export function Portrait({ glyph, initial, src, label, size = 'profile', guest = false, className, style, ...props }: PortraitProps) {
  const canvasRef = React.useRef<HTMLCanvasElement | null>(null)
  const scheme = useResolvedScheme()
  const face = typeof size === 'number'
  /* The picture that failed to load, so a new src tries again. */
  const [failedSrc, setFailedSrc] = React.useState<string | null>(null)
  const picture = face && !!src && failedSrc !== src

  React.useEffect(() => {
    const canvas = canvasRef.current
    if (typeof size === 'number' || !canvas || !scheme) return
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

  const name = guest ? `${label}, a guest` : label
  const ring = guest ? <GuestRing className="sl-portrait-guest" /> : null

  if (typeof size === 'number') {
    return (
      <span
        role="img"
        aria-label={name}
        className={cx('sl-portrait', className)}
        data-size={size}
        data-form={picture ? 'picture' : 'disc'}
        style={{ '--sl-portrait-size': `${size}px`, ...style } as React.CSSProperties}
        {...props}
      >
        {picture ? (
          <img
            className="sl-portrait-picture"
            src={src}
            alt=""
            width={size}
            height={size}
            draggable={false}
            decoding="async"
            onError={() => setFailedSrc(src)}
          />
        ) : (
          <span className="sl-portrait-initial" aria-hidden="true">
            {initial ?? label.slice(0, 1).toLowerCase()}
          </span>
        )}
        {ring}
      </span>
    )
  }

  return (
    <span role="img" aria-label={name} className={cx('sl-portrait', className)} data-size={size} data-form="plate" style={style} {...props}>
      <canvas ref={canvasRef} className="sl-portrait-print" aria-hidden="true" />
      {ring}
    </span>
  )
}
