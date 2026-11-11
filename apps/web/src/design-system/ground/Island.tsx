import * as React from 'react'
import { bayerThreshold, develop, prefersReducedMotion } from '../lib/dither'
import { FIELD_ART, FIELD_CELL, FIELD_DOT, fieldTone, loadImage, resolvedColor, viewportSize } from '../lib/field-art'
import { cx, mergeRefs } from '../lib/react-utils'
import { useResolvedScheme } from '../lib/scheme'

/* Coverage of the even screen under the grain, and the share of the field's
   tone the grain carries on top of it. */
const GRAIN_FLOOR = 0.05
const GRAIN_TONE = 0.65

/* The grain: the field's print continued inside the island, in the island's
   own coordinates, at low contrast over a faint even screen. The cloud
   composition is the same in both schemes, so both print the same tone map;
   only the ink changes. */
function paintGrain(canvas: HTMLCanvasElement, island: HTMLElement, img: HTMLImageElement, animate: boolean) {
  const rect = island.getBoundingClientRect()
  const width = Math.max(1, Math.round(rect.width))
  const height = Math.max(1, Math.round(rect.height))
  canvas.width = width
  canvas.height = height
  const ctx = canvas.getContext('2d')
  if (!ctx) return () => {}
  const ink = resolvedColor(canvas)
  const viewport = viewportSize()
  const field = fieldTone(img, viewport.width, viewport.height)
  const cell = FIELD_CELL
  const c0 = Math.floor(rect.left / cell)
  const r0 = Math.floor(rect.top / cell)
  const ox = c0 * cell - rect.left
  const oy = r0 * cell - rect.top
  const columns = Math.ceil(width / cell) + 1
  const rows = Math.ceil(height / cell) + 1
  return develop(
    (exposure) => {
      ctx.clearRect(0, 0, width, height)
      ctx.fillStyle = ink
      for (let y = 0; y < rows; y++) {
        for (let x = 0; x < columns; x++) {
          const gx = c0 + x
          const gy = r0 + y
          const inside = gx >= 0 && gy >= 0 && gx < field.columns && gy < field.rows
          const t = inside ? field.tone[gy * field.columns + gx] : 0
          if ((GRAIN_FLOOR + t * GRAIN_TONE) * exposure > bayerThreshold(gx, gy)) {
            ctx.fillRect(ox + x * cell, oy + y * cell, FIELD_DOT, FIELD_DOT)
          }
        }
      }
    },
    { reduced: !animate || prefersReducedMotion() },
  )
}

export interface IslandProps extends React.ComponentPropsWithRef<'div'> {
  /* The quiet grain inside the well. On by default. */
  grain?: boolean
}

/* The one well carved into the field. Field shows around it (the caller
   keeps a gutter on at least three sides); inside, a quiet grain carries the
   material where the field is covered. */
export function Island({ ref, className, grain = true, children, ...props }: IslandProps) {
  const islandRef = React.useRef<HTMLDivElement | null>(null)
  const canvasRef = React.useRef<HTMLCanvasElement | null>(null)
  const scheme = useResolvedScheme()
  const developed = React.useRef(false)

  React.useEffect(() => {
    const island = islandRef.current
    const canvas = canvasRef.current
    if (!scheme || !grain || !island || !canvas) return
    let alive = true
    let cancel = () => {}
    let timer: ReturnType<typeof setTimeout> | undefined

    const paint = (animate: boolean) => {
      loadImage(FIELD_ART.night)
        .then((img) => {
          if (!alive) return
          cancel()
          cancel = paintGrain(canvas, island, img, animate)
        })
        .catch(() => {
          /* without the art the island stays a plain tone step */
        })
    }
    const repaint = () => {
      clearTimeout(timer)
      timer = setTimeout(() => paint(false), 120)
    }

    /* Layout settles once the fonts are in; the first paint waits for them. */
    const fontsReady = document.fonts?.ready ?? Promise.resolve()
    fontsReady.then(() => {
      if (!alive) return
      paint(!developed.current)
      developed.current = true
    })

    const observer = new ResizeObserver(() => {
      if (developed.current) repaint()
    })
    observer.observe(island)
    addEventListener('resize', repaint)
    return () => {
      alive = false
      cancel()
      clearTimeout(timer)
      observer.disconnect()
      removeEventListener('resize', repaint)
    }
  }, [scheme, grain])

  return (
    <div ref={mergeRefs(ref, islandRef)} className={cx('sl-island', className)} {...props}>
      {grain ? <canvas ref={canvasRef} className="sl-island-grain" aria-hidden="true" /> : null}
      {children}
    </div>
  )
}
