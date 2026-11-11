import * as React from 'react'
import { bayerThreshold, develop, prefersReducedMotion } from '../lib/dither'
import {
  FIELD_ART,
  FIELD_CELL,
  FIELD_DOT,
  drawFieldArt,
  fieldTone,
  loadImage,
  resolvedColor,
  viewportSize,
} from '../lib/field-art'
import { cx, mergeRefs } from '../lib/react-utils'
import { useResolvedScheme } from '../lib/scheme'

/* Night: share of a cell's tone that prints at full exposure. */
const NIGHT_STRENGTH = 0.8

/* The night field: the cloud art reduced to one tone per 3 px cell and
   printed through the Bayer screen in the field ink. */
function paintNight(
  canvas: HTMLCanvasElement,
  img: HTMLImageElement,
  width: number,
  height: number,
  animate: boolean,
): () => void {
  canvas.width = width
  canvas.height = height
  const ctx = canvas.getContext('2d')
  if (!ctx) return () => {}
  const ink = resolvedColor(canvas)
  const { columns, rows, tone } = fieldTone(img, width, height)
  return develop(
    (exposure) => {
      ctx.clearRect(0, 0, width, height)
      ctx.fillStyle = ink
      for (let y = 0; y < rows; y++) {
        for (let x = 0; x < columns; x++) {
          if (tone[y * columns + x] * NIGHT_STRENGTH * exposure > bayerThreshold(x, y)) {
            ctx.fillRect(x * FIELD_CELL, y * FIELD_CELL, FIELD_DOT, FIELD_DOT)
          }
        }
      }
    },
    { reduced: !animate || prefersReducedMotion() },
  )
}

/* The day field: the day art as drawn, exposed cell by cell in Bayer order
   while it develops. */
function paintDay(
  canvas: HTMLCanvasElement,
  img: HTMLImageElement,
  width: number,
  height: number,
  animate: boolean,
): () => void {
  const dpr = Math.max(1, Math.round(window.devicePixelRatio || 1))
  const W = width * dpr
  const H = height * dpr
  canvas.width = W
  canvas.height = H
  const ctx = canvas.getContext('2d')
  if (!ctx) return () => {}
  const art = document.createElement('canvas')
  art.width = W
  art.height = H
  const artCtx = art.getContext('2d')
  if (!artCtx) return () => {}
  drawFieldArt(artCtx, img, W, H)

  const columns = Math.ceil(width / FIELD_CELL)
  const rows = Math.ceil(height / FIELD_CELL)
  const mask = document.createElement('canvas')
  mask.width = columns
  mask.height = rows
  const maskCtx = mask.getContext('2d')
  const maskData = maskCtx?.createImageData(columns, rows)

  return develop(
    (exposure) => {
      ctx.globalCompositeOperation = 'source-over'
      ctx.clearRect(0, 0, W, H)
      ctx.drawImage(art, 0, 0)
      if (exposure >= 1 || !maskCtx || !maskData) return
      const px = maskData.data
      for (let y = 0; y < rows; y++) {
        for (let x = 0; x < columns; x++) {
          px[(y * columns + x) * 4 + 3] = exposure > bayerThreshold(x, y) ? 255 : 0
        }
      }
      maskCtx.putImageData(maskData, 0, 0)
      ctx.globalCompositeOperation = 'destination-in'
      ctx.imageSmoothingEnabled = false
      ctx.drawImage(mask, 0, 0, columns * FIELD_CELL * dpr, rows * FIELD_CELL * dpr)
      ctx.globalCompositeOperation = 'source-over'
    },
    { reduced: !animate || prefersReducedMotion() },
  )
}

export interface FieldProps extends Omit<React.ComponentPropsWithRef<'canvas'>, 'children'> {}

/* The full-viewport field behind the work. It develops once when it mounts
   (about a second; at once under reduced motion), then repaints at once on
   resize and when the scheme flips. */
export function Field({ ref, className, ...props }: FieldProps) {
  const canvasRef = React.useRef<HTMLCanvasElement | null>(null)
  const scheme = useResolvedScheme()
  const developed = React.useRef(false)

  React.useEffect(() => {
    const canvas = canvasRef.current
    if (!scheme || !canvas) return
    let alive = true
    let cancel = () => {}
    let timer: ReturnType<typeof setTimeout> | undefined

    const paint = (animate: boolean) => {
      const { width, height } = viewportSize()
      loadImage(scheme === 'dark' ? FIELD_ART.night : FIELD_ART.day)
        .then((img) => {
          if (!alive) return
          cancel()
          cancel =
            scheme === 'dark'
              ? paintNight(canvas, img, width, height, animate)
              : paintDay(canvas, img, width, height, animate)
        })
        .catch(() => {
          /* without the art the ground colour stands alone */
        })
    }

    paint(!developed.current)
    developed.current = true

    const onResize = () => {
      clearTimeout(timer)
      timer = setTimeout(() => paint(false), 120)
    }
    addEventListener('resize', onResize)
    return () => {
      alive = false
      cancel()
      clearTimeout(timer)
      removeEventListener('resize', onResize)
    }
  }, [scheme])

  return (
    <canvas
      ref={mergeRefs(ref, canvasRef)}
      className={cx('sl-field', className)}
      aria-hidden="true"
      data-scheme={scheme ?? undefined}
      {...props}
    />
  )
}
