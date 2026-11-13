import * as React from 'react'
import { bayerThreshold } from '../lib/dither'
import { cx, mergeRefs } from '../lib/react-utils'
import { readScene, type SceneReading } from '../lib/scene'
import { useResolvedScheme } from '../lib/scheme'
import { hexToRgb } from '../lib/theme'
import { useRootTheme } from './root-theme'

/* One print cell, in CSS pixels. */
const CELL = 2

/* Prints the scene's tone map over the canvas, cover-fit: one canvas pixel
   per cell, each cell the lighter ink where its tone passes the cell's
   threshold in the 8 x 8 Bayer matrix, else the darker ink. */
function printScene(
  canvas: HTMLCanvasElement,
  width: number,
  height: number,
  reading: SceneReading,
  inkA: string,
  inkB: string,
) {
  const columns = Math.max(1, Math.ceil(width / CELL))
  const rows = Math.max(1, Math.ceil(height / CELL))
  canvas.width = columns
  canvas.height = rows
  canvas.style.width = `${columns * CELL}px`
  canvas.style.height = `${rows * CELL}px`
  const ctx = canvas.getContext('2d', { willReadFrequently: true })
  if (!ctx) return
  const tones = reading.tonePicture
  const scale = Math.max(columns / tones.width, rows / tones.height)
  const w = tones.width * scale
  const h = tones.height * scale
  ctx.imageSmoothingEnabled = true
  ctx.imageSmoothingQuality = 'high'
  ctx.drawImage(tones, (columns - w) / 2, (rows - h) / 2, w, h)
  const image = ctx.getImageData(0, 0, columns, rows)
  const px = image.data
  const a = hexToRgb(inkA)
  const b = hexToRgb(inkB)
  for (let y = 0, i = 0; y < rows; y++) {
    for (let x = 0; x < columns; x++, i += 4) {
      const ink = px[i] / 255 > bayerThreshold(x, y) ? b : a
      px[i] = ink[0]
      px[i + 1] = ink[1]
      px[i + 2] = ink[2]
      px[i + 3] = 255
    }
  }
  ctx.putImageData(image, 0, 0)
}

export interface WindowGroundProps extends Omit<React.ComponentPropsWithRef<'div'>, 'children'> {}

/* What shows around the sheet: it fills its parent, behind everything. A
   flat theme is one colour. A scene is its print: the tone map in the
   theme's two inks through an ordered screen, one cell per 2 CSS px. Until
   the scene's picture is read, and on the server, the ground is the flat
   tone, and the print takes its place with no change of layout. It redraws
   when its size changes, at most once per animation frame, and never
   animates. */
export function WindowGround({ ref, className, ...props }: WindowGroundProps) {
  const root = useRootTheme()
  const scheme = useResolvedScheme()
  const groundRef = React.useRef<HTMLDivElement | null>(null)
  const canvasRef = React.useRef<HTMLCanvasElement | null>(null)
  const [printed, setPrinted] = React.useState<string | null>(null)
  const { theme } = root
  const url = theme.kind === 'scene' && scheme ? (scheme === 'dark' ? theme.night : theme.day) : null
  const tones = scheme === 'dark' ? root.night : root.day
  const canPrint = url !== null && root.sceneRead
  const inkA = tones.groundA
  const inkB = tones.groundB

  React.useEffect(() => {
    const ground = groundRef.current
    const canvas = canvasRef.current
    if (!canPrint || !url || !ground || !canvas) return
    let alive = true
    let reading: SceneReading | null = null
    let frame = 0
    const draw = () => {
      frame = 0
      if (!alive || !reading) return
      printScene(canvas, ground.clientWidth, ground.clientHeight, reading, inkA, inkB)
      setPrinted(url)
    }
    const schedule = () => {
      if (frame === 0) frame = requestAnimationFrame(draw)
    }
    readScene(url)
      .then((r) => {
        reading = r
        schedule()
      })
      .catch(() => {
        /* without the picture the flat tone stays */
      })
    const observer = new ResizeObserver(schedule)
    observer.observe(ground)
    return () => {
      alive = false
      cancelAnimationFrame(frame)
      observer.disconnect()
    }
  }, [canPrint, url, inkA, inkB])

  return (
    <div
      ref={mergeRefs(ref, groundRef)}
      className={cx('sl-window-ground', className)}
      aria-hidden="true"
      data-kind={theme.kind}
      data-printed={canPrint && printed === url ? '' : undefined}
      {...props}
    >
      {theme.kind === 'scene' ? <canvas ref={canvasRef} className="sl-window-ground-print" /> : null}
    </div>
  )
}
