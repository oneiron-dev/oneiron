import { luminanceCoverage } from './dither'

/* The field art and how it maps onto a viewport. Night and day share one
   composition, so they share one crop: the crop starts under the moon (the
   day sun sits on the same pixel), and the remaining picture covers the
   viewport anchored at its bottom centre. */

export const FIELD_ART = {
  night: '/art/field-night.png',
  day: '/art/field-day.png',
} as const

/* Rows of the source picture above this line never show. */
export const FIELD_CROP_Y = 470

/* The print cell in CSS pixels; each printed dot is 2x2 inside it. */
export const FIELD_CELL = 3
export const FIELD_DOT = 2

export interface CoverRect {
  x: number
  y: number
  width: number
  height: number
}

/* Where the cropped picture lands on a width x height target: scaled to
   cover, centred horizontally, bottom-aligned. Pure. */
export function fieldCover(
  imageWidth: number,
  imageHeight: number,
  width: number,
  height: number,
  cropY = FIELD_CROP_Y,
): CoverRect {
  const sourceHeight = Math.max(1, imageHeight - cropY)
  const scale = Math.max(width / imageWidth, height / sourceHeight)
  const w = imageWidth * scale
  const h = sourceHeight * scale
  return { x: (width - w) / 2, y: height - h, width: w, height: h }
}

const images = new Map<string, Promise<HTMLImageElement>>()

/* One decoded image per URL for the page's lifetime. */
export function loadImage(src: string): Promise<HTMLImageElement> {
  let pending = images.get(src)
  if (!pending) {
    pending = new Promise((resolve, reject) => {
      const img = new Image()
      img.decoding = 'async'
      img.onload = () => resolve(img)
      img.onerror = () => {
        images.delete(src)
        reject(new Error(`field art failed to load: ${src}`))
      }
      img.src = src
    })
    images.set(src, pending)
  }
  return pending
}

/* Draws the cropped art covering a width x height context. */
export function drawFieldArt(ctx: CanvasRenderingContext2D, img: HTMLImageElement, width: number, height: number) {
  const r = fieldCover(img.naturalWidth, img.naturalHeight, width, height)
  ctx.drawImage(
    img,
    0,
    FIELD_CROP_Y,
    img.naturalWidth,
    img.naturalHeight - FIELD_CROP_Y,
    r.x,
    r.y,
    r.width,
    r.height,
  )
}

export interface ToneGrid {
  columns: number
  rows: number
  tone: Float32Array
}

/* The night art sampled at one value per print cell over a width x height
   viewport: the coverage each cell prints at full exposure. */
export function fieldTone(img: HTMLImageElement, width: number, height: number, cell = FIELD_CELL): ToneGrid {
  const columns = Math.max(1, Math.ceil(width / cell))
  const rows = Math.max(1, Math.ceil(height / cell))
  const canvas = document.createElement('canvas')
  canvas.width = columns
  canvas.height = rows
  const ctx = canvas.getContext('2d', { willReadFrequently: true })
  const tone = new Float32Array(columns * rows)
  if (!ctx) return { columns, rows, tone }
  drawFieldArt(ctx, img, columns, rows)
  const data = ctx.getImageData(0, 0, columns, rows).data
  for (let i = 0; i < columns * rows; i++) {
    tone[i] = luminanceCoverage(data[i * 4], data[i * 4 + 1], data[i * 4 + 2])
  }
  return { columns, rows, tone }
}

/* The viewport the field covers, in CSS pixels, without the scrollbar. */
export function viewportSize(): { width: number; height: number } {
  return {
    width: Math.max(1, document.documentElement.clientWidth || innerWidth),
    height: Math.max(1, innerHeight),
  }
}

/* A colour resolved by CSS for this element (custom properties hold
   unresolved light-dark() text, so canvas painters read a real property). */
export function resolvedColor(el: Element, property: 'color' | 'textDecorationColor' = 'color'): string {
  return getComputedStyle(el)[property]
}
