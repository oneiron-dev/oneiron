import { bayerThreshold } from './dither'

/* Resident glyphs as two printing plates on a 32x32 drawing box: the ink
   plate (lines and solids that always print) and the tone plate (half-tone
   areas the ordered dither screens). Seals and portraits sample these plates
   into coverage grids and print them at once; identity never animates. */

export const GLYPH_NAMES = ['wing', 'owl', 'laurel', 'ruler', 'moon'] as const
export type GlyphName = (typeof GLYPH_NAMES)[number]

type Plate = 'ink' | 'tone'
type DrawPlate = (ctx: CanvasRenderingContext2D, plate: Plate) => void

/* The laurel's spine: a cubic from the base to the tip, mirrored. */
export const LAUREL_SPINE: ReadonlyArray<readonly [number, number]> = [
  [15.2, 28.6],
  [7.4, 25.6],
  [4.2, 15.8],
  [9.4, 4.8],
]

export function laurelPoint(t: number): [number, number] {
  const u = 1 - t
  const P = LAUREL_SPINE
  const at = (k: 0 | 1) => u * u * u * P[0][k] + 3 * u * u * t * P[1][k] + 3 * u * t * t * P[2][k] + t * t * t * P[3][k]
  return [at(0), at(1)]
}

export function laurelTangent(t: number): [number, number] {
  const u = 1 - t
  const P = LAUREL_SPINE
  const at = (k: 0 | 1) =>
    3 * u * u * (P[1][k] - P[0][k]) + 6 * u * t * (P[2][k] - P[1][k]) + 3 * t * t * (P[3][k] - P[2][k])
  return [at(0), at(1)]
}

const PLATES: Record<GlyphName, DrawPlate> = {
  /* Two open wings over a small body. */
  wing(ctx, plate) {
    const wing = 'M15.6 25 C13 14 8 6 1.2 4 L2.2 11.4 L5.8 12.2 L4.4 16.6 L8.6 17.2 L8.4 21.2 L12.4 21.4 Z'
    const edge = 'M15.6 25 C13 14 8 6 1.2 4'
    for (const mirror of [1, -1]) {
      ctx.save()
      if (mirror < 0) {
        ctx.translate(32, 0)
        ctx.scale(-1, 1)
      }
      if (plate === 'tone') {
        ctx.globalAlpha = 0.62
        ctx.fill(new Path2D(wing))
      } else {
        ctx.lineWidth = 2
        ctx.lineCap = 'round'
        ctx.stroke(new Path2D(edge))
      }
      ctx.restore()
    }
    if (plate === 'ink') {
      ctx.beginPath()
      ctx.ellipse(16, 25, 1.8, 3.4, 0, 0, Math.PI * 2)
      ctx.fill()
    }
  },
  /* An owl's face: ear tufts, two eyes, a beak. */
  owl(ctx, plate) {
    const body = new Path2D(
      'M8.6 12 L6.4 4.6 L12.4 8.8 Q16 7.6 19.6 8.8 L25.6 4.6 L23.4 12 Q26.6 18 24 24 Q20.6 29.4 16 29.4 Q11.4 29.4 8 24 Q5.4 18 8.6 12 Z',
    )
    if (plate === 'tone') {
      ctx.globalAlpha = 0.5
      ctx.fill(body)
      ctx.globalAlpha = 1
      ctx.globalCompositeOperation = 'destination-out'
      for (const x of [11.6, 20.4]) {
        ctx.beginPath()
        ctx.arc(x, 14.6, 4.4, 0, Math.PI * 2)
        ctx.fill()
      }
      return
    }
    ctx.lineWidth = 1.5
    ctx.lineJoin = 'round'
    ctx.stroke(body)
    ctx.lineWidth = 1.7
    for (const x of [11.6, 20.4]) {
      ctx.beginPath()
      ctx.arc(x, 14.6, 3.7, 0, Math.PI * 2)
      ctx.stroke()
      ctx.beginPath()
      ctx.arc(x, 14.8, 1.3, 0, Math.PI * 2)
      ctx.fill()
    }
    ctx.fill(new Path2D('M14.6 18.4 L17.4 18.4 L16 21.6 Z'))
    ctx.lineWidth = 1.1
    ctx.stroke(new Path2D('M12.6 24.4 L14.2 23.2 L16 24.4 L17.8 23.2 L19.4 24.4'))
  },
  /* A laurel wreath: two curved stems with leaves. */
  laurel(ctx, plate) {
    const P = LAUREL_SPINE
    for (const mirror of [1, -1]) {
      ctx.save()
      if (mirror < 0) {
        ctx.translate(32, 0)
        ctx.scale(-1, 1)
      }
      if (plate === 'ink') {
        ctx.lineWidth = 1.4
        ctx.lineCap = 'round'
        ctx.beginPath()
        ctx.moveTo(P[0][0], P[0][1])
        ctx.bezierCurveTo(P[1][0], P[1][1], P[2][0], P[2][1], P[3][0], P[3][1])
        ctx.stroke()
      }
      ;[0.2, 0.37, 0.54, 0.71, 0.88].forEach((t, i) => {
        const [x, y] = laurelPoint(t)
        const [dx, dy] = laurelTangent(t)
        const angle = Math.atan2(dy, dx)
        const len = Math.hypot(dx, dy)
        const nx = dy / len
        const ny = -dx / len
        if (plate === 'ink') {
          ctx.save()
          ctx.translate(x - nx * 2.2, y - ny * 2.2)
          ctx.rotate(angle - 0.75)
          ctx.beginPath()
          ctx.ellipse(0, 0, 3.3, 1.35, 0, 0, Math.PI * 2)
          ctx.fill()
          ctx.restore()
        } else if (i < 4) {
          ctx.save()
          ctx.globalAlpha = 0.6
          ctx.translate(x + nx * 2.2, y + ny * 2.2)
          ctx.rotate(angle + 0.75)
          ctx.beginPath()
          ctx.ellipse(0, 0, 3, 1.3, 0, 0, Math.PI * 2)
          ctx.fill()
          ctx.restore()
        }
      })
      if (plate === 'ink') {
        ctx.save()
        ctx.translate(9.8, 3.6)
        ctx.rotate(-1.2)
        ctx.beginPath()
        ctx.ellipse(0, 0, 2.6, 1.2, 0, 0, Math.PI * 2)
        ctx.fill()
        ctx.restore()
      }
      ctx.restore()
    }
  },
  /* A ruler laid on the diagonal, alternate ticks long and short. */
  ruler(ctx, plate) {
    ctx.save()
    ctx.translate(16, 16)
    ctx.rotate(-Math.PI / 4)
    if (plate === 'tone') {
      ctx.globalAlpha = 0.42
      ctx.beginPath()
      ctx.moveTo(-14.5, 4.6)
      ctx.lineTo(14.5, 4.6)
      ctx.lineTo(-14.5, 15)
      ctx.closePath()
      ctx.fill()
    } else {
      ctx.lineWidth = 1.5
      ctx.lineJoin = 'round'
      ctx.strokeRect(-14, -2.6, 28, 5.2)
      ctx.lineWidth = 1.2
      ctx.lineCap = 'butt'
      for (let i = 0; i < 9; i++) {
        const x = -11.2 + i * 2.8
        ctx.beginPath()
        ctx.moveTo(x, -2.6)
        ctx.lineTo(x, i % 2 ? -0.2 : 2.6)
        ctx.stroke()
      }
    }
    ctx.restore()
  },
  /* A crescent moon with a small star. */
  moon(ctx, plate) {
    const moon = new Path2D('M16 4a8 8 0 0 0 12 12 12 12 0 1 1-12-12Z')
    if (plate === 'tone') {
      ctx.globalAlpha = 0.5
      ctx.fill(moon)
      return
    }
    ctx.lineWidth = 1.6
    ctx.lineJoin = 'round'
    ctx.lineCap = 'round'
    ctx.stroke(moon)
    ctx.lineWidth = 1.3
    ctx.stroke(new Path2D('M25.3 3.2v5.4M28 5.9h-5.4'))
  },
}

/* Samples one plate into a cells x cells grid of coverage in [0, 1],
   supersampled 4x4 per cell. Only alpha is read, so the fill colour is
   arbitrary. */
export function samplePlate(name: GlyphName, plate: Plate, cells: number): Float32Array {
  const SS = 4
  const S = cells * SS
  const canvas = document.createElement('canvas')
  canvas.width = canvas.height = S
  const ctx = canvas.getContext('2d', { willReadFrequently: true })
  const out = new Float32Array(cells * cells)
  if (!ctx) return out
  ctx.fillStyle = ctx.strokeStyle = 'black'
  ctx.scale(S / 32, S / 32)
  PLATES[name](ctx, plate)
  const data = ctx.getImageData(0, 0, S, S).data
  for (let cy = 0; cy < cells; cy++) {
    for (let cx = 0; cx < cells; cx++) {
      let a = 0
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) a += data[((cy * SS + sy) * S + cx * SS + sx) * 4 + 3]
      }
      out[cy * cells + cx] = a / (SS * SS * 255)
    }
  }
  return out
}

function parseRgb(color: string): [number, number, number] {
  const m = color.match(/[\d.]+/g)
  if (!m || m.length < 3) return [128, 128, 128]
  return [Number(m[0]), Number(m[1]), Number(m[2])]
}

/* The inset between a seal's frame and its print, by frame size. */
export function sealInset(size: number): number {
  return size >= 32 ? 3 : size >= 20 ? 2 : 1
}

/* A seal: the glyph printed inside a size x size frame (1 px border), ink
   lines at device resolution, tone screened at CSS resolution. */
export function paintSeal(canvas: HTMLCanvasElement, name: GlyphName, size: number, ink: string, dpr: number) {
  const N = size - 2 - sealInset(size) * 2
  const D = N * dpr
  const inkPlate = samplePlate(name, 'ink', D)
  const tonePlate = samplePlate(name, 'tone', N)
  canvas.width = canvas.height = D
  canvas.style.width = canvas.style.height = `${N}px`
  const ctx = canvas.getContext('2d')
  if (!ctx) return
  const img = ctx.createImageData(D, D)
  const px = img.data
  const [r, g, b] = parseRgb(ink)
  for (let y = 0; y < D; y++) {
    for (let x = 0; x < D; x++) {
      const k = inkPlate[y * D + x]
      let on: boolean
      if (k >= 0.5) on = true
      else {
        const cx = (x / dpr) | 0
        const cy = (y / dpr) | 0
        on = Math.max(tonePlate[cy * N + cx], k * 1.2) > bayerThreshold(cx, cy)
      }
      if (on) {
        const j = (y * D + x) * 4
        px[j] = r
        px[j + 1] = g
        px[j + 2] = b
        px[j + 3] = 255
      }
    }
  }
  ctx.putImageData(img, 0, 0)
}

/* A portrait: the same glyph, large, printed at the 3 px house dot. */
export function paintPortrait(canvas: HTMLCanvasElement, name: GlyphName, css: number, ink: string, dpr: number) {
  const cell = 3
  const cells = Math.floor(css / cell)
  const inkPlate = samplePlate(name, 'ink', cells)
  const tonePlate = samplePlate(name, 'tone', cells)
  canvas.width = canvas.height = cells * cell * dpr
  canvas.style.width = canvas.style.height = `${cells * cell}px`
  const ctx = canvas.getContext('2d')
  if (!ctx) return
  ctx.fillStyle = ink
  const dot = (cell - 1) * dpr
  for (let cy = 0; cy < cells; cy++) {
    for (let cx = 0; cx < cells; cx++) {
      const i = cy * cells + cx
      const k = inkPlate[i]
      const t = Math.max(tonePlate[i] * 0.85, k * 1.1, 0.035)
      if (k > 0.62 || t > bayerThreshold(cx, cy)) ctx.fillRect(cx * cell * dpr, cy * cell * dpr, dot, dot)
    }
  }
}

/* A person's portrait: their initial set once in the serif and printed like
   a seal, over a faint vignette screened in the second ink. */
export function paintInitialPortrait(
  canvas: HTMLCanvasElement,
  initial: string,
  css: number,
  ink: string,
  toneInk: string,
  serif: string,
  dpr: number,
) {
  const cell = css >= 100 ? 3 : 2
  const cells = Math.floor(css / cell)
  const S = cells * 4
  const source = document.createElement('canvas')
  source.width = source.height = S
  const sx = source.getContext('2d', { willReadFrequently: true })
  if (!sx) return
  sx.fillStyle = 'black'
  sx.textAlign = 'center'
  sx.textBaseline = 'middle'
  sx.font = `500 ${Math.round(S * 0.62)}px ${serif}`
  sx.fillText(initial, S / 2, S * 0.44)
  const data = sx.getImageData(0, 0, S, S).data
  canvas.width = canvas.height = cells * cell * dpr
  canvas.style.width = canvas.style.height = `${cells * cell}px`
  const ctx = canvas.getContext('2d')
  if (!ctx) return
  const dot = (cell - (cell > 2 ? 1 : 0.5)) * dpr
  for (let cy = 0; cy < cells; cy++) {
    for (let cx = 0; cx < cells; cx++) {
      let a = 0
      for (let yy = 0; yy < 4; yy++) {
        for (let xx = 0; xx < 4; xx++) a += data[((cy * 4 + yy) * S + cx * 4 + xx) * 4 + 3]
      }
      const k = a / (16 * 255)
      const dist = Math.hypot(cx - cells / 2 + 0.5, cy - cells / 2 + 0.5) / (cells / 2)
      const tone = dist < 1 ? 0.2 * (1 - dist * 0.6) : 0
      ctx.fillStyle = k > 0.45 ? ink : toneInk
      if (k > 0.45 || tone > bayerThreshold(cx, cy)) ctx.fillRect(cx * cell * dpr, cy * cell * dpr, dot, dot)
    }
  }
}

export function devicePixelRatioRounded(): number {
  return Math.max(1, Math.round(window.devicePixelRatio || 1))
}
