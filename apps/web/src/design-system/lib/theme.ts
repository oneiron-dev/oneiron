/* Themes and the colour arithmetic behind them: OKLab and OKLCH
   conversions, APCA contrast, a theme's seed (a hue and a chroma) read
   from a colour or a picture, the tone map a scene prints from, and the
   tones a theme adds to the tokens. Pure functions and data only; nothing
   here touches the DOM, so all of it runs in tests. */

/* ── themes ───────────────────────────────────────────────────────────── */

/* A theme is one flat colour, or a scene: a picture for day and one for
   night (URLs). The tones around the sheet are computed from it. */
export type Theme = { id: string; label: string } & (
  | { kind: 'flat'; colour: string }
  | { kind: 'scene'; day: string; night: string }
)

export const THEMES = [
  { id: 'deep-sea', label: 'deep sea', kind: 'flat', colour: '#074B7B' },
  { id: 'plum', label: 'plum', kind: 'flat', colour: '#6B3F6E' },
  { id: 'moss', label: 'moss', kind: 'flat', colour: '#4E7A5A' },
] as const satisfies readonly Theme[]

export const DEFAULT_THEME: Theme = THEMES[0]

/* The colour that stands in for a scene until its pictures are read: the
   default theme's, so a scene's first paint is a flat ground. */
export const SCENE_STAND_IN_COLOUR: string = THEMES[0].colour

/* ── conversions ──────────────────────────────────────────────────────── */

/* Lightness 0 to 1, chroma from 0, hue in degrees from 0 up to 360. */
export interface Oklch {
  l: number
  c: number
  h: number
}

const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v))

function srgbToLinear(channel: number): number {
  const c = channel / 255
  return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4
}

function linearToSrgb(linear: number): number {
  const c = clamp(linear, 0, 1)
  return c <= 0.0031308 ? c * 12.92 : 1.055 * c ** (1 / 2.4) - 0.055
}

/* `#RRGGBB` (or `#RGB`) to its three 0..255 channels. */
export function hexToRgb(hex: string): [number, number, number] {
  let h = hex.trim().replace(/^#/, '')
  if (h.length === 3) h = h.replace(/./g, (d) => d + d)
  if (!/^[0-9a-fA-F]{6}$/.test(h)) throw new Error(`not a hex colour: ${hex}`)
  return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)]
}

/* sRGB channels (0..255) to OKLab [L, a, b]. */
export function rgbToOklab(r: number, g: number, b: number): [number, number, number] {
  const lr = srgbToLinear(r)
  const lg = srgbToLinear(g)
  const lb = srgbToLinear(b)
  const l = Math.cbrt(0.4122214708 * lr + 0.5363325363 * lg + 0.0514459929 * lb)
  const m = Math.cbrt(0.2119034982 * lr + 0.6806995451 * lg + 0.1073969566 * lb)
  const s = Math.cbrt(0.0883024619 * lr + 0.2817188376 * lg + 0.6299787005 * lb)
  return [
    0.2104542553 * l + 0.793617785 * m - 0.0040720468 * s,
    1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s,
    0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s,
  ]
}

function labToLch(L: number, a: number, b: number): Oklch {
  const h = (Math.atan2(b, a) * 180) / Math.PI
  return { l: L, c: Math.hypot(a, b), h: h < 0 ? h + 360 : h }
}

export function hexToOklch(hex: string): Oklch {
  const [r, g, b] = hexToRgb(hex)
  return labToLch(...rgbToOklab(r, g, b))
}

/* Tolerance on each linear channel when deciding a colour is inside sRGB. */
const GAMUT_EPSILON = 1e-4
/* Out of gamut: chroma is multiplied by this until the colour fits. */
const GAMUT_PULL = 0.94
const GAMUT_STEPS = 40

/* OKLCH to an sRGB hex. A colour outside sRGB keeps its lightness and hue
   and loses chroma, a factor of 0.94 at a time (at most 40 times); what is
   still outside after that is clipped per channel. */
export function oklchToHex(l: number, c: number, hueDegrees: number): string {
  const h = (hueDegrees * Math.PI) / 180
  let a = c * Math.cos(h)
  let b = c * Math.sin(h)
  let lin: [number, number, number] = [0, 0, 0]
  for (let step = 0; step < GAMUT_STEPS; step++) {
    const l3 = (l + 0.3963377774 * a + 0.2158037573 * b) ** 3
    const m3 = (l - 0.1055613458 * a - 0.0638541728 * b) ** 3
    const s3 = (l - 0.0894841775 * a - 1.291485548 * b) ** 3
    lin = [
      4.0767416621 * l3 - 3.3077115913 * m3 + 0.2309699292 * s3,
      -1.2684380046 * l3 + 2.6097574011 * m3 - 0.3413193965 * s3,
      -0.0041960863 * l3 - 0.7034186147 * m3 + 1.707614701 * s3,
    ]
    if (Math.min(...lin) >= -GAMUT_EPSILON && Math.max(...lin) <= 1 + GAMUT_EPSILON) break
    a *= GAMUT_PULL
    b *= GAMUT_PULL
  }
  return (
    '#' +
    lin
      .map((v) =>
        Math.round(linearToSrgb(v) * 255)
          .toString(16)
          .padStart(2, '0'),
      )
      .join('')
      .toUpperCase()
  )
}

/* ── contrast ─────────────────────────────────────────────────────────── */

/* Screen luminance as APCA reads it, with the soft clamp near black. */
function apcaY([r, g, b]: [number, number, number]): number {
  const y = 0.2126729 * (r / 255) ** 2.4 + 0.7151522 * (g / 255) ** 2.4 + 0.072175 * (b / 255) ** 2.4
  return y < 0.022 ? y + (0.022 - y) ** 1.414 : y
}

/* APCA lightness contrast (Lc) of text on a ground, as an absolute value:
   dark text on a light ground and light text on a dark one both come out
   positive. 60 is the floor for text a person reads, 75 is comfortable. */
export function apcaLc(textHex: string, groundHex: string): number {
  const yt = apcaY(hexToRgb(textHex))
  const yb = apcaY(hexToRgb(groundHex))
  if (yb > yt) {
    const darkText = (yb ** 0.56 - yt ** 0.57) * 1.14
    return darkText < 0.1 ? 0 : (darkText - 0.027) * 100
  }
  const lightText = (yb ** 0.65 - yt ** 0.62) * 1.14
  return lightText > -0.1 ? 0 : Math.abs((lightText + 0.027) * 100)
}

/* ── seeds and tone maps ──────────────────────────────────────────────── */

/* The colour a theme is built from: a hue in degrees and an OKLCH chroma. */
export interface ThemeSeed {
  hue: number
  chroma: number
}

/* RGBA pixels, row-major, as a canvas hands them out (ImageData fits). */
export interface PixelData {
  data: ArrayLike<number>
  width: number
  height: number
}

/* One value per pixel, 0..1, row-major. */
export interface ToneMap {
  width: number
  height: number
  values: Float32Array
}

export function themeSeedFromColour(hex: string): ThemeSeed {
  const { c, h } = hexToOklch(hex)
  return { hue: h, chroma: c }
}

/* Share of the picture, from the top, whose mean colour seeds the theme:
   the sky of a scene, not its ground. */
const SEED_ROWS = 0.6

/* The hue and chroma of the mean OKLab colour of the picture's upper 60 %. */
export function themeSeedFromPixels(pixels: PixelData): ThemeSeed {
  const rows = Math.max(1, Math.floor(pixels.height * SEED_ROWS))
  const count = rows * pixels.width
  let sa = 0
  let sb = 0
  for (let i = 0; i < count; i++) {
    const p = i * 4
    const [, a, b] = rgbToOklab(pixels.data[p], pixels.data[p + 1], pixels.data[p + 2])
    sa += a
    sb += b
  }
  const { c, h } = labToLch(0, sa / count, sb / count)
  return { hue: h, chroma: c }
}

/* The value at percentile p (0..100) of sorted values, interpolated
   linearly between neighbours. */
function percentile(sorted: Float32Array, p: number): number {
  if (sorted.length === 0) return 0
  const at = (p / 100) * (sorted.length - 1)
  const lo = Math.floor(at)
  const hi = Math.min(sorted.length - 1, lo + 1)
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (at - lo)
}

/* A tone map's ends: the darkest and the lightest cell never reach the
   threshold matrix's extremes, so both inks always show a little. */
export const TONE_FLOOR = 0.07
export const TONE_SPAN = 0.86
const TONE_LOW_PERCENTILE = 4
const TONE_HIGH_PERCENTILE = 96

/* OKLab lightness per pixel, stretched so the 4th percentile maps to 0.07
   and the 96th to 0.93 (clipped beyond them). */
export function toneMapFromPixels(pixels: PixelData): ToneMap {
  const n = pixels.width * pixels.height
  const lightness = new Float32Array(n)
  for (let i = 0; i < n; i++) {
    const p = i * 4
    lightness[i] = rgbToOklab(pixels.data[p], pixels.data[p + 1], pixels.data[p + 2])[0]
  }
  const sorted = lightness.slice().sort()
  const lo = percentile(sorted, TONE_LOW_PERCENTILE)
  const hi = percentile(sorted, TONE_HIGH_PERCENTILE)
  const span = Math.max(hi - lo, 1e-6)
  const values = new Float32Array(n)
  for (let i = 0; i < n; i++) values[i] = clamp((lightness[i] - lo) / span, 0, 1) * TONE_SPAN + TONE_FLOOR
  return { width: pixels.width, height: pixels.height, values }
}

/* ── the tones a theme adds ───────────────────────────────────────────── */

export type ThemeMode = 'day' | 'night'
export type ThemeKind = Theme['kind']

/* The sheet's tones at night, turned toward the theme's hue. */
export interface SheetTones {
  bg: string
  island: string
  sunk: string
  well: string
  pop: string
  chip: string
  disc: string
  rule: string
}

export interface ThemeTones {
  /* The window ground's two inks, darker first. A flat theme has no
     print: both are the flat tone. */
  groundA: string
  groundB: string
  /* The ground as one colour: a flat theme, and a scene before its
     picture has loaded. */
  flat: string
  /* Words and symbols set on the window ground. */
  ink: string
  /* Night only; by day the sheet does not change with the theme. */
  sheet: SheetTones | null
}

export const DAY_GROUND_INK = '#FFFDF8'
export const NIGHT_GROUND_INK = '#E8E1D5'
/* The chroma of the theme's hue in the night sheet: a trace. */
const SHEET_TRACE = 0.012

export function deriveThemeTones(seed: ThemeSeed, mode: ThemeMode, kind: ThemeKind): ThemeTones {
  const h = seed.hue
  if (mode === 'day') {
    const c = clamp(seed.chroma * 0.8, 0.035, 0.115)
    const flat = oklchToHex(0.4, c, h)
    return {
      groundA: kind === 'flat' ? flat : oklchToHex(0.355, c, h),
      groundB: kind === 'flat' ? flat : oklchToHex(0.445, c * 0.9, h),
      flat,
      ink: DAY_GROUND_INK,
      sheet: null,
    }
  }
  const c = clamp(kind === 'flat' ? seed.chroma * 0.7 : seed.chroma, 0.006, 0.045)
  const flat = oklchToHex(0.205, c, h)
  const t = SHEET_TRACE
  const well = oklchToHex(0.172, t, h)
  return {
    groundA: kind === 'flat' ? flat : oklchToHex(0.165, c, h),
    groundB: kind === 'flat' ? flat : oklchToHex(0.25, c * 0.9, h),
    flat,
    ink: NIGHT_GROUND_INK,
    sheet: {
      bg: well,
      island: oklchToHex(0.215, t, h),
      sunk: oklchToHex(0.262, t, h),
      well,
      pop: oklchToHex(0.285, t, h),
      chip: oklchToHex(0.3, t, h),
      disc: oklchToHex(0.4, t * 1.3, h),
      rule: oklchToHex(0.34, t, h),
    },
  }
}

/* The custom properties a theme sets on its root: the window ground in
   both modes, and the night sheet tones the token sheet reads at night
   (tokens.css falls back to its own values without them). */
export function themeProperties(day: ThemeTones, night: ThemeTones): Record<string, string> {
  const both = (d: string, n: string) => `light-dark(${d}, ${n})`
  const props: Record<string, string> = {
    '--sl-ground-a': both(day.groundA, night.groundA),
    '--sl-ground-b': both(day.groundB, night.groundB),
    '--sl-ground-ink': both(day.ink, night.ink),
  }
  if (night.sheet) {
    for (const [name, value] of Object.entries(night.sheet)) props[`--sl-night-${name}`] = value
  }
  return props
}
