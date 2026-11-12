import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import {
  THEMES,
  TONE_FLOOR,
  TONE_SPAN,
  apcaLc,
  deriveThemeTones,
  hexToOklch,
  oklchToHex,
  themeProperties,
  themeSeedFromColour,
  themeSeedFromPixels,
  toneMapFromPixels,
  type PixelData,
} from '../src/design-system/lib/theme'

/* The day and night values of a colour token, read from tokens.css: the
   first and the last hex colour on its line. */
const TOKENS = readFileSync(new URL('../src/design-system/tokens.css', import.meta.url), 'utf8')
function token(name: string): { day: string; night: string } {
  const line = TOKENS.split('\n').find((l) => l.trim().startsWith(`--sl-${name}:`))
  const hexes = line?.match(/#[0-9A-Fa-f]{6}\b/g)
  if (!hexes || hexes.length < 2) throw new Error(`no day and night value for --sl-${name}`)
  return { day: hexes[0], night: hexes[hexes.length - 1] }
}

/* A picture as RGBA pixels: `colourAt(x, y)` gives each pixel's hex. */
function picture(width: number, height: number, colourAt: (x: number, y: number) => string): PixelData {
  const data = new Uint8ClampedArray(width * height * 4)
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const hex = colourAt(x, y).slice(1)
      const p = (y * width + x) * 4
      data[p] = parseInt(hex.slice(0, 2), 16)
      data[p + 1] = parseInt(hex.slice(2, 4), 16)
      data[p + 2] = parseInt(hex.slice(4, 6), 16)
      data[p + 3] = 255
    }
  }
  return { data, width, height }
}

describe('OKLCH conversions', () => {
  test('hex to OKLCH and back gives the same hex, for ten colours', () => {
    for (const hex of ['#EFF0F2', '#120F0D', '#FAF9F5', '#1B1815', '#074B7B', '#6B3F6E', '#4E7A5A', '#C13A20', '#E0452B', '#95BAB4']) {
      const { l, c, h } = hexToOklch(hex)
      assert.equal(oklchToHex(l, c, h), hex)
    }
  })

  test('reads lightness, chroma and hue in degrees', () => {
    const sea = hexToOklch('#074B7B')
    assert.ok(Math.abs(sea.l - 0.40124) < 1e-4)
    assert.ok(Math.abs(sea.c - 0.10123) < 1e-4)
    assert.ok(Math.abs(sea.h - 246.9618) < 1e-3)
    const grey = hexToOklch('#808080')
    assert.ok(grey.c < 1e-4)
  })

  test('a colour outside sRGB keeps its lightness and hue and loses chroma', () => {
    /* Reference values from the same pull-in computed in numpy. */
    assert.equal(oklchToHex(0.7, 0.4, 145), '#14BF38')
    assert.equal(oklchToHex(0.5, 0.3, 264), '#0945F6')
    assert.equal(oklchToHex(0.9, 0.3, 30), '#FED2CB')
    const pulled = hexToOklch(oklchToHex(0.7, 0.4, 145))
    assert.ok(pulled.c < 0.4 * 0.94, `chroma ${pulled.c} was pulled in`)
    assert.ok(Math.abs(pulled.l - 0.7) < 0.01, `lightness ${pulled.l} kept`)
    assert.ok(Math.abs(pulled.h - 145) < 1.5, `hue ${pulled.h} kept`)
  })

  test('a colour inside sRGB keeps its chroma', () => {
    const inside = hexToOklch(oklchToHex(0.6, 0.08, 200))
    assert.ok(Math.abs(inside.c - 0.08) < 0.003)
  })
})

describe('apcaLc', () => {
  test('matches the reference APCA values', () => {
    /* Computed with the reference implementation in numpy. */
    const cases: Array<[string, string, number]> = [
      ['#1E2226', '#FAF9F5', 99.3389],
      ['#E8E1D5', '#1B1815', 87.7725],
      ['#FFFDF8', '#074B7B', 93.6496],
      ['#837C74', '#120F0D', 32.9293],
    ]
    for (const [text, ground, lc] of cases) {
      assert.ok(Math.abs(apcaLc(text, ground) - lc) < 0.01, `${text} on ${ground}: ${apcaLc(text, ground)} not ${lc}`)
    }
  })

  test('is positive both ways and zero for the same colour', () => {
    assert.ok(apcaLc('#FAF9F5', '#1E2226') > 0)
    assert.equal(apcaLc('#808080', '#808080'), 0)
  })
})

describe('theme seeds and tone maps', () => {
  test('a colour seeds its own hue and chroma', () => {
    const seed = themeSeedFromColour('#074B7B')
    assert.ok(Math.abs(seed.hue - 246.96) < 0.01)
    assert.ok(Math.abs(seed.chroma - 0.1012) < 1e-4)
  })

  test('a picture seeds from the mean colour of its upper 60 %', () => {
    /* Rows 0..5 of 10 are plum; the rest is moss and does not count. */
    const pixels = picture(8, 10, (_x, y) => (y < 6 ? '#6B3F6E' : '#4E7A5A'))
    const seed = themeSeedFromPixels(pixels)
    const plum = themeSeedFromColour('#6B3F6E')
    assert.ok(Math.abs(seed.hue - plum.hue) < 1e-3)
    assert.ok(Math.abs(seed.chroma - plum.chroma) < 1e-4)
  })

  test('the tone map stretches lightness to 0.07 … 0.93 and keeps its order', () => {
    const steps = 50
    const pixels = picture(steps, 1, (x) => {
      const v = Math.round((x / (steps - 1)) * 255)
        .toString(16)
        .padStart(2, '0')
      return `#${v}${v}${v}`
    })
    const map = toneMapFromPixels(pixels)
    assert.equal(map.values.length, steps)
    assert.ok(Math.abs(map.values[0] - TONE_FLOOR) < 1e-6)
    assert.ok(Math.abs(map.values[steps - 1] - (TONE_FLOOR + TONE_SPAN)) < 1e-6)
    for (let i = 1; i < steps; i++) assert.ok(map.values[i] >= map.values[i - 1])
    /* The middle of the ramp lands inside the range, not at an end. */
    assert.ok(map.values[25] > 0.3 && map.values[25] < 0.8)
  })

  test('an even picture maps to the floor everywhere', () => {
    const map = toneMapFromPixels(picture(4, 4, () => '#405060'))
    for (const v of map.values) assert.ok(Math.abs(v - TONE_FLOOR) < 1e-6)
  })
})

describe('deriveThemeTones', () => {
  const sea = themeSeedFromColour('#074B7B')

  test('a flat theme has no print: both ground inks are the flat tone', () => {
    for (const mode of ['day', 'night'] as const) {
      const t = deriveThemeTones(sea, mode, 'flat')
      assert.equal(t.groundA, t.flat)
      assert.equal(t.groundB, t.flat)
    }
    assert.equal(deriveThemeTones(sea, 'day', 'flat').flat, '#1E4B71')
    assert.equal(deriveThemeTones(sea, 'night', 'flat').flat, '#04182A')
  })

  test('a scene prints in two inks, the darker first', () => {
    for (const mode of ['day', 'night'] as const) {
      const t = deriveThemeTones(sea, mode, 'scene')
      assert.notEqual(t.groundA, t.groundB)
      assert.ok(hexToOklch(t.groundA).l < hexToOklch(t.groundB).l)
    }
    assert.equal(deriveThemeTones(sea, 'day', 'scene').groundA, '#103E63')
  })

  test('by day the sheet keeps its tones; at night it takes a trace of the hue', () => {
    assert.equal(deriveThemeTones(sea, 'day', 'flat').sheet, null)
    const sheet = deriveThemeTones(sea, 'night', 'flat').sheet
    assert.ok(sheet)
    assert.equal(sheet.island, '#151A1F')
    assert.equal(sheet.bg, sheet.well)
    for (const tone of Object.values(sheet)) assert.ok(hexToOklch(tone).c < 0.03, tone)
  })

  test('chroma is clamped: a grey seed still gives a coloured ground by day', () => {
    const t = deriveThemeTones({ hue: 250, chroma: 0 }, 'day', 'flat')
    assert.ok(hexToOklch(t.flat).c > 0.03)
  })

  test('the root sets the ground in both modes and the night sheet', () => {
    const props = themeProperties(deriveThemeTones(sea, 'day', 'flat'), deriveThemeTones(sea, 'night', 'flat'))
    assert.equal(props['--sl-ground-a'], 'light-dark(#1E4B71, #04182A)')
    assert.equal(props['--sl-ground-ink'], 'light-dark(#FFFDF8, #E8E1D5)')
    assert.equal(props['--sl-night-island'], '#151A1F')
  })

  test('every built-in theme reads, in both modes', () => {
    const ink2 = token('ink-2')
    const ink3 = token('ink-3')
    const island = token('island')
    for (const theme of THEMES) {
      const seed = themeSeedFromColour(theme.colour)
      for (const mode of ['day', 'night'] as const) {
        const t = deriveThemeTones(seed, mode, theme.kind)
        const where = `${theme.label}, ${mode}`
        for (const ground of [t.groundA, t.groundB]) {
          assert.ok(apcaLc(t.ink, ground) >= 75, `${where}: ink on ${ground} is Lc ${apcaLc(t.ink, ground).toFixed(1)}`)
        }
        const isl = mode === 'day' ? island.day : t.sheet!.island
        const i2 = mode === 'day' ? ink2.day : ink2.night
        const i3 = mode === 'day' ? ink3.day : ink3.night
        assert.ok(apcaLc(i2, isl) >= 75, `${where}: ink-2 on island is Lc ${apcaLc(i2, isl).toFixed(1)}`)
        assert.ok(apcaLc(i3, isl) >= 60, `${where}: ink-3 on island is Lc ${apcaLc(i3, isl).toFixed(1)}`)
      }
    }
  })
})
