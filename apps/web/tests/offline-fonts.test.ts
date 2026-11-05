import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const base = new URL('../', import.meta.url)
const css = readFileSync(new URL('src/styles/fonts.css', base), 'utf8')
const manifest = JSON.parse(readFileSync(new URL('public/fonts/google-fonts-manifest.json', base), 'utf8'))

describe('offline application fonts', () => {
  it('keeps the existing faces and ranges without remote stylesheet/font URLs', () => {
    const safelight = readFileSync(new URL('src/styles/safelight.css', base), 'utf8')
    assert.ok(safelight.startsWith("@import './fonts.css';"))
    assert.doesNotMatch(css, /https?:\/\//)
    assert.match(css, /font-family: 'Source Serif 4'/)
    assert.match(css, /font-weight: 400 600/)
    assert.match(css, /font-style: italic/)
    assert.match(css, /font-family: 'Barlow'/)
    assert.equal([...css.matchAll(/@font-face/g)].length, 18)
  })
  it('ships all referenced WOFF2 files and both upstream licenses', () => {
    for (const file of manifest.files) {
      const bytes = readFileSync(new URL('public/fonts/' + file.file, base))
      assert.equal(bytes.length, file.bytes)
      if (file.file.endsWith('.woff2')) assert.equal(bytes.toString('ascii', 0, 4), 'wOF2')
      else assert.match(bytes.toString(), /SIL OPEN FONT LICENSE Version 1\.1/)
    }
    for (const match of css.matchAll(/url\(([^)]+)\)/g)) {
      assert.ok(manifest.files.some((file: { file: string }) => match[1] === '/fonts/' + file.file))
    }
  })
})
