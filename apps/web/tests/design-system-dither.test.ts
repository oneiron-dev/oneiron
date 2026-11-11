import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { BAYER_8X8, bayerThreshold, easeOutQuart, luminanceCoverage } from '../src/design-system/lib/dither'
import { FIELD_CROP_Y, fieldCover } from '../src/design-system/lib/field-art'

describe('ordered dither', () => {
  test('the Bayer matrix holds each index 0..63 once', () => {
    assert.deepEqual([...BAYER_8X8].sort((a, b) => a - b), Array.from({ length: 64 }, (_, i) => i))
  })

  test('thresholds sit strictly inside (0, 1) and tile every 8 cells', () => {
    for (let y = 0; y < 8; y++) {
      for (let x = 0; x < 8; x++) {
        const t = bayerThreshold(x, y)
        assert.ok(t > 0 && t < 1)
        assert.equal(bayerThreshold(x + 8, y + 16), t)
      }
    }
    assert.equal(bayerThreshold(0, 0), 0.5 / 64)
  })

  test('the develop curve starts at 0, ends at 1 and never runs backwards', () => {
    assert.equal(easeOutQuart(0), 0)
    assert.equal(easeOutQuart(1), 1)
    assert.equal(easeOutQuart(2), 1)
    let last = -1
    for (let t = 0; t <= 1; t += 0.05) {
      const v = easeOutQuart(t)
      assert.ok(v >= last)
      last = v
    }
  })

  test('dark sky prints nothing; bright cloud prints most of a cell', () => {
    assert.equal(luminanceCoverage(19, 17, 16), 0)
    assert.ok(Math.abs(luminanceCoverage(255, 255, 255) - 0.88) < 1e-9)
  })
})

describe('fieldCover', () => {
  test('a wide viewport scales by width and anchors the picture to the bottom', () => {
    const r = fieldCover(2200, 1466, 4400, 900)
    assert.equal(r.width, 4400)
    assert.equal(r.height, (1466 - FIELD_CROP_Y) * 2)
    assert.equal(r.x, 0)
    assert.equal(r.y, 900 - r.height)
  })

  test('a tall viewport scales by height and centres horizontally', () => {
    const r = fieldCover(2200, 1466, 400, 1992)
    assert.equal(r.height, 1992)
    assert.equal(r.y, 0)
    assert.equal(r.x, (400 - r.width) / 2)
  })
})
