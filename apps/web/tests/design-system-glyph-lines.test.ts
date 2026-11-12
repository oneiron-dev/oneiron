import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { laurelLeaves } from '../src/design-system/lib/glyph-lines'

describe('laurelLeaves', () => {
  test('five leaves along the spine, base to tip', () => {
    const leaves = laurelLeaves()
    assert.equal(leaves.length, 5)
    /* The spine climbs from the base (y 28.6) to the tip (y 4.8). */
    for (let i = 1; i < leaves.length; i++) assert.ok(leaves[i].cy < leaves[i - 1].cy)
  })

  test('every leaf of the left half sits inside the left half of the 32 box', () => {
    for (const leaf of laurelLeaves()) {
      assert.ok(leaf.cx > 0 && leaf.cx < 16, `cx ${leaf.cx}`)
      assert.ok(leaf.cy > 0 && leaf.cy < 32, `cy ${leaf.cy}`)
      assert.ok(Number.isFinite(leaf.deg))
    }
  })

  test('the first leaf matches the drawn geometry', () => {
    const [first] = laurelLeaves()
    assert.ok(Math.abs(first.cx - 12.75) < 0.05, `cx ${first.cx}`)
    assert.ok(Math.abs(first.cy - 24.29) < 0.05, `cy ${first.cy}`)
  })
})
