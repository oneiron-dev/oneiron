import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { SPLIT_MAGNETS, SPLIT_MAGNET_PULL_PX, snapToMagnet } from '../src/design-system/patterns/snap-to-magnet'

const W = 1000
const near = (a: number, b: number, eps = 1e-9) => assert.ok(Math.abs(a - b) < eps, `${a} is not ${b}`)

describe('snapToMagnet', () => {
  test('the defaults are 25, 50 and 75 percent with a 30 px pull', () => {
    assert.deepEqual([...SPLIT_MAGNETS], [0.25, 0.5, 0.75])
    assert.equal(SPLIT_MAGNET_PULL_PX, 30)
  })

  test('outside every pull radius the edge is left alone', () => {
    assert.deepEqual(snapToMagnet(0.4, W), { fraction: 0.4, magnet: null })
  })

  test('on a magnet it stays exactly there', () => {
    assert.deepEqual(snapToMagnet(0.5, W), { fraction: 0.5, magnet: 0.5 })
  })

  test('inside the radius it eases toward the magnet by 0.72 times the squared closeness', () => {
    /* 10 px short of 500: closeness 2/3, pull 0.72 * 4/9 = 0.32 of the 10 px. */
    const { fraction, magnet } = snapToMagnet(0.49, W)
    assert.equal(magnet, 0.5)
    near(fraction * W, 490 + 10 * 0.32)
  })

  test('the pull fades to nothing at the edge of the radius, so the edge never jumps', () => {
    const inside = snapToMagnet((500 - 29.999) / W, W)
    near(inside.fraction * W, 500 - 29.999, 1e-3)
    assert.deepEqual(snapToMagnet((500 - 30) / W, W), { fraction: 0.47, magnet: null })
  })

  test('the pull radius is in pixels: a narrow pane reaches farther in fractions', () => {
    assert.equal(snapToMagnet(0.45, 400).magnet, 0.5)
    assert.equal(snapToMagnet(0.45, 1000).magnet, null)
  })

  test('custom magnets and pull', () => {
    const { fraction, magnet } = snapToMagnet(0.31, W, [0.33], 50)
    assert.equal(magnet, 0.33)
    assert.ok(fraction > 0.31 && fraction < 0.33)
  })

  test('a zero width or zero pull leaves the fraction alone', () => {
    assert.deepEqual(snapToMagnet(0.5, 0), { fraction: 0.5, magnet: null })
    assert.deepEqual(snapToMagnet(0.5, W, SPLIT_MAGNETS, 0), { fraction: 0.5, magnet: null })
  })
})
