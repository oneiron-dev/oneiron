import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { placeFloating } from '../src/design-system/lib/placement'

const viewport = { width: 1000, height: 800 }
const layer = { width: 200, height: 100 }
const anchor = { top: 100, left: 300, width: 80, height: 30 }

describe('placeFloating', () => {
  test('below the anchor, start-aligned, growing from the top-left corner', () => {
    assert.deepEqual(placeFloating(anchor, layer, viewport), {
      top: 138,
      left: 300,
      side: 'bottom',
      transformOrigin: 'top left',
      anchorInView: true,
    })
  })

  test('end alignment lines up the right edges and grows from the top-right', () => {
    const p = placeFloating(anchor, layer, viewport, { align: 'end' })
    assert.equal(p.left, 300 + 80 - 200)
    assert.equal(p.transformOrigin, 'top right')
  })

  test('centre alignment centres on the anchor', () => {
    const p = placeFloating(anchor, layer, viewport, { align: 'center' })
    assert.equal(p.left, 240)
    assert.equal(p.transformOrigin, 'top center')
  })

  test('flips above when there is no room below and more room above', () => {
    const low = { top: 740, left: 300, width: 80, height: 30 }
    const p = placeFloating(low, layer, viewport)
    assert.equal(p.side, 'top')
    assert.equal(p.top, 740 - 8 - 100)
    assert.equal(p.transformOrigin, 'bottom left')
  })

  test('keeps the preferred side when the other side has even less room', () => {
    const tall = { width: 200, height: 700 }
    const p = placeFloating({ top: 60, left: 300, width: 80, height: 30 }, tall, viewport)
    assert.equal(p.side, 'bottom')
  })

  test('clamps inside the viewport margin', () => {
    const edge = { top: 100, left: 950, width: 40, height: 30 }
    const p = placeFloating(edge, layer, viewport, { margin: 8 })
    assert.equal(p.left, 1000 - 8 - 200)
  })

  test('to the right, centred vertically, for side tooltips', () => {
    const p = placeFloating(anchor, { width: 120, height: 40 }, viewport, { side: 'right', align: 'center', offset: 10 })
    assert.deepEqual(p, { top: 95, left: 390, side: 'right', transformOrigin: 'left center', anchorInView: true })
  })
})

describe('placeFloating against the viewport', () => {
  const menu = { width: 300, height: 270 }

  test('a trigger inside the viewport keeps the layer inside the margin', () => {
    const p = placeFloating({ top: 400, left: 60, width: 60, height: 22 }, menu, viewport)
    assert.equal(p.anchorInView, true)
    assert.equal(p.side, 'bottom')
    assert.equal(p.top, 430)
    assert.equal(p.left, 60)
  })

  test('a trigger above the viewport keeps the layer under it, unclamped', () => {
    const trigger = { top: -500, left: 60, width: 60, height: 22 }
    const p = placeFloating(trigger, menu, viewport)
    assert.equal(p.anchorInView, false)
    assert.equal(p.side, 'bottom')
    assert.equal(p.top, -500 + 22 + 8)
    assert.equal(p.left, 60)
  })

  test('a trigger below the viewport keeps the layer against it, unclamped', () => {
    const trigger = { top: 2100, left: 60, width: 60, height: 22 }
    const p = placeFloating(trigger, menu, viewport)
    assert.equal(p.anchorInView, false)
    /* Above the trigger is the roomier side, as it was while the trigger
       sat at the bottom edge; the layer stays there and leaves with it. */
    assert.equal(p.side, 'top')
    assert.equal(p.top, 2100 - 8 - 270)
    assert.ok(p.top > viewport.height, 'the layer is outside the viewport with its trigger')
  })

  test('scrolling moves the layer by the same distance as the trigger', () => {
    const at = (top: number) => placeFloating({ top, left: 60, width: 60, height: 22 }, menu, viewport)
    assert.equal(at(-200).top - at(-320).top, 120)
    assert.equal(at(900).top - at(1020).top, -120)
  })

  test('a trigger just inside the bottom edge flips the layer above it', () => {
    const p = placeFloating({ top: 770, left: 60, width: 60, height: 22 }, menu, viewport)
    assert.equal(p.anchorInView, true)
    assert.equal(p.side, 'top')
    assert.equal(p.top, 770 - 8 - 270)
  })
})
