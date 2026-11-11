import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { InfoMark } from '../src/design-system/primitives/InfoMark'
import {
  INFO_NOTE_DELAY_MS,
  INFO_NOTE_SIDE_ROOM_PX,
  INFO_NOTE_SIDE_WIDTH_PX,
  INFO_NOTE_UNDER_WIDTH_PX,
  placeInfoNote,
} from '../src/design-system/lib/info-note'

/* A block 620 px wide at x 300; its mark at its right end, on its first line. */
const block = { left: 300, top: 200, width: 620, height: 180 }
const mark = { left: 884, top: 210, width: 30, height: 30 }

describe('placeInfoNote', () => {
  test('the delay is 160 ms, the side needs 350 px, the note is 300 px beside and 340 px under', () => {
    assert.equal(INFO_NOTE_DELAY_MS, 160)
    assert.equal(INFO_NOTE_SIDE_ROOM_PX, 350)
    assert.equal(INFO_NOTE_SIDE_WIDTH_PX, 300)
    assert.equal(INFO_NOTE_UNDER_WIDTH_PX, 340)
  })

  test('with 350 px free to the right of the block, the note sits there, 20 px away, level with the mark', () => {
    const p = placeInfoNote(mark, block, 920 + 350)
    assert.deepEqual(p, { side: 'right', left: 940, top: 210, width: 300 })
  })

  test('with 349 px free, the note goes under the mark, its right edge on the mark’s', () => {
    const p = placeInfoNote(mark, block, 920 + 349)
    assert.equal(p.side, 'under')
    assert.equal(p.width, 340)
    assert.equal(p.left + p.width, mark.left + mark.width)
    assert.equal(p.top, mark.top + mark.height + 4)
  })

  test('the free room is measured from the block, not from the mark', () => {
    /* The mark sits well inside the block: 360 px right of the mark, 340 right of the block. */
    const inner = { ...mark, left: 860 }
    assert.equal(placeInfoNote(inner, block, 1260).side, 'under')
  })

  test('inside the viewport: an under note near the left edge keeps the margin', () => {
    const near = { left: 20, top: 300, width: 30, height: 30 }
    const p = placeInfoNote(near, { left: 0, top: 290, width: 600, height: 60 }, 800, 120, { width: 800, height: 800 })
    assert.equal(p.side, 'under')
    assert.equal(p.left, 8)
    assert.equal(p.top, 334)
  })

  test('no room under the mark near the foot of the viewport: the note goes above it, never over the row', () => {
    const near = { left: 600, top: 700, width: 30, height: 30 }
    const p = placeInfoNote(near, { left: 0, top: 690, width: 640, height: 60 }, 800, 120, { width: 800, height: 800 })
    assert.equal(p.side, 'above')
    assert.equal(p.top, 700 - 4 - 120)
  })

  test('a note beside the block stays above the foot of the viewport', () => {
    const low = { left: 884, top: 840, width: 30, height: 30 }
    const p = placeInfoNote(low, { ...block, top: 830 }, 1400, 90, { width: 1400, height: 900 })
    assert.equal(p.side, 'right')
    assert.equal(p.top, 900 - 8 - 90)
  })
})

describe('InfoMark', () => {
  test('a button named About this, with its note as a hidden layer beside it', () => {
    const html = renderToStaticMarkup(<InfoMark note="Metryon built this card from Acme store sales." />)
    assert.match(html, /^<button type="button" aria-label="About this"/)
    assert.match(html, /class="sl-icon-action sl-info-mark"/)
    assert.match(html, /<div id="[^"]+" popover="manual" role="tooltip" class="sl-info-note">Metryon built this card/)
  })

  test('a label of its own', () => {
    const html = renderToStaticMarkup(<InfoMark note="n" label="About the Q4 view" />)
    assert.match(html, /aria-label="About the Q4 view"/)
  })
})
