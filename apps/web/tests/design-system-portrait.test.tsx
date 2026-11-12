import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { Portrait } from '../src/design-system/marks/Portrait'

describe('Portrait', () => {
  test('an agent with a picture: the picture cropped round at the face size, named by the label', () => {
    const html = renderToStaticMarkup(<Portrait src="/art/faces/eiri-A-day.png" label="Eiri" size={24} />)
    assert.match(html, /<span role="img" aria-label="Eiri" class="sl-portrait" data-size="24" data-form="picture" style="--sl-portrait-size:24px">/)
    assert.match(html, /<img class="sl-portrait-picture" src="\/art\/faces\/eiri-A-day.png" alt="" width="24" height="24" draggable="false" decoding="async"\/>/)
  })

  test('every face size from 16 to 32 sets its own box', () => {
    for (const size of [16, 18, 20, 22, 24, 28, 32] as const) {
      const html = renderToStaticMarkup(<Portrait src="/art/faces/tory-A-day.png" label="Tory" size={size} />)
      assert.match(html, new RegExp(`--sl-portrait-size:${size}px`))
    }
  })

  test('a person with no picture: the initial on a disc', () => {
    const html = renderToStaticMarkup(<Portrait initial="y" label="Yuki" size={22} guest />)
    assert.match(html, /aria-label="Yuki, a guest"/)
    assert.match(html, /data-form="disc"/)
    assert.match(html, /<span class="sl-portrait-initial" aria-hidden="true">y<\/span>/)
    assert.match(html, /sl-portrait-guest/)
    assert.doesNotMatch(html, /<img/)
  })

  test('the printed plate stays as it was at profile and stack sizes', () => {
    const html = renderToStaticMarkup(<Portrait glyph="ruler" label="Metryon" size="stack" />)
    assert.match(html, /data-size="stack" data-form="plate"/)
    assert.match(html, /<canvas class="sl-portrait-print" aria-hidden="true"><\/canvas>/)
    assert.match(renderToStaticMarkup(<Portrait initial="o" label="Owen" />), /data-size="profile" data-form="plate"/)
  })
})
