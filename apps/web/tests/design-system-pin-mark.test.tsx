import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { PinMark } from '../src/design-system/marks/PinMark'
import { MessageRow } from '../src/design-system/patterns/MessageRow'

describe('PinMark', () => {
  test('a 14 px pin named Pinned in this room', () => {
    const html = renderToStaticMarkup(<PinMark />)
    assert.match(html, /<span role="img" aria-label="Pinned in this room" class="sl-pin-mark">/)
    assert.match(html, /<svg class="sl-icon" width="14" height="14"/)
  })

  test('in MessageRow’s marks it follows the time', () => {
    const html = renderToStaticMarkup(
      <MessageRow author={<span />} name="Yuki" time="13:50" marks={<PinMark />}>
        <MessageRow.Text>Can we have the Q4 view by Friday?</MessageRow.Text>
      </MessageRow>,
    )
    const time = html.indexOf('13:50')
    const pin = html.indexOf('class="sl-pin-mark"')
    assert.ok(time > 0 && pin > time, 'the pin comes after the time')
    assert.ok(html.indexOf('class="sl-message-marks"') < pin)
  })
})
