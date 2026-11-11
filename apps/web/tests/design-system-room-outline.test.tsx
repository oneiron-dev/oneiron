import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { RoomOutline } from '../src/design-system/patterns/RoomOutline'
import { Icon } from '../src/design-system/primitives/Icon'
import { ProgressDonut } from '../src/design-system/marks/ProgressDonut'

function outline() {
  return renderToStaticMarkup(
    <RoomOutline aria-label="outline of # acme-forecast">
      <RoomOutline.Group label="pinned">
        <RoomOutline.Row id="q4" mark={<Icon name="chart" />}>
          Q4 view
        </RoomOutline.Row>
        <RoomOutline.Row id="pinned-message" mark={<Icon name="pin" />} who="Yuki" time="13:50">
          Can we have the Q4 view by Friday?
        </RoomOutline.Row>
      </RoomOutline.Group>
      <RoomOutline.Group label="tasks">
        <RoomOutline.Row id="tasks" mark={<ProgressDonut arcs={['done', 'working', 'ahead']} needsYou tooltip={false} />} who="Metryon" time="14:02">
          I split the Q4 view in three.
        </RoomOutline.Row>
      </RoomOutline.Group>
      <RoomOutline.Group label="threads">
        <RoomOutline.Row id="stores" mark={<Icon name="thread" />} who="Yuki" time="14:10">
          Which stores are in?
        </RoomOutline.Row>
      </RoomOutline.Group>
    </RoomOutline>,
  )
}

describe('RoomOutline', () => {
  test('a named map with three quiet groups in order', () => {
    const html = outline()
    assert.match(html, /^<nav aria-label="outline of # acme-forecast" class="sl-room-outline">/)
    const labels = [...html.matchAll(/<p id="[^"]+" class="sl-room-outline-label">([^<]+)<\/p>/g)].map((m) => m[1])
    assert.deepEqual(labels, ['pinned', 'tasks', 'threads'])
    assert.equal(html.match(/role="group" aria-labelledby=/g)?.length, 3)
  })

  test('a row: the mark, who at weight 600, the first words, the time figure', () => {
    const html = outline()
    const row = html.slice(html.indexOf('data-outline-id="pinned-message"'))
    const order = ['class="sl-room-outline-mark"', 'class="sl-room-outline-who">Yuki', 'Can we have the Q4 view by Friday?', 'class="sl-figure sl-room-outline-time" data-size="figure">13:50'].map((m) => row.indexOf(m))
    assert.ok(order.every((at) => at >= 0), `parts present: ${order}`)
    assert.deepEqual([...order].sort((a, b) => a - b), order)
  })

  test('a row without who or time has neither', () => {
    const html = outline()
    const row = html.slice(html.indexOf('data-outline-id="q4"'), html.indexOf('data-outline-id="pinned-message"'))
    assert.doesNotMatch(row, /sl-room-outline-who|sl-room-outline-time/)
  })

  test('rows are buttons that carry their id for onOpen', () => {
    const html = outline()
    assert.deepEqual(
      [...html.matchAll(/<button type="button" class="sl-room-outline-row" data-outline-id="([^"]+)"/g)].map((m) => m[1]),
      ['q4', 'pinned-message', 'tasks', 'stores'],
    )
    assert.match(html, /aria-label="1 of 3 done, waits on you"/)
  })
})
