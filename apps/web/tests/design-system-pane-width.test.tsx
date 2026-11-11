import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { SplitPane } from '../src/design-system/patterns/SplitPane'
import {
  COLUMN_ROOM_PX,
  LIST_PANE_PX,
  SPLIT_EDGE_PX,
  THING_PANE_MAX_PX,
  THING_PANE_MIN_PX,
  paneBounds,
  paneTrack,
  paneWidth,
  thingPlaceholder,
} from '../src/design-system/patterns/pane-width'

/* The opening tag of the first element carrying `attribute`. */
function tagWith(html: string, attribute: string): string {
  const at = html.indexOf(attribute)
  assert.ok(at >= 0, `no element with ${attribute}`)
  const start = html.lastIndexOf('<', at)
  return html.slice(start, html.indexOf('>', at) + 1)
}

describe('the pane width rule', () => {
  test('a pane for a list is 340 px at any width', () => {
    assert.equal(LIST_PANE_PX, 340)
    assert.equal(paneWidth('list', 900), 340)
    assert.equal(paneWidth('list', 2400, 248), 340)
  })

  test('a pane for one thing takes what the column leaves: the width less the sidebar less 620 + 92, less the 1 px edge', () => {
    assert.equal(COLUMN_ROOM_PX, 92)
    assert.equal(SPLIT_EDGE_PX, 1)
    /* The sheet of a 1440 px window: 1374 px, a 248 px sidebar. */
    assert.equal(paneWidth('thing', 1374, 248), 1374 - 248 - 712 - 1)
    /* The same inside the work area alone. */
    assert.equal(paneWidth('thing', 1126), 1126 - 712 - 1)
  })

  test('never under 380 px, never over 680 px', () => {
    assert.equal(THING_PANE_MIN_PX, 380)
    assert.equal(THING_PANE_MAX_PX, 680)
    assert.equal(paneWidth('thing', 1034, 248), 380)
    assert.equal(paneWidth('thing', 2560, 248), 680)
    assert.equal(paneWidth('thing', 713 + 380), 380)
    assert.equal(paneWidth('thing', 713 + 381), 381)
  })

  test('the drag bounds', () => {
    assert.deepEqual(paneBounds('thing'), { min: 380, max: 680 })
    assert.deepEqual(paneBounds('list'), { min: 340, max: 680 })
  })

  test('the CSS track carries the same rule', () => {
    assert.equal(paneTrack('list'), '340px')
    assert.equal(paneTrack('thing', 248), 'clamp(380px, calc(100% - 248px - (var(--sl-col, 620px) + 92px) - 1px), 680px)')
  })
})

describe('SplitPane.Thing', () => {
  function thing(thread?: React.ReactNode) {
    return renderToStaticMarkup(
      <SplitPane pane="thing">
        <SplitPane.Pane>room</SplitPane.Pane>
        <SplitPane.Handle />
        <SplitPane.Thing title="Promo weeks or not moves the quarter by ¥2.0M" onClose={() => {}} note="Metryon built this card from Acme store sales." thread={thread}>
          <p>the chart</p>
        </SplitPane.Thing>
      </SplitPane>,
    )
  }

  test('the placeholder: write about the thing, then reply', () => {
    assert.equal(thingPlaceholder(false), 'Write about this')
    assert.equal(thingPlaceholder(true), 'Reply')
    assert.match(tagWith(thing(), 'class="sl-composer-field"'), /placeholder="Write about this"/)
    assert.match(tagWith(thing([<p key="1">Keep the promo weeks.</p>]), 'class="sl-composer-field"'), /placeholder="Reply"/)
    /* An empty thread is no thread. */
    assert.match(tagWith(thing([]), 'class="sl-composer-field"'), /placeholder="Write about this"/)
  })

  test('head, then the body (the thing, its note, its thread), then the small write box outside the body', () => {
    const html = thing([<p key="1">Keep the promo weeks.</p>])
    const order = ['class="sl-split-head sl-split-thing-head"', 'class="sl-split-thing-body"', 'the chart', 'class="sl-split-thing-note"', 'class="sl-split-thing-thread"', 'class="sl-composer sl-split-thing-write"'].map((m) =>
      html.indexOf(m),
    )
    assert.ok(order.every((at) => at >= 0), `parts present: ${order}`)
    assert.deepEqual([...order].sort((a, b) => a - b), order)
    assert.match(tagWith(html, 'class="sl-split-head sl-split-thing-head"'), /data-lines="2"/)
    assert.match(tagWith(html, 'class="sl-composer sl-split-thing-write"'), /data-size="small"/)
    assert.match(html, /aria-label="Close"/)
  })

  test('the split draws the rule as its track before measuring', () => {
    const root = tagWith(thing(), 'class="sl-split-pane"')
    assert.match(root, /data-pane="thing"/)
    assert.match(root, /grid-template-columns:minmax\(0, 1fr\) 1px clamp\(380px/)
  })
})
