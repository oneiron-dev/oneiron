import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { PIN_NOTE, Tabs, pinPress, pinsFold } from '../src/design-system/primitives/Tabs'

/* The opening tag of the first element carrying `attribute`. */
function tagWith(html: string, attribute: string): string {
  const at = html.indexOf(attribute)
  assert.ok(at >= 0, `no element with ${attribute}`)
  const start = html.lastIndexOf('<', at)
  return html.slice(start, html.indexOf('>', at) + 1)
}

function head(value = 'talk') {
  return renderToStaticMarkup(
    <Tabs value={value}>
      <Tabs.List foldValue="pinned" aria-label="views of this room">
        <Tabs.Tab value="talk">talk</Tabs.Tab>
        <Tabs.Tab value="files" count={6}>
          files
        </Tabs.Tab>
        <Tabs.Divider />
        <Tabs.Pin value="q4" icon="chart" pinnedBy="Metryon">
          Q4 view
        </Tabs.Pin>
        <Tabs.Pin value="brief" icon="note" pinnedBy="Antevon">
          The brief
        </Tabs.Pin>
        <Tabs.Pin onGo={() => {}} mark={<span className="portrait">y</span>} pinnedBy="Owen">
          Can we have the Q4 view by Friday?
        </Tabs.Pin>
        <Tabs.Add />
      </Tabs.List>
    </Tabs>,
  )
}

describe('the overflow rule of the tabs', () => {
  test('pins fold only when the content is wider than the list', () => {
    assert.equal(pinsFold(600, 600), false)
    assert.equal(pinsFold(600, 600.4), false)
    assert.equal(pinsFold(600, 601), true)
    assert.equal(pinsFold(420, 460), true)
  })

  test('folded, they unfold only once the list again holds the width they need', () => {
    /* Measured unfolded at 460 px of content; the list grows from 420. */
    const needed = 460
    assert.equal(pinsFold(440, needed), true)
    assert.equal(pinsFold(459, needed), true)
    assert.equal(pinsFold(460, needed), false)
  })

  test('the pins, the divider and the add action are the parts that fold; the fold tab counts the pins', () => {
    const html = head()
    const parts = html.match(/data-pin-part=""/g) ?? []
    /* Three pins, the divider and the add action. */
    assert.equal(parts.length, 5)
    const fold = tagWith(html, 'class="sl-tab sl-tab-fold"')
    assert.match(fold, /role="tab"/)
    assert.match(fold, /data-value="pinned"/)
    assert.match(fold, /aria-label="Pinned in this room, 3"/)
    /* Unfolded until measured. */
    assert.doesNotMatch(tagWith(html, 'role="tablist"'), /data-folded/)
  })

  test('no fold tab without a pinned list to fold into, or without pins', () => {
    const plain = renderToStaticMarkup(
      <Tabs defaultValue="talk">
        <Tabs.List>
          <Tabs.Tab value="talk">talk</Tabs.Tab>
          <Tabs.Pin value="q4" icon="chart" pinnedBy="Metryon">
            Q4 view
          </Tabs.Pin>
        </Tabs.List>
      </Tabs>,
    )
    assert.doesNotMatch(plain, /sl-tab-fold/)
    const none = renderToStaticMarkup(
      <Tabs defaultValue="talk">
        <Tabs.List foldValue="pinned">
          <Tabs.Tab value="talk">talk</Tabs.Tab>
        </Tabs.List>
      </Tabs>,
    )
    assert.doesNotMatch(none, /sl-tab-fold/)
  })

  test('the fold tab is the selected tab when the pinned list shows', () => {
    assert.match(tagWith(head('pinned'), 'class="sl-tab sl-tab-fold"'), /aria-selected="true"/)
    assert.match(tagWith(head('talk'), 'class="sl-tab sl-tab-fold"'), /aria-selected="false"/)
  })
})

describe('pins', () => {
  test('a pinned view is a tab with its value; selected like any tab', () => {
    const html = head('q4')
    const q4 = tagWith(html, 'data-value="q4"')
    assert.match(q4, /data-pin="view"/)
    assert.match(q4, /aria-selected="true"/)
    assert.match(html, /<span class="sl-tab-pin-name">Q4 view<\/span>/)
  })

  test('a pinned message does not select: pressing it goes to the message', () => {
    assert.equal(pinPress({ onGo: () => {} }), 'go')
    assert.equal(pinPress({ value: 'q4' }), 'select')
    const html = head()
    const message = tagWith(html, 'data-pin="message"')
    assert.match(message, /aria-selected="false"/)
    /* No value: arrow keys move focus past it without selecting it. */
    assert.doesNotMatch(message, /data-value=/)
    assert.doesNotMatch(message, /aria-controls=/)
    assert.match(html, /class="portrait">y</)
  })

  test('the pin tooltip names who pinned it and what a pin does', () => {
    assert.equal(PIN_NOTE, 'Everyone here sees it, and the agents working in this room keep it in view.')
    const html = head()
    assert.match(html, /<span class="sl-tooltip-label">Pinned by Metryon<\/span>/)
    assert.ok(html.includes(PIN_NOTE))
  })

  test('the add action says what it pins', () => {
    assert.match(head(), /aria-label="Pin a message, a file or a lens to this room"/)
  })
})
