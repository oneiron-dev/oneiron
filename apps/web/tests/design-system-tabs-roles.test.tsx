import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { Tabs } from '../src/design-system/primitives/Tabs'

const TABS_CSS = readFileSync(new URL('../src/design-system/primitives/Tabs.css', import.meta.url), 'utf8')

/* The markup of the element that opens at `start`, up to its own closing
   tag (divs only). */
function element(html: string, start: number): string {
  let depth = 0
  const tags = /<(\/?)div\b[^>]*>/g
  tags.lastIndex = start
  for (let m = tags.exec(html); m; m = tags.exec(html)) {
    depth += m[1] ? -1 : 1
    if (depth === 0) return html.slice(start, m.index + m[0].length)
  }
  throw new Error('unclosed element')
}

function roomTabs() {
  return renderToStaticMarkup(
    <Tabs value="talk">
      <Tabs.List foldValue="pinned" aria-label="views of this room">
        <Tabs.Tab value="talk">talk</Tabs.Tab>
        <Tabs.Tab value="files" count={6}>
          files
        </Tabs.Tab>
        <Tabs.Divider />
        <Tabs.Pin value="q4" icon="chart" pinnedBy="Metryon">
          Q4 view
        </Tabs.Pin>
        <Tabs.Add />
      </Tabs.List>
    </Tabs>,
  )
}

describe('the tab list holds only tabs', () => {
  test('the add action is drawn after the tablist, in the same row', () => {
    const html = roomTabs()
    const list = element(html, html.indexOf('<div role="tablist"'))
    assert.doesNotMatch(list, /sl-tabs-add/)
    /* Every button inside the tablist is a tab. */
    const buttons = list.match(/<button[^>]*>/g) ?? []
    assert.ok(buttons.length > 0)
    for (const button of buttons) assert.match(button, /role="tab"/)
    const row = element(html, html.indexOf('<div class="sl-tabs-row"'))
    assert.ok(row.indexOf('role="tablist"') < row.indexOf('sl-tabs-add'))
  })

  test('the row hides the add action when the pins fold', () => {
    assert.match(TABS_CSS, /\.sl-tabs-row\[data-folded\] > \[data-pin-part\]/)
  })

  test('a list without an add action is the tablist alone', () => {
    const html = renderToStaticMarkup(
      <Tabs defaultValue="talk">
        <Tabs.List aria-label="views">
          <Tabs.Tab value="talk">talk</Tabs.Tab>
        </Tabs.List>
      </Tabs>,
    )
    assert.doesNotMatch(html, /sl-tabs-row/)
    assert.match(html, /^<div class="sl-tabs"><div role="tablist"/)
  })
})
