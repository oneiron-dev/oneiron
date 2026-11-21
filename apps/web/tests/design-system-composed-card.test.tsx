import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { ComposedCard } from '../src/design-system/patterns/ComposedCard'

const CSS = readFileSync(new URL('../src/design-system/patterns/ComposedCard.css', import.meta.url), 'utf8')

function card(pending: boolean) {
  return renderToStaticMarkup(
    <ComposedCard title="Stores in the pilot" note="Metryon built this card." pending={pending}>
      <ComposedCard.Foot count="12 of 14 in" action="use this list" actionDisabled={pending} />
    </ComposedCard>,
  )
}

describe('a ComposedCard still arriving', () => {
  test('the live mark stands in the information mark’s place; the card is busy', () => {
    const html = card(true)
    assert.match(html, /aria-busy="true"/)
    assert.match(html, /data-pending=""/)
    const mark = html.indexOf('sl-info-mark')
    const live = html.search(/<span[^>]*sl-composed-card-live[^>]*>/)
    assert.ok(mark > 0 && live > mark, 'the live mark follows the information mark in the head')
    assert.ok(live < html.indexOf('sl-composed-foot'), 'and sits in the head, before the body')
    assert.match(html.slice(live, html.indexOf('>', live)), /data-state="live"/)
  })

  test('whole, the card has no live mark and is not busy', () => {
    const html = card(false)
    assert.doesNotMatch(html, /aria-busy|data-pending|data-state="live"/)
  })

  test('the information mark keeps its place while hidden, and the live mark takes no room', () => {
    assert.match(CSS, /\.sl-composed-card\[data-pending\] \.sl-composed-card-head > \.sl-info-mark \{\s*visibility: hidden;\s*\}/)
    assert.match(CSS, /\.sl-composed-card-live \{\s*position: absolute;/)
  })

  test('the foot’s action can wait: it shows and does not press', () => {
    const chip = (html: string) => html.slice(html.indexOf('<button', html.indexOf('sl-composed-foot')), html.indexOf('>', html.indexOf('<button', html.indexOf('sl-composed-foot'))) + 1)
    assert.match(chip(card(true)), /disabled=""/)
    assert.doesNotMatch(chip(card(false)), /disabled/)
    assert.match(CSS, /\.sl-composed-chip:disabled \{/)
  })
})
