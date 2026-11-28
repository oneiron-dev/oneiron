import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { CrewStack, crewCountName } from '../src/design-system/patterns/CrewStack'

function crew(extra: Record<string, unknown> = {}) {
  return renderToStaticMarkup(
    <CrewStack max={2} {...extra}>
      <CrewStack.Member name="Owen, you" caption="here now">
        <span className="face">o</span>
      </CrewStack.Member>
      <CrewStack.Member name="Metryon" onClick={() => {}}>
        <span className="face">m</span>
      </CrewStack.Member>
      <CrewStack.Member name="Tory">
        <span className="face">t</span>
      </CrewStack.Member>
      <CrewStack.List>
        <CrewStack.ListRow glyph={<span />}>Tory</CrewStack.ListRow>
      </CrewStack.List>
    </CrewStack>,
  )
}

describe('CrewStack as one button', () => {
  test('the whole stack is one button with its tooltip and caption, expanded as the caller says', () => {
    const html = crew({ onOpen: () => {}, 'aria-expanded': true, caption: 'see and manage' })
    assert.equal((html.match(/<button/g) ?? []).length, 1)
    const button = html.slice(html.indexOf('<button'), html.indexOf('>', html.indexOf('<button')) + 1)
    assert.match(button, /aria-label="3 people"/)
    assert.match(button, /aria-expanded="true"/)
    assert.match(button, /data-form="button"/)
    assert.match(html, /class="sl-tooltip-label">3 people</)
    assert.match(html, /class="sl-tooltip-caption">see and manage</)
  })

  test('no popover per face and none for +N; +N is a figure; no member is a stop', () => {
    const html = crew({ onOpen: () => {} })
    assert.doesNotMatch(html, /popover="auto"|sl-crew-list|sl-crew-invite/)
    assert.doesNotMatch(html, /tabindex="0"/)
    assert.match(html, /<span class="sl-crew-member sl-crew-more" aria-hidden="true">\+1<\/span>/)
    /* One tooltip: the stack's own. */
    assert.equal((html.match(/role="tooltip"/g) ?? []).length, 1)
  })

  test('the default form keeps a popover behind +N and a mark per face', () => {
    const html = crew()
    assert.match(html, /role="group" aria-label="crew"/)
    assert.match(html, /sl-crew-list/)
    assert.match(html, /tabindex="0"/)
  })

  test('the count in words', () => {
    assert.equal(crewCountName(1), '1 person')
    assert.equal(crewCountName(5), '5 people')
  })
})
