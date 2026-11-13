import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { Place } from '../src/design-system/frame/Place'
import { PLACE_END_SLACK_PX, atScrollEnd, followScrollEnd, type ScrollBox } from '../src/design-system/frame/place-scroll'

/* A body 600 px high over `content` px of messages, scrolled to `top`. */
const box = (content: number, top: number): ScrollBox => ({ scrollTop: top, clientHeight: 600, scrollHeight: Math.max(600, content) })

describe('Place.Body keeps the end in view', () => {
  test('at the end, or within 24 px of it, counts as at the end', () => {
    assert.equal(PLACE_END_SLACK_PX, 24)
    assert.equal(atScrollEnd(box(1000, 400)), true)
    assert.equal(atScrollEnd(box(1000, 376)), true)
    assert.equal(atScrollEnd(box(1000, 375)), false)
    /* Content shorter than the body: nothing to scroll, so at the end. */
    assert.equal(atScrollEnd(box(300, 0)), true)
  })

  test('a message added while at the end: the body scrolls to the new end', () => {
    const before = box(1000, 400)
    const after = { ...before, scrollHeight: 1120 }
    assert.equal(followScrollEnd(atScrollEnd(before), after), 520)
  })

  test('a message added after the person scrolled up: the position stays', () => {
    const before = box(1000, 120)
    const after = { ...before, scrollHeight: 1120 }
    assert.equal(followScrollEnd(atScrollEnd(before), after), null)
  })

  test('a foot that grows shortens the body: the end stays in view', () => {
    const before = box(1000, 400)
    const after = { ...before, clientHeight: 540 }
    assert.equal(followScrollEnd(atScrollEnd(before), after), 460)
  })

  test('short content: the end is the top', () => {
    assert.equal(followScrollEnd(true, box(300, 0)), 0)
  })
})

describe('Place', () => {
  test('the head, the scrolling body with its content, the foot', () => {
    const html = renderToStaticMarkup(
      <Place aria-label="eiri">
        <Place.Head>
          <h1>eiri</h1>
        </Place.Head>
        <Place.Body>
          <p>Morning.</p>
        </Place.Body>
        <Place.Foot>
          <form />
        </Place.Foot>
      </Place>,
    )
    assert.equal(
      html,
      '<div class="sl-place" aria-label="eiri"><div class="sl-place-head-slot"><h1>eiri</h1></div><div class="sl-place-body"><div class="sl-place-content"><p>Morning.</p></div></div><div class="sl-place-foot"><form></form></div></div>',
    )
  })

  test('asChild lays the place on its child (a Tabs root)', () => {
    const html = renderToStaticMarkup(
      <Place asChild data-view="talk">
        <section className="room">
          <Place.Body>
            <p>Hello</p>
          </Place.Body>
        </section>
      </Place>,
    )
    assert.match(html, /^<section class="sl-place room" data-view="talk"><div class="sl-place-body">/)
  })
})
