import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { HoverBar, toolbarActions } from '../src/design-system/patterns/HoverBar'
import { rovingMoveForKey, rovingTarget, setRovingStop, type RovingItem } from '../src/design-system/lib/roving-focus'

/* A stand-in action: a tab index and a focus call that records itself. */
function action(name: string, log: string[] = []): RovingItem & { name: string } {
  return { name, tabIndex: 0, focus: () => log.push(name) }
}

describe('the hover bar is one tab stop', () => {
  test('one action holds the stop, the first at the start', () => {
    const actions = ['react', 'reply', 'forward', 'save', 'more'].map((n) => action(n))
    setRovingStop(actions, 0)
    assert.deepEqual(
      actions.map((a) => a.tabIndex),
      [0, -1, -1, -1, -1],
    )
  })

  test('the stop follows the action focused last', () => {
    const actions = ['react', 'reply', 'forward', 'save', 'more'].map((n) => action(n))
    setRovingStop(actions, 3)
    assert.deepEqual(
      actions.map((a) => a.tabIndex),
      [-1, -1, -1, 0, -1],
    )
    /* An action that is gone leaves the stop on the first. */
    setRovingStop(actions, -1)
    assert.equal(actions[0].tabIndex, 0)
    assert.equal(actions.filter((a) => a.tabIndex === 0).length, 1)
  })

  test('Left and Right move and wrap; Home and End go to the ends', () => {
    assert.equal(rovingMoveForKey('ArrowRight'), 'next')
    assert.equal(rovingMoveForKey('ArrowLeft'), 'previous')
    assert.equal(rovingMoveForKey('Home'), 'first')
    assert.equal(rovingMoveForKey('End'), 'last')
    assert.equal(rovingMoveForKey('ArrowDown'), null)
    assert.equal(rovingMoveForKey('Tab'), null)
    assert.equal(rovingTarget('next', 4, 5), 0)
    assert.equal(rovingTarget('previous', 0, 5), 4)
    assert.equal(rovingTarget('next', 1, 5), 2)
    assert.equal(rovingTarget('first', 3, 5), 0)
    assert.equal(rovingTarget('last', 0, 5), 4)
  })

  test('the actions of the bar leave out the items of a menu it opened', () => {
    const bar = { contains: (node: unknown) => node === menuLayer } as unknown as HTMLElement
    const menuLayer = { name: 'menu layer' }
    const own = (name: string) => ({ name, closest: () => null })
    const inMenu = (name: string) => ({ name, closest: () => menuLayer })
    const found = [own('react'), own('more'), inMenu('quote in a reply'), inMenu('copy the link')]
    ;(bar as unknown as { querySelectorAll: () => unknown[] }).querySelectorAll = () => found
    assert.deepEqual(
      toolbarActions(bar).map((a) => (a as unknown as { name: string }).name),
      ['react', 'more'],
    )
  })

  test('the toolbar keeps its role and its name', () => {
    const html = renderToStaticMarkup(
      <HoverBar aria-label="message actions">
        <button type="button">react</button>
      </HoverBar>,
    )
    assert.match(html, /^<div role="toolbar" aria-label="message actions" class="sl-hover-bar">/)
  })
})
