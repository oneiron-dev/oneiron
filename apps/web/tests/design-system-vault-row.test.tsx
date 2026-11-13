import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { VaultRow } from '../src/design-system/patterns/VaultRow'
import { THEMES } from '../src/design-system/lib/theme'

const FIELD = { id: 'field', label: 'field', kind: 'scene', day: '/art/field-day.png', night: '/art/field-night.png' } as const

describe('VaultRow', () => {
  test('a button: the picture, the name over where it runs, the waiting ring and count', () => {
    const html = renderToStaticMarkup(<VaultRow theme={THEMES[1]} name="acme" runs="Oneiron Cloud" waiting={3} />)
    assert.match(html, /^<button type="button" class="sl-vault-row">/)
    const order = ['class="sl-vault-row-picture"', 'class="sl-vault-row-name">acme', 'class="sl-vault-row-runs">Oneiron Cloud', 'aria-label="3 waiting on you"', '>3</span>'].map((m) => html.indexOf(m))
    assert.ok(order.every((at) => at >= 0), `parts present: ${order}`)
    assert.deepEqual([...order].sort((a, b) => a - b), order)
    assert.match(html, /class="sl-status-dot" data-state="waiting"/)
  })

  test('nothing waits: no ring', () => {
    const html = renderToStaticMarkup(<VaultRow theme={THEMES[0]} name="owen" runs="this Mac" />)
    assert.doesNotMatch(html, /sl-vault-row-waiting|sl-status-dot/)
  })

  test('a flat theme pictures its flat tone in both modes', () => {
    const html = renderToStaticMarkup(<VaultRow theme={THEMES[1]} name="acme" runs="Oneiron Cloud" />)
    assert.match(html, /class="sl-vault-row-picture" data-kind="flat" style="background-color:light-dark\(#[0-9A-F]{6}, #[0-9A-F]{6}\)" aria-hidden="true"/i)
  })

  test('a scene waits for the client to pick its picture by mode', () => {
    const html = renderToStaticMarkup(<VaultRow theme={FIELD} name="owen" runs="this Mac" />)
    assert.match(html, /data-kind="scene"/)
    assert.doesNotMatch(html, /background-image/)
  })
})
