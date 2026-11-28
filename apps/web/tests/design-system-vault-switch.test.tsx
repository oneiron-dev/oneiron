import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { VaultSwitch, type VaultSwitchVault } from '../src/design-system/frame/VaultSwitch'

const CSS = readFileSync(new URL('../src/design-system/frame/VaultSwitch.css', import.meta.url), 'utf8')

const VAULTS: VaultSwitchVault[] = [
  { id: 'antevon', name: 'antevon', caption: 'the house', mark: <span className="mark-a">A</span> },
  { id: 'owen', name: 'owen', caption: 'yours', needsYou: 2, mark: <span className="mark-o">O</span> },
]

describe('VaultSwitch', () => {
  test('the heading over the vaults is a prop: as before by default, none with null', () => {
    assert.match(renderToStaticMarkup(<VaultSwitch vaults={VAULTS} />), /class="sl-menu-heading">Vaults</)
    assert.match(renderToStaticMarkup(<VaultSwitch vaults={VAULTS} heading="Your vaults" />), /class="sl-menu-heading">Your vaults</)
    assert.doesNotMatch(renderToStaticMarkup(<VaultSwitch vaults={VAULTS} heading={null} />), /sl-menu-heading/)
  })

  test('each vault row carries its mark at its left, in the mark square', () => {
    const html = renderToStaticMarkup(<VaultSwitch vaults={VAULTS} />)
    assert.match(html, /data-marks=""/)
    const row = html.slice(html.indexOf('sl-vault-switch-item'))
    const mark = row.indexOf('<span class="sl-vault-switch-mark"><span class="mark-a">A</span></span>')
    assert.ok(mark >= 0, 'the mark is in its square')
    assert.ok(mark < row.indexOf('sl-vault-switch-item-name'), 'the mark comes before the name')
  })

  test('without marks the rows are as before', () => {
    const html = renderToStaticMarkup(<VaultSwitch vaults={[{ id: 'antevon', name: 'antevon' }]} />)
    assert.doesNotMatch(html, /data-marks|sl-vault-switch-mark/)
  })

  test('the mark square is 22 px with the well radius', () => {
    const rule = CSS.match(/\.sl-vault-switch-mark \{([^}]*)\}/)
    assert.ok(rule)
    assert.match(rule[1], /width: 22px;/)
    assert.match(rule[1], /height: 22px;/)
    assert.match(rule[1], /border-radius: var\(--sl-radius\);/)
  })
})
