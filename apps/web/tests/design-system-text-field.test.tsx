import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { TextField } from '../src/design-system/primitives/TextField'

/* The opening tag of the input. */
const input = (html: string) => html.slice(html.indexOf('<input'), html.indexOf('>', html.indexOf('<input')) + 1)

describe('TextField', () => {
  test('uncontrolled: it starts from defaultValue, empty without one', () => {
    assert.match(input(renderToStaticMarkup(<TextField aria-label="Email address" defaultValue="owen@" />)), /value="owen@"/)
    assert.match(input(renderToStaticMarkup(<TextField aria-label="Email address" />)), /value=""/)
  })

  test('controlled: it shows value, not defaultValue', () => {
    const html = renderToStaticMarkup(<TextField aria-label="Email address" value="yuki" defaultValue="owen" onValueChange={() => {}} />)
    assert.match(input(html), /value="yuki"/)
  })

  test('the label sits above the field and names it', () => {
    const html = renderToStaticMarkup(<TextField label="Email address" id="email" type="email" placeholder="you@acme" autoComplete="email" />)
    assert.match(html, /^<div class="sl-text-field"><label for="email" class="sl-text-field-label">Email address<\/label><input id="email" type="email" class="sl-text-field-input"/)
    assert.match(input(html), /placeholder="you@acme"/)
    assert.match(input(html), /autoComplete="email"|autocomplete="email"/)
  })

  test('without an id the label still finds the field', () => {
    const html = renderToStaticMarkup(<TextField label="Vault name" />)
    const forId = /<label for="([^"]+)"/.exec(html)?.[1]
    assert.ok(forId)
    assert.match(input(html), new RegExp(`id="${forId}"`))
  })

  test('the class name goes to the wrapper; a text input by default', () => {
    const html = renderToStaticMarkup(<TextField aria-label="Search" className="wide" />)
    assert.match(html, /^<div class="sl-text-field wide"><input id="[^"]+" type="text" class="sl-text-field-input"/)
  })
})
