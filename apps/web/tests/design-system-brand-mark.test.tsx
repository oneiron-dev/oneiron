import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { BrandMark } from '../src/design-system/marks/BrandMark'

describe('BrandMark', () => {
  test('alone it is an image named Oneiron, 24 px by default', () => {
    const html = renderToStaticMarkup(<BrandMark />)
    assert.match(html, /^<span class="sl-brand-mark" role="img" aria-label="Oneiron">/)
    assert.match(html, /<svg class="sl-brand-mark-symbol" viewBox="0 0 120 120" width="24" height="24" aria-hidden="true"/)
    assert.match(html, /fill-rule="evenodd"/)
    assert.doesNotMatch(html, /mask|id=/)
  })

  test('with the word, the name is the text and the symbol is hidden', () => {
    const html = renderToStaticMarkup(<BrandMark size={32} word />)
    assert.doesNotMatch(html, /role="img"/)
    assert.match(html, /data-word=""/)
    assert.match(html, /width="32" height="32" aria-hidden="true"/)
    assert.match(html, /<span class="sl-brand-mark-word">oneiron<\/span>/)
  })
})
