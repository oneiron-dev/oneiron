import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { WordDivider } from '../src/design-system/primitives/WordDivider'

describe('WordDivider', () => {
  test('the word or by default, between two drawn lines', () => {
    assert.equal(renderToStaticMarkup(<WordDivider />), '<p class="sl-word-divider"><span class="sl-word-divider-word">or</span></p>')
  })

  test('a word of its own', () => {
    assert.match(renderToStaticMarkup(<WordDivider className="gap">then</WordDivider>), /class="sl-word-divider gap"><span class="sl-word-divider-word">then</)
  })
})
