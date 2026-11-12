import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { ToneButton } from '../src/design-system/primitives/ToneButton'

describe('ToneButton', () => {
  test('a button by default, the mark before the word', () => {
    const html = renderToStaticMarkup(<ToneButton mark={<span className="disc" />}>Continue with a provider</ToneButton>)
    assert.equal(
      html,
      '<button type="button" class="sl-tone-button"><span class="sl-tone-button-mark" aria-hidden="true"><span class="disc"></span></span><span class="sl-tone-button-word">Continue with a provider</span></button>',
    )
  })

  test('no mark: the word alone; a type and class of its own', () => {
    const html = renderToStaticMarkup(
      <ToneButton type="submit" className="wide">
        Continue
      </ToneButton>,
    )
    assert.equal(html, '<button type="submit" class="sl-tone-button wide"><span class="sl-tone-button-word">Continue</span></button>')
  })
})
