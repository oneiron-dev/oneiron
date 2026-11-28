import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { Composer } from '../src/design-system/patterns/Composer'
import { composerKeySends, composerSendText } from '../src/design-system/patterns/composer-keys'

/* The opening tag of the first element carrying `attribute`. */
function tagWith(html: string, attribute: string): string {
  const at = html.indexOf(attribute)
  assert.ok(at >= 0, `no element with ${attribute}`)
  const start = html.lastIndexOf('<', at)
  return html.slice(start, html.indexOf('>', at) + 1)
}

describe('composer keys', () => {
  test('Enter sends', () => {
    assert.equal(composerKeySends('Enter', { shiftKey: false, isComposing: false }), true)
  })

  test('Shift+Enter and Enter inside an input method do not send', () => {
    assert.equal(composerKeySends('Enter', { shiftKey: true, isComposing: false }), false)
    assert.equal(composerKeySends('Enter', { shiftKey: false, isComposing: true }), false)
  })

  test('other keys do not send', () => {
    assert.equal(composerKeySends('a', { shiftKey: false, isComposing: false }), false)
    assert.equal(composerKeySends('Escape', { shiftKey: false, isComposing: false }), false)
  })

  test('empty text does not send; text is sent trimmed', () => {
    assert.equal(composerSendText(''), null)
    assert.equal(composerSendText('   \n '), null)
    assert.equal(composerSendText('  Keep the promo weeks. \n'), 'Keep the promo weeks.')
  })
})

describe('Composer, small', () => {
  test('one text input with its placeholder; the tools show on focus by default', () => {
    const html = renderToStaticMarkup(<Composer size="small" placeholder="Write about this" />)
    const form = tagWith(html, 'class="sl-composer"')
    assert.match(form, /data-size="small"/)
    assert.match(form, /data-tools="on focus"/)
    assert.doesNotMatch(form, /data-has-text/)
    const field = tagWith(html, 'class="sl-composer-field"')
    assert.match(field, /^<input/)
    assert.match(field, /placeholder="Write about this"/)
    assert.match(field, /aria-label="Write about this"/)
    /* The button sends: an arrow, never the voice mark. */
    assert.match(tagWith(html, 'class="sl-primary-button sl-composer-send"'), /data-mode="send"/)
  })

  test('tools always; text marks the box so its tools stay', () => {
    const html = renderToStaticMarkup(<Composer size="small" tools="always" defaultValue="Show week 44" />)
    const form = tagWith(html, 'class="sl-composer"')
    assert.match(form, /data-tools="always"/)
    assert.match(form, /data-has-text=""/)
  })

  test('small has no portrait', () => {
    const html = renderToStaticMarkup(<Composer size="small" persona={<Composer.Persona initial="o" />} />)
    assert.doesNotMatch(html, /sl-composer-writer/)
  })
})

describe('Composer, default', () => {
  test('the portrait in the gutter before the box; the button talks while empty', () => {
    const html = renderToStaticMarkup(
      <Composer placeholder="Write to eiri" onVoice={() => {}} persona={<Composer.Persona initial="o" note="You write as Owen." />} />,
    )
    assert.ok(html.indexOf('class="sl-composer-writer"') < html.indexOf('class="sl-composer-bar"'))
    assert.match(tagWith(html, 'class="sl-composer-field"'), /^<textarea/)
    assert.match(tagWith(html, 'class="sl-primary-button sl-composer-send"'), /data-mode="talk"/)
    /* No standing line under the box. */
    assert.doesNotMatch(html, /Saved in/)
  })

  test('with text the button sends', () => {
    const html = renderToStaticMarkup(<Composer defaultValue="Check the filings" onVoice={() => {}} />)
    assert.match(tagWith(html, 'class="sl-primary-button sl-composer-send"'), /data-mode="send"/)
  })

  test('the crossing line sits above the box', () => {
    const html = renderToStaticMarkup(<Composer crossing={<p className="crossing">Guests see what you send here</p>} />)
    assert.ok(html.indexOf('class="sl-composer-crossing"') >= 0)
    assert.ok(html.indexOf('class="sl-composer-crossing"') < html.indexOf('class="sl-composer-bar"'))
  })
})

describe('Composer.Add finds the box', () => {
  /* A caller's own part around the add: it adds attributes of its own. */
  function OwnAdd() {
    return <Composer.Add label="Add to the message" data-own="" />
  }

  test('a direct add is drawn in the box, in its slot', () => {
    const html = renderToStaticMarkup(
      <Composer tools="always">
        <Composer.Add label="Add to the message" />
      </Composer>,
    )
    const bar = html.indexOf('class="sl-composer-bar"')
    const slot = html.indexOf('class="sl-composer-add-slot"')
    const add = html.search(/sl-composer-add[" ]/)
    assert.ok(bar >= 0 && bar < slot && slot < add, 'the add sits in the slot inside the box')
  })

  test('an add inside a part of the caller is never drawn above the box', () => {
    const html = renderToStaticMarkup(
      <Composer tools="always">
        <OwnAdd />
      </Composer>,
    )
    const bar = html.indexOf('class="sl-composer-bar"')
    const add = html.indexOf('data-own')
    /* On the server it waits for the slot; in the browser it is drawn
       into the slot (the gallery's write boxes use such a part). */
    assert.ok(add < 0 || add > bar, 'the add is not above the box')
    assert.match(html, /<span class="sl-composer-add-slot"><span class="sl-composer-add-slot"><\/span><\/span>/)
  })

  test('outside a write box the add draws where it stands', () => {
    const html = renderToStaticMarkup(<Composer.Add label="Add" data-own="" />)
    assert.match(html, /data-own=""/)
  })
})
