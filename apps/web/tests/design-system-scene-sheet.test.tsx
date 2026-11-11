import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { SceneSheet } from '../src/design-system/ground/SceneSheet'
import { SafelightRoot } from '../src/design-system/ground/SafelightRoot'

describe('SceneSheet', () => {
  test('one sheet on the stage, 410 px wide by default, its props on the sheet', () => {
    const html = renderToStaticMarkup(
      <SceneSheet aria-label="sign in">
        <p>fields</p>
      </SceneSheet>,
    )
    assert.match(html, /^<div class="sl-scene-sheet-stage" data-kind="flat"><section class="sl-scene-sheet" style="width:410px" aria-label="sign in"><p>fields<\/p><\/section><\/div>$/)
  })

  test('a width of its own, and the brand line centred or at the start', () => {
    const centred = renderToStaticMarkup(<SceneSheet brand width={620} />)
    assert.match(centred, /style="width:620px"/)
    assert.match(centred, /<div class="sl-scene-sheet-brand" data-align="center"><span class="sl-brand-mark" data-word="">/)
    assert.match(centred, /<span class="sl-brand-mark-word">oneiron<\/span>/)
    assert.match(renderToStaticMarkup(<SceneSheet brand brandAlign="start" />), /data-align="start"/)
    assert.doesNotMatch(renderToStaticMarkup(<SceneSheet />), /sl-scene-sheet-brand/)
  })

  test('on a scene theme the stage names its kind; the picture waits for the client', () => {
    const html = renderToStaticMarkup(
      <SafelightRoot theme={{ id: 'field', label: 'field', kind: 'scene', day: '/art/field-day.png', night: '/art/field-night.png' }}>
        <SceneSheet />
      </SafelightRoot>,
    )
    assert.match(html, /<div class="sl-scene-sheet-stage" data-kind="scene">/)
    assert.doesNotMatch(html, /background-image/)
  })
})
