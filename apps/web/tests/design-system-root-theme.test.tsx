import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { SafelightRoot } from '../src/design-system/ground/SafelightRoot'
import { WindowGround } from '../src/design-system/ground/WindowGround'
import { THEMES, deriveThemeTones, themeSeedFromColour, type Theme } from '../src/design-system/lib/theme'

const SCENE: Theme = { id: 'field', label: 'field', kind: 'scene', day: '/art/day.png', night: '/art/night.png' }

describe('SafelightRoot and WindowGround on the server', () => {
  test('a flat theme puts its ground and its night sheet in the markup', () => {
    const plum = THEMES[1]
    const seed = themeSeedFromColour(plum.colour)
    const day = deriveThemeTones(seed, 'day', 'flat')
    const night = deriveThemeTones(seed, 'night', 'flat')
    const html = renderToStaticMarkup(<SafelightRoot theme={plum} />)
    assert.match(html, /class="sl-root"/)
    assert.match(html, /data-sl-theme="plum"/)
    assert.ok(html.includes(`--sl-ground-a:light-dark(${day.flat}, ${night.flat})`), html)
    assert.ok(html.includes(`--sl-ground-b:light-dark(${day.flat}, ${night.flat})`), html)
    assert.ok(html.includes('--sl-ground-ink:light-dark(#FFFDF8, #E8E1D5)'), html)
    assert.ok(html.includes(`--sl-night-island:${night.sheet!.island}`), html)
  })

  test('the default theme is deep sea', () => {
    assert.match(renderToStaticMarkup(<SafelightRoot />), /data-sl-theme="deep-sea"/)
  })

  test('a scene starts on the flat tone of the default theme', () => {
    const sea = deriveThemeTones(themeSeedFromColour(THEMES[0].colour), 'day', 'flat')
    const html = renderToStaticMarkup(<SafelightRoot theme={SCENE} />)
    assert.ok(html.includes(`--sl-ground-a:light-dark(${sea.flat},`), html)
  })

  test('the window ground is hidden from assistive tech; only a scene has a canvas', () => {
    const flat = renderToStaticMarkup(
      <SafelightRoot theme={THEMES[2]}>
        <WindowGround />
      </SafelightRoot>,
    )
    const ground = flat.match(/<div[^>]*class="sl-window-ground"[^>]*>(.*?)<\/div>/)
    assert.ok(ground, flat)
    assert.match(ground[0], /aria-hidden="true"/)
    assert.match(ground[0], /data-kind="flat"/)
    assert.equal(ground[1], '')
    const scene = renderToStaticMarkup(
      <SafelightRoot theme={SCENE}>
        <WindowGround />
      </SafelightRoot>,
    )
    assert.match(scene, /data-kind="scene"><canvas class="sl-window-ground-print"><\/canvas><\/div>/)
    assert.doesNotMatch(scene, /data-printed/)
  })
})
