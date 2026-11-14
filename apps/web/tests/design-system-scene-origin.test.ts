import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { THEMES, sceneAddressAllowed, scenePictures, type Theme } from '../src/design-system/lib/theme'

const PAGE = 'https://app.example/app/inbox?view=talk'

describe('a scene’s picture comes from the page’s own origin', () => {
  test('a relative path', () => {
    assert.equal(sceneAddressAllowed('art/scenes/field-day.png', PAGE), true)
    assert.equal(sceneAddressAllowed('../art/field-night.png', PAGE), true)
  })

  test('an absolute path', () => {
    assert.equal(sceneAddressAllowed('/art/scenes/field-day.png', PAGE), true)
  })

  test('the same origin written in full', () => {
    assert.equal(sceneAddressAllowed('https://app.example/art/field-day.png', PAGE), true)
    /* Another port or scheme is another origin. */
    assert.equal(sceneAddressAllowed('https://app.example:8443/art/field-day.png', PAGE), false)
    assert.equal(sceneAddressAllowed('http://app.example/art/field-day.png', PAGE), false)
  })

  test('another host', () => {
    assert.equal(sceneAddressAllowed('https://elsewhere.example/field-day.png', PAGE), false)
    assert.equal(sceneAddressAllowed('https://app.example.elsewhere.example/field-day.png', PAGE), false)
  })

  test('//host/path', () => {
    assert.equal(sceneAddressAllowed('//elsewhere.example/field-day.png', PAGE), false)
    assert.equal(sceneAddressAllowed('/\\elsewhere.example/field-day.png', PAGE), false)
  })

  test('data: and blob: addresses', () => {
    assert.equal(sceneAddressAllowed('data:image/png;base64,iVBORw0KGgo=', PAGE), true)
    assert.equal(sceneAddressAllowed('blob:https://app.example/6f1c2e9a-0d3b-4f7e-9a51-2c7d8e0b4a11', PAGE), true)
  })

  test('javascript: and other schemes', () => {
    assert.equal(sceneAddressAllowed('javascript:alert(1)', PAGE), false)
    assert.equal(sceneAddressAllowed('JavaScript:alert(1)', PAGE), false)
    assert.equal(sceneAddressAllowed('file:///etc/field.png', PAGE), false)
    assert.equal(sceneAddressAllowed('', PAGE), false)
  })

  test('a page whose scheme has no web origin (a desktop shell) compares scheme and host', () => {
    const desktop = 'tauri://localhost/app/inbox'
    assert.equal(sceneAddressAllowed('/art/field-day.png', desktop), true)
    assert.equal(sceneAddressAllowed('tauri://elsewhere/field-day.png', desktop), false)
    assert.equal(sceneAddressAllowed('https://localhost/field-day.png', desktop), false)
  })
})

describe('a scene with a picture from elsewhere keeps its stand-in', () => {
  const scene = (day: string, night: string): Theme => ({ id: 'field', label: 'field', kind: 'scene', day, night })

  test('both pictures from the page: both are drawn', () => {
    assert.deepEqual(scenePictures(scene('/art/day.png', '/art/night.png'), PAGE), { day: '/art/day.png', night: '/art/night.png' })
  })

  test('one picture from another host: neither is drawn', () => {
    assert.equal(scenePictures(scene('/art/day.png', 'https://elsewhere.example/night.png'), PAGE), null)
  })

  test('on the server, and for a flat theme, there are no pictures', () => {
    assert.equal(scenePictures(scene('/art/day.png', '/art/night.png'), null), null)
    assert.equal(scenePictures(THEMES[1], PAGE), null)
  })
})
