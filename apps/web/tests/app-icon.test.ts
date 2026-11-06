import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { supportsAppIconAppearance } from '../src/runtime/app-icon'

describe('native app icon setting availability', () => {
  it('is enabled only in the actual macOS shell', () => {
    assert.equal(supportsAppIconAppearance('macos', true), true)
    for (const marker of [undefined, 'macos', 'windows', 'linux']) {
      assert.equal(supportsAppIconAppearance(marker, false), false)
    }
    assert.equal(supportsAppIconAppearance(undefined, true), false)
    assert.equal(supportsAppIconAppearance('windows', true), false)
    assert.equal(supportsAppIconAppearance('linux', true), false)
  })
})
