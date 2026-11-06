import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { clampTunerY } from '../src/runtime/window-chrome'

describe('tuner chrome clearance', () => {
  it('clamps a restored or dragged Mac position to the current CSS inset', () => {
    assert.equal(clampTunerY(0, 'macos', '40px'), 40)
    assert.equal(clampTunerY(20, 'macos', '40px'), 40)
    assert.equal(clampTunerY(50, 'macos', '64px'), 64)
    assert.equal(clampTunerY(90, 'macos', '40px'), 90)
  })
  it('leaves web and other platform positions unchanged', () => {
    for (const platform of [undefined, 'windows', 'linux']) {
      assert.equal(clampTunerY(0, platform, '40px'), 0)
      assert.equal(clampTunerY(20, platform, '40px'), 20)
    }
  })
  it('does not turn an absent or invalid CSS inset into NaN', () => {
    assert.equal(clampTunerY(20, 'macos', ''), 20)
    assert.equal(clampTunerY(20, 'macos', 'invalid'), 20)
  })
})
