import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { claimInk } from '../src/design-system/patterns/claim-ink'
import { formatElapsed } from '../src/design-system/patterns/run-elapsed'

describe('claimInk', () => {
  test('0.9 and up prints ink-1', () => {
    assert.equal(claimInk(1), 1)
    assert.equal(claimInk(0.97), 1)
    assert.equal(claimInk(0.9), 1)
  })

  test('0.7 to 0.89 prints ink-2', () => {
    assert.equal(claimInk(0.89), 2)
    assert.equal(claimInk(0.7), 2)
  })

  test('0.4 to 0.69 prints ink-3', () => {
    assert.equal(claimInk(0.69), 3)
    assert.equal(claimInk(0.4), 3)
  })

  test('below 0.4 prints ink-4', () => {
    assert.equal(claimInk(0.39), 4)
    assert.equal(claimInk(0), 4)
  })
})

describe('formatElapsed', () => {
  test('seconds, minutes with seconds, hours with minutes', () => {
    assert.equal(formatElapsed(0), '0s')
    assert.equal(formatElapsed(54), '54s')
    assert.equal(formatElapsed(255), '4m15s')
    assert.equal(formatElapsed(3600), '1h00m')
    assert.equal(formatElapsed(4020.9), '1h07m')
  })
})
