import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { SETTLE_OPEN, settleReducer, type SettleState } from '../src/design-system/patterns/settle-reducer'

const pending: SettleState = { status: 'pending', value: 'promo weeks', kind: 'answer' }
const settled: SettleState = { status: 'settled', value: 'promo weeks', kind: 'answer' }

describe('settleReducer', () => {
  test('a pick moves an open item to pending with its value', () => {
    assert.deepEqual(settleReducer(SETTLE_OPEN, { type: 'pick', value: 'promo weeks' }), pending)
  })

  test('later is a pick of its own kind', () => {
    assert.deepEqual(settleReducer(SETTLE_OPEN, { type: 'pick', value: 'later', kind: 'later' }), {
      status: 'pending',
      value: 'later',
      kind: 'later',
    })
  })

  test('undo inside the window restores the open item with no pick', () => {
    assert.deepEqual(settleReducer(pending, { type: 'undo' }), SETTLE_OPEN)
  })

  test('the end of the window settles the pending answer', () => {
    assert.deepEqual(settleReducer(pending, { type: 'commit' }), settled)
  })

  test('a second pick while pending changes nothing', () => {
    assert.equal(settleReducer(pending, { type: 'pick', value: 'normal weeks' }), pending)
  })

  test('undo and commit do nothing to an open item', () => {
    assert.equal(settleReducer(SETTLE_OPEN, { type: 'undo' }), SETTLE_OPEN)
    assert.equal(settleReducer(SETTLE_OPEN, { type: 'commit' }), SETTLE_OPEN)
  })

  test('a settled item stays settled', () => {
    assert.equal(settleReducer(settled, { type: 'undo' }), settled)
    assert.equal(settleReducer(settled, { type: 'pick', value: 'x' }), settled)
    assert.equal(settleReducer(settled, { type: 'commit' }), settled)
  })
})
