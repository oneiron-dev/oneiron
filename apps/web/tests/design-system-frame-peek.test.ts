import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { PEEK_CLOSED, peekReducer, type PeekAction, type PeekState } from '../src/design-system/frame/frame-peek'

const run = (actions: PeekAction[], from: PeekState = PEEK_CLOSED) => actions.reduce(peekReducer, from)

describe('peekReducer, the pointer', () => {
  test('resting on an item waits, then shows its sidebar', () => {
    const waiting = run([{ type: 'enter', id: 'home', canPeek: true }])
    assert.deepEqual(waiting, { shownId: null, waitingId: 'home' })
    assert.deepEqual(peekReducer(waiting, { type: 'elapsed', id: 'home' }), { shownId: 'home', waitingId: null })
  })

  test('leaving before the delay ends shows nothing', () => {
    const s = run([
      { type: 'enter', id: 'home', canPeek: true },
      { type: 'leave', to: 'outside' },
      { type: 'elapsed', id: 'home' },
    ])
    assert.deepEqual(s, PEEK_CLOSED)
  })

  test('a stale delay for another item does nothing', () => {
    const s = run([
      { type: 'enter', id: 'home', canPeek: true },
      { type: 'leave', to: 'item' },
      { type: 'enter', id: 'activity', canPeek: true },
      { type: 'elapsed', id: 'home' },
    ])
    assert.deepEqual(s, { shownId: null, waitingId: 'activity' })
  })

  test('an item without a sidebar, or an open sidebar, never peeks', () => {
    assert.deepEqual(run([{ type: 'enter', id: 'more', canPeek: false }]), PEEK_CLOSED)
    assert.equal(run([{ type: 'enter', id: 'more', canPeek: false }]), PEEK_CLOSED)
  })

  test('moving into the overlay keeps it; leaving both hides it at once', () => {
    const shown = run([
      { type: 'enter', id: 'home', canPeek: true },
      { type: 'elapsed', id: 'home' },
      { type: 'leave', to: 'overlay' },
    ])
    assert.deepEqual(shown, { shownId: 'home', waitingId: null })
    assert.deepEqual(peekReducer(shown, { type: 'leave', to: 'outside' }), PEEK_CLOSED)
  })

  test('with an overlay up, another item switches at once', () => {
    const s = run([
      { type: 'enter', id: 'home', canPeek: true },
      { type: 'elapsed', id: 'home' },
      { type: 'leave', to: 'item' },
      { type: 'enter', id: 'activity', canPeek: true },
    ])
    assert.deepEqual(s, { shownId: 'activity', waitingId: null })
  })

  test('with an overlay up, an item without a sidebar hides it', () => {
    const s = run([
      { type: 'enter', id: 'home', canPeek: true },
      { type: 'elapsed', id: 'home' },
      { type: 'leave', to: 'item' },
      { type: 'enter', id: 'more', canPeek: false },
    ])
    assert.deepEqual(s, PEEK_CLOSED)
  })

  test('a press stops the wait but keeps a shown overlay', () => {
    assert.deepEqual(run([{ type: 'enter', id: 'home', canPeek: true }, { type: 'press' }]), PEEK_CLOSED)
    const shown = { shownId: 'home', waitingId: null }
    assert.equal(peekReducer(shown, { type: 'press' }), shown)
  })
})

describe('peekReducer, keyboard and touch', () => {
  test('open shows at once', () => {
    assert.deepEqual(run([{ type: 'open', id: 'home', canPeek: true }]), { shownId: 'home', waitingId: null })
  })

  test('open does nothing for an item without a sidebar', () => {
    const shown = { shownId: 'home', waitingId: null }
    assert.equal(peekReducer(shown, { type: 'open', id: 'more', canPeek: false }), shown)
  })

  test('close hides from any state, and keeps the closed state as is', () => {
    assert.deepEqual(peekReducer({ shownId: 'home', waitingId: null }, { type: 'close' }), PEEK_CLOSED)
    assert.deepEqual(peekReducer({ shownId: null, waitingId: 'home' }, { type: 'close' }), PEEK_CLOSED)
    assert.equal(peekReducer(PEEK_CLOSED, { type: 'close' }), PEEK_CLOSED)
  })
})
