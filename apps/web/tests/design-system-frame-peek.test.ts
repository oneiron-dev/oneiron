import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { PEEK_CLOSED, peekReducer, type PeekAction, type PeekState } from '../src/design-system/frame/frame-peek'

const run = (actions: PeekAction[], from: PeekState = PEEK_CLOSED) => actions.reduce(peekReducer, from)
const shown = (id: string): PeekState => ({ shownId: id, waitingId: null, warm: false })
const waiting = (id: string, warm = false): PeekState => ({ shownId: null, waitingId: id, warm })
const HIDDEN_WARM: PeekState = { shownId: null, waitingId: null, warm: true }

describe('peekReducer, the pointer', () => {
  test('resting on an item waits, then shows its sidebar', () => {
    const s = run([{ type: 'enter', id: 'home', canPeek: true }])
    assert.deepEqual(s, waiting('home'))
    assert.deepEqual(peekReducer(s, { type: 'elapsed', id: 'home' }), shown('home'))
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
    assert.deepEqual(s, waiting('activity'))
  })

  test('an item without a sidebar, or an open sidebar, never peeks', () => {
    assert.equal(run([{ type: 'enter', id: 'more', canPeek: false }]), PEEK_CLOSED)
  })

  test('moving into the overlay keeps it; leaving both hides it at once', () => {
    const s = run([
      { type: 'enter', id: 'home', canPeek: true },
      { type: 'elapsed', id: 'home' },
      { type: 'leave', to: 'overlay' },
    ])
    assert.deepEqual(s, shown('home'))
    assert.deepEqual(peekReducer(s, { type: 'leave', to: 'outside' }), HIDDEN_WARM)
  })

  test('leaving both hides it even when a group label inside it is expanded', () => {
    /* Only an open layer opened from inside the peek holds it, never an
       attribute on its rows. */
    assert.deepEqual(peekReducer(shown('home'), { type: 'leave', to: 'outside', held: false }).shownId, null)
  })

  test('a layer opened from inside the peek holds it while the pointer is away', () => {
    const s = shown('home')
    assert.equal(peekReducer(s, { type: 'leave', to: 'outside', held: true }), s)
    assert.equal(peekReducer(s, { type: 'enter', id: 'activity', canPeek: true, held: true }), s)
    assert.equal(peekReducer(s, { type: 'enter', id: 'more', canPeek: false, held: true }), s)
  })

  test('once the held layer closes, the next leave hides it', () => {
    const still = peekReducer(shown('home'), { type: 'leave', to: 'outside', held: true })
    assert.equal(peekReducer(still, { type: 'leave', to: 'outside', held: false }).shownId, null)
  })

  test('held means nothing while no peek shows', () => {
    assert.deepEqual(run([{ type: 'enter', id: 'home', canPeek: true, held: true }]), waiting('home'))
    assert.deepEqual(peekReducer(waiting('home'), { type: 'leave', to: 'outside', held: true }), PEEK_CLOSED)
  })

  test('a press stops the wait but keeps a shown overlay', () => {
    assert.deepEqual(run([{ type: 'enter', id: 'home', canPeek: true }, { type: 'press' }]), PEEK_CLOSED)
    const s = shown('home')
    assert.equal(peekReducer(s, { type: 'press' }), s)
  })
})

describe('peekReducer, a preview of the place under the pointer', () => {
  test('with a peek up, another item switches at once, with no new delay', () => {
    const s = run([
      { type: 'enter', id: 'home', canPeek: true },
      { type: 'elapsed', id: 'home' },
      { type: 'leave', to: 'item' },
      { type: 'enter', id: 'activity', canPeek: true },
    ])
    assert.deepEqual(s, shown('activity'))
  })

  test('an item without a sidebar hides the peek and shows no other', () => {
    const s = run([{ type: 'leave', to: 'item' }, { type: 'enter', id: 'more', canPeek: false }], shown('home'))
    assert.deepEqual(s, HIDDEN_WARM)
  })

  test('just after a peek hid, the next item with a sidebar shows at once', () => {
    const acrossItem = run([{ type: 'enter', id: 'more', canPeek: false }, { type: 'enter', id: 'vault', canPeek: true }], shown('home'))
    assert.deepEqual(acrossItem, shown('vault'))
    const acrossGap = run([{ type: 'leave', to: 'outside' }, { type: 'enter', id: 'vault', canPeek: true }], shown('home'))
    assert.deepEqual(acrossGap, shown('vault'))
  })

  test('once the warm window ends, the delay applies again', () => {
    const s = run(
      [{ type: 'leave', to: 'outside' }, { type: 'cool' }, { type: 'enter', id: 'vault', canPeek: true }],
      shown('home'),
    )
    assert.deepEqual(s, waiting('vault'))
  })

  test('a peek closed on purpose is not warm', () => {
    assert.deepEqual(run([{ type: 'close' }, { type: 'enter', id: 'vault', canPeek: true }], shown('home')), waiting('vault'))
  })

  test('cool keeps a cold state as it is', () => {
    assert.equal(peekReducer(PEEK_CLOSED, { type: 'cool' }), PEEK_CLOSED)
  })
})

describe('peekReducer, keyboard and touch', () => {
  test('open shows at once', () => {
    assert.deepEqual(run([{ type: 'open', id: 'home', canPeek: true }]), shown('home'))
  })

  test('open does nothing for an item without a sidebar', () => {
    const s = shown('home')
    assert.equal(peekReducer(s, { type: 'open', id: 'more', canPeek: false }), s)
  })

  test('close hides from any state, and keeps the closed state as is', () => {
    assert.deepEqual(peekReducer(shown('home'), { type: 'close' }), PEEK_CLOSED)
    assert.deepEqual(peekReducer(waiting('home'), { type: 'close' }), PEEK_CLOSED)
    assert.deepEqual(peekReducer(HIDDEN_WARM, { type: 'close' }), PEEK_CLOSED)
    assert.equal(peekReducer(PEEK_CLOSED, { type: 'close' }), PEEK_CLOSED)
  })
})
