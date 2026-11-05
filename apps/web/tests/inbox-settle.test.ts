import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { settleFixture, previewReply } from '../src/components/safelight/inbox-fixture'

describe('Inbox local decision preview', () => {
  test('the first choice settles once; repeats and conflicting choices preserve it', () => {
    const receipt = settleFixture(null, 'accept')
    assert.equal(receipt.word, 'accepted locally')
    assert.equal(receipt.clock, 'fixture 14:09')
    assert.equal(receipt.ok, true)
    assert.equal(settleFixture(receipt, 'accept'), receipt)
    assert.equal(settleFixture(receipt, 'reject'), receipt)
  })
})

describe('Inbox reply preview', () => {
  test('Enter keeps trimmed words locally as one replaceable record, never a send', () => {
    const reply = previewReply(null, '  Please shorten it.  ', { key: 'Enter' })
    assert.deepEqual(reply, { text: 'Please shorten it.', clock: 'fixture 14:09' })
    assert.equal(previewReply(reply, 'Please shorten it.', { key: 'Enter' }), reply)
    assert.equal(previewReply(reply, 'Use Tuesday.', { key: 'Enter' })?.text, 'Use Tuesday.')
  })
})

test('reply input ignores blanks, typing, IME confirmation, held keys and modifier chords', () => {
  const current = previewReply(null, 'Keep this.', { key: 'Enter' })
  const ignored = [
    { key: 'a' }, { key: ' ' }, { key: 'Escape' },
    { key: 'Enter', isComposing: true }, { key: 'Enter', keyCode: 229 },
    { key: 'Enter', repeat: true }, { key: 'Enter', metaKey: true },
    { key: 'Enter', ctrlKey: true }, { key: 'Enter', altKey: true },
    { key: 'Enter', shiftKey: true },
  ]
  for (const event of ignored) {
    assert.equal(previewReply(null, 'New words.', event), null)
    assert.equal(previewReply(current, 'New words.', event), current)
  }
  assert.equal(previewReply(null, ' \n\t ', { key: 'Enter' }), null)
  assert.equal(previewReply(current, '   ', { key: 'Enter' }), current)
})

test('all choices use explicit local outcomes and a fixed fixture clock', () => {
  const words = {
    accept: 'accepted locally', reject: 'rejected locally',
    send: 'previewed · not sent', allow: 'allowed locally · not sent',
    grant: 'previewed · no grant created', deny: 'denied locally',
    discard: 'discarded locally · run unchanged',
  } as const
  for (const action of Object.keys(words) as Array<keyof typeof words>) {
    const receipt = settleFixture(null, action)
    assert.equal(receipt.word, words[action])
    assert.equal(receipt.clock, 'fixture 14:09')
    assert.equal(receipt.ok, !['reject', 'deny', 'discard'].includes(action))
    assert.equal(settleFixture(receipt, action), receipt)
  }
})
