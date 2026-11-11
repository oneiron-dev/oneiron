import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { findBoostWord } from '../src/design-system/patterns/find-boost-word'

const WORDS = ['ultrathink', 'think hard']

describe('findBoostWord', () => {
  test('a word that stands alone matches', () => {
    assert.equal(findBoostWord('please ultrathink this one', WORDS), 'ultrathink')
  })

  test('at the start, at the end and next to punctuation', () => {
    assert.equal(findBoostWord('ultrathink: the Q4 view', WORDS), 'ultrathink')
    assert.equal(findBoostWord('check the fit, ultrathink', WORDS), 'ultrathink')
    assert.equal(findBoostWord('(ultrathink)', WORDS), 'ultrathink')
  })

  test('case does not matter; the word comes back as given', () => {
    assert.equal(findBoostWord('ULTRATHINK it', WORDS), 'ultrathink')
  })

  test('inside a longer word it does not match', () => {
    assert.equal(findBoostWord('ultrathinking about it', WORDS), null)
    assert.equal(findBoostWord('preultrathink', WORDS), null)
    assert.equal(findBoostWord('ultrathink_2', WORDS), null)
    assert.equal(findBoostWord('ultrathink2', WORDS), null)
  })

  test('letters outside ASCII count as word letters', () => {
    assert.equal(findBoostWord('éultrathink', WORDS), null)
    assert.equal(findBoostWord('ultrathinké', WORDS), null)
  })

  test('a phrase matches as a whole', () => {
    assert.equal(findBoostWord('think hard about the stores', WORDS), 'think hard')
    assert.equal(findBoostWord('think harder about it', WORDS), null)
  })

  test('the earliest in the text wins; on a tie the longer word', () => {
    assert.equal(findBoostWord('think hard, then ultrathink', WORDS), 'think hard')
    assert.equal(findBoostWord('think hard', ['think', 'think hard']), 'think hard')
  })

  test('no words, blank words and empty text never match', () => {
    assert.equal(findBoostWord('ultrathink', []), null)
    assert.equal(findBoostWord('anything', ['', '  ']), null)
    assert.equal(findBoostWord('', WORDS), null)
  })

  test('words with symbols are matched as written', () => {
    assert.equal(findBoostWord('try c++ here', ['c++']), 'c++')
    assert.equal(findBoostWord('a.b', ['a.b']), 'a.b')
    assert.equal(findBoostWord('axb', ['a.b']), null)
  })
})
