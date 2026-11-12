import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { SIDEBAR_CHILD_ROWS_SHOWN, splitChildRows } from '../src/design-system/frame/sidebar-tree'

describe('splitChildRows', () => {
  test('five or fewer child rows all show', () => {
    assert.equal(SIDEBAR_CHILD_ROWS_SHOWN, 5)
    for (const n of [0, 1, 5]) assert.deepEqual(splitChildRows(n), { shown: n, folded: 0 })
  })

  test('past five, the rest fold behind show more', () => {
    assert.deepEqual(splitChildRows(6), { shown: 5, folded: 1 })
    assert.deepEqual(splitChildRows(12), { shown: 5, folded: 7 })
  })

  test('a caller limit and odd counts', () => {
    assert.deepEqual(splitChildRows(4, 3), { shown: 3, folded: 1 })
    assert.deepEqual(splitChildRows(-2), { shown: 0, folded: 0 })
    assert.deepEqual(splitChildRows(7.6), { shown: 5, folded: 2 })
  })
})
