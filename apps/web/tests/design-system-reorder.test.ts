import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { dropIndex, leadingEdge, moveItem, shiftFor } from '../src/design-system/frame/reorder'

const rooms = ['pinned', 'rooms', 'projects', 'vault']

describe('moveItem', () => {
  test('moves an item down', () => {
    assert.deepEqual(moveItem(rooms, 0, 2), ['rooms', 'projects', 'pinned', 'vault'])
  })

  test('moves an item up', () => {
    assert.deepEqual(moveItem(rooms, 3, 1), ['pinned', 'vault', 'rooms', 'projects'])
  })

  test('to the same place returns an equal copy, never the same array', () => {
    const out = moveItem(rooms, 1, 1)
    assert.deepEqual(out, rooms)
    assert.notEqual(out, rooms)
  })

  test('a target past either end is clamped', () => {
    assert.deepEqual(moveItem(rooms, 1, 99), ['pinned', 'projects', 'vault', 'rooms'])
    assert.deepEqual(moveItem(rooms, 2, -5), ['projects', 'pinned', 'rooms', 'vault'])
  })

  test('a source outside the list changes nothing', () => {
    assert.deepEqual(moveItem(rooms, -1, 0), rooms)
    assert.deepEqual(moveItem(rooms, 4, 0), rooms)
    assert.deepEqual(moveItem(rooms, 1.5, 0), rooms)
  })

  test('the input is never changed', () => {
    const list = ['a', 'b', 'c']
    moveItem(list, 0, 2)
    assert.deepEqual(list, ['a', 'b', 'c'])
  })

  test('an empty list stays empty', () => {
    assert.deepEqual(moveItem([], 0, 0), [])
  })
})

describe('dropIndex', () => {
  /* Four 30 px rows with a 1 px gap: midpoints 15, 46, 77, 108. */
  const mids = [15, 46, 77, 108]

  test('a row held near its own place stays there', () => {
    assert.equal(dropIndex(mids, 1, 46), 1)
    assert.equal(dropIndex(mids, 1, 50), 1)
  })

  test('a row dragged past a neighbour midpoint takes its slot', () => {
    assert.equal(dropIndex(mids, 0, 47), 1)
    assert.equal(dropIndex(mids, 0, 80), 2)
    assert.equal(dropIndex(mids, 3, 40), 1)
    assert.equal(dropIndex(mids, 3, 0), 0)
  })

  test('past the last row it lands last', () => {
    assert.equal(dropIndex(mids, 0, 500), 3)
  })
})

describe('leadingEdge', () => {
  test('moving down leads with the bottom, moving up with the top, at rest the midpoint', () => {
    assert.equal(leadingEdge(15, 30, 10), 40)
    assert.equal(leadingEdge(108, 30, -10), 83)
    assert.equal(leadingEdge(46, 30, 0), 46)
  })

  test('with dropIndex: a row gives way once the edge passes half of it', () => {
    const mids = [15, 46, 77, 108]
    /* Row 0 (30 tall) moved 16 px down: bottom edge 46 is not past row 1's midpoint yet. */
    assert.equal(dropIndex(mids, 0, leadingEdge(15, 30, 16)), 0)
    assert.equal(dropIndex(mids, 0, leadingEdge(15, 30, 17)), 1)
    /* A tall item (a group, 120 tall at midpoint 300) dragged up by its head
       passes a 30 px row above once its top crosses that row's midpoint. */
    const groups = [100, 300]
    assert.equal(dropIndex(groups, 1, leadingEdge(300, 120, -139)), 1)
    assert.equal(dropIndex(groups, 1, leadingEdge(300, 120, -141)), 0)
  })
})

describe('shiftFor', () => {
  test('dragging down: the rows passed move up by the dragged extent', () => {
    assert.deepEqual([0, 1, 2, 3].map((j) => shiftFor(j, 0, 2, 31)), [0, -31, -31, 0])
  })

  test('dragging up: the rows passed move down', () => {
    assert.deepEqual([0, 1, 2, 3].map((j) => shiftFor(j, 3, 1, 31)), [0, 31, 31, 0])
  })

  test('held in place: nothing moves', () => {
    assert.deepEqual([0, 1, 2, 3].map((j) => shiftFor(j, 2, 2, 31)), [0, 0, 0, 0])
  })
})
