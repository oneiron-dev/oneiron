import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { groupTasks, taskCountWords, taskGroup } from '../src/design-system/patterns/task-group'

describe('taskGroup', () => {
  test('waiting on the person comes first, whatever the steps', () => {
    assert.equal(taskGroup(['done', 'done'], true), 'needs-you')
    assert.equal(taskGroup(['working'], true), 'needs-you')
  })

  test('every step done is done', () => {
    assert.equal(taskGroup(['done', 'done', 'done'], false), 'done')
  })

  test('anything else is working: working, ahead, failed, or no steps yet', () => {
    assert.equal(taskGroup(['done', 'working', 'ahead'], false), 'working')
    assert.equal(taskGroup(['done', 'failed'], false), 'working')
    assert.equal(taskGroup([], false), 'working')
  })
})

describe('groupTasks', () => {
  test('splits into the three groups and keeps the order inside each', () => {
    const groups = groupTasks([
      { id: 'a', arcs: ['done'] },
      { id: 'b', arcs: ['working'], needsYou: true },
      { id: 'c', arcs: ['working'] },
      { id: 'd', arcs: ['done', 'done'] },
      { id: 'e', arcs: ['ahead'], needsYou: true },
    ])
    assert.deepEqual(
      Object.fromEntries(Object.entries(groups).map(([k, v]) => [k, v.map((t) => t.id)])),
      { 'needs-you': ['b', 'e'], working: ['c'], done: ['a', 'd'] },
    )
  })
})

describe('taskCountWords', () => {
  test('one task, then tasks', () => {
    assert.equal(taskCountWords(1), '1 task')
    assert.equal(taskCountWords(3), '3 tasks')
    assert.equal(taskCountWords(0), '0 tasks')
  })
})
