import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { TaskFlow } from '../src/design-system/patterns/TaskFlow'
import { TaskRow } from '../src/design-system/patterns/TaskRow'
import { arcsDone } from '../src/design-system/marks/donut-segments'

describe('a done task', () => {
  test('arcsDone: every arc done, and at least one', () => {
    assert.equal(arcsDone(['done', 'done']), true)
    assert.equal(arcsDone(['done', 'working']), false)
    assert.equal(arcsDone(['done', 'failed']), false)
    assert.equal(arcsDone([]), false)
  })

  test('TaskFlow: done shows a plain 15 px check, no donut', () => {
    const html = renderToStaticMarkup(
      <TaskFlow>
        <TaskFlow.Task id="pull" done>
          pull Acme store sales
        </TaskFlow.Task>
      </TaskFlow>,
    )
    assert.match(html, /data-state="done"/)
    assert.match(html, /<svg class="sl-icon sl-task-flow-check" width="15" height="15"[^>]*role="img" aria-label="done"/)
    assert.doesNotMatch(html, /sl-progress-donut/)
  })

  test('TaskFlow: a task whose arcs are all done is done too', () => {
    const html = renderToStaticMarkup(
      <TaskFlow>
        <TaskFlow.Task id="pull" arcs={['done', 'done']}>
          pull Acme store sales
        </TaskFlow.Task>
        <TaskFlow.Task id="fit" arcs={['done', 'working']}>
          fit the Q4 forecast
        </TaskFlow.Task>
      </TaskFlow>,
    )
    assert.equal(html.match(/sl-task-flow-check/g)?.length, 1)
    assert.equal(html.match(/class="sl-progress-donut"/g)?.length, 1)
  })

  test('TaskRow: all arcs done shows a plain check in place of the donut', () => {
    const done = renderToStaticMarkup(<TaskRow id="pull" arcs={['done', 'done']} name="pull Acme store sales" />)
    assert.match(done, /<svg class="sl-icon sl-task-check" width="15" height="15"[^>]*aria-label="done"/)
    assert.doesNotMatch(done, /sl-progress-donut/)
    const working = renderToStaticMarkup(<TaskRow id="fit" arcs={['done', 'working', 'ahead']} name="fit the Q4 forecast" />)
    assert.match(working, /class="sl-progress-donut"/)
    assert.doesNotMatch(working, /sl-task-check/)
  })
})
