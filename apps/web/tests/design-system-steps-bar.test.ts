import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import {
  STEPS_BAR_FIXED_CELLS,
  stepsBarCells,
  stepsBarLabel,
  type Step,
} from '../src/design-system/marks/steps-bar-cells'

const done: Step = { state: 'done' }
const ahead: Step = { state: 'ahead' }
const failed: Step = { state: 'failed' }
const working = (progress?: number): Step => ({ state: 'working', progress })

describe('stepsBarCells, one cell per step', () => {
  test('an empty plan draws nothing', () => {
    assert.deepEqual(stepsBarCells([]), { layout: 'per-step', cells: [] })
  })

  test('done is solid, working is half-tone with its progress in solid, ahead is empty', () => {
    assert.deepEqual(stepsBarCells([done, working(0.4), ahead]), {
      layout: 'per-step',
      cells: [
        { state: 'done', solid: 1, halftone: 0 },
        { state: 'working', solid: 0.4, halftone: 1 },
        { state: 'ahead', solid: 0, halftone: 0 },
      ],
    })
  })

  test('a working step without sub-progress is all half-tone', () => {
    assert.deepEqual(stepsBarCells([working()]).cells, [{ state: 'working', solid: 0, halftone: 1 }])
  })

  test('progress is clamped to 0..1 and non-numbers count as 0', () => {
    assert.equal(stepsBarCells([working(1.5)]).cells[0].solid, 1)
    assert.equal(stepsBarCells([working(-0.2)]).cells[0].solid, 0)
    assert.equal(stepsBarCells([working(Number.NaN)]).cells[0].solid, 0)
  })

  test('a failed step is an empty cell in the failed state', () => {
    assert.deepEqual(stepsBarCells([done, failed, ahead]), {
      layout: 'per-step',
      cells: [
        { state: 'done', solid: 1, halftone: 0 },
        { state: 'failed', solid: 0, halftone: 0 },
        { state: 'ahead', solid: 0, halftone: 0 },
      ],
    })
  })

  test('progress on a failed step is ignored', () => {
    assert.deepEqual(stepsBarCells([{ state: 'failed', progress: 0.6 }]).cells, [{ state: 'failed', solid: 0, halftone: 0 }])
  })

  test('eight steps still draw one cell each', () => {
    const result = stepsBarCells(Array.from({ length: 8 }, () => done))
    assert.equal(result.layout, 'per-step')
    assert.equal(result.cells.length, 8)
  })
})

describe('stepsBarCells, past eight steps', () => {
  test('nine or more steps fall back to twelve fixed cells filled by done over total', () => {
    const plan: Step[] = [...Array.from({ length: 5 }, () => done), working(0.5), ahead, ahead, ahead, ahead]
    const result = stepsBarCells(plan)
    assert.equal(result.layout, 'fixed')
    assert.equal(result.cells.length, STEPS_BAR_FIXED_CELLS)
    /* 5 of 10 done → floor(0.5 * 12) = 6 solid cells */
    assert.deepEqual(
      result.cells.map((c) => c.state),
      ['done', 'done', 'done', 'done', 'done', 'done', 'working', 'ahead', 'ahead', 'ahead', 'ahead', 'ahead'],
    )
    assert.deepEqual(result.cells[6], { state: 'working', solid: 0, halftone: 0.5 })
  })

  test('the working cell appears only when the working step has progress', () => {
    const plan: Step[] = [done, done, done, working(0), ahead, ahead, ahead, ahead, ahead]
    const result = stepsBarCells(plan)
    assert.equal(result.cells.filter((c) => c.state === 'working').length, 0)
    /* 3 of 9 done → floor(4) = 4 solid cells */
    assert.equal(result.cells.filter((c) => c.state === 'done').length, 4)
  })

  test('a failed step marks the cell after the done cells when no step is working', () => {
    const plan: Step[] = [done, done, done, failed, ahead, ahead, ahead, ahead, ahead]
    const result = stepsBarCells(plan)
    /* 3 of 9 done → 4 solid cells, then the failed cell */
    assert.deepEqual(
      result.cells.slice(0, 6).map((c) => c.state),
      ['done', 'done', 'done', 'done', 'failed', 'ahead'],
    )
    assert.equal(result.cells.filter((c) => c.state === 'failed').length, 1)
  })

  test('a working step with progress wins the next cell over a failed step', () => {
    const plan: Step[] = [done, done, done, failed, working(0.5), ahead, ahead, ahead, ahead]
    const states = stepsBarCells(plan).cells.map((c) => c.state)
    assert.equal(states[4], 'working')
    assert.ok(!states.includes('failed'))
  })

  test('a finished long plan fills all twelve cells', () => {
    const result = stepsBarCells(Array.from({ length: 9 }, () => done))
    assert.ok(result.cells.every((c) => c.state === 'done' && c.solid === 1))
  })
})

describe('stepsBarLabel', () => {
  test('names the done count and the working step', () => {
    assert.equal(stepsBarLabel([done, working(0.2), ahead]), '1 of 3 steps done, step 2 of 3 working')
    assert.equal(stepsBarLabel([done, done]), '2 of 2 steps done')
  })

  test('names the failed step when none is working', () => {
    assert.equal(stepsBarLabel([done, failed, ahead]), '1 of 3 steps done, step 2 of 3 failed')
  })
})
