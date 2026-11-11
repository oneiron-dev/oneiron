import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import {
  DONUT_MAX_ARCS,
  arcPath,
  donutCentre,
  donutLabel,
  donutSegments,
  type DonutArc,
} from '../src/design-system/marks/donut-segments'

const many = (done: number, total: number): DonutArc[] =>
  Array.from({ length: total }, (_, i) => (i < done ? 'done' : 'ahead'))

describe('donutSegments, one arc per entry', () => {
  test('three entries give three arcs, clockwise from twelve, in order', () => {
    const g = donutSegments(['done', 'working', 'ahead'], 18)
    assert.equal(g.layout, 'arcs')
    assert.deepEqual(
      g.segments.map((s) => s.state),
      ['done', 'working', 'ahead'],
    )
    assert.deepEqual(
      g.segments.map((s) => [s.start, s.end]),
      [
        [7.64, 112.36],
        [127.64, 232.36],
        [247.64, 352.36],
      ],
    )
  })

  test('the gap between arcs is the same along the ring at every count', () => {
    for (let n = 2; n <= DONUT_MAX_ARCS; n++) {
      const s = donutSegments(many(1, n), 18).segments
      const gaps = s.map((seg, i) => Math.round(((s[(i + 1) % n].start - seg.end + 360) % 360) * 10) / 10)
      assert.ok(gaps.every((g) => Math.abs(g - gaps[0]) <= 0.1), `n=${n}: ${gaps.join(',')}`)
      assert.ok(gaps[0] > 0, `n=${n}: no gap`)
    }
  })

  test('the gap keeps its length in pixels at 14: a wider angle on the smaller ring', () => {
    const big = donutSegments(many(1, 4), 18).segments[0].start * 2
    const small = donutSegments(many(1, 4), 14).segments[0].start * 2
    assert.ok(small > big, `${small} > ${big}`)
  })

  test('one entry is a whole ring, drawn as two half arcs', () => {
    const g = donutSegments(['working'], 18)
    assert.equal(g.segments.length, 1)
    assert.equal(g.segments[0].state, 'working')
    assert.equal(g.segments[0].d, 'M9 3A6 6 0 1 1 9 15A6 6 0 1 1 9 3')
  })

  test('the size sets the ring: radius and stroke at 14 and 18', () => {
    assert.deepEqual([donutSegments(['done'], 18).radius, donutSegments(['done'], 18).stroke], [6, 2.5])
    assert.deepEqual([donutSegments(['done'], 14).radius, donutSegments(['done'], 14).stroke], [4.75, 2])
    assert.equal(donutSegments(['done'], 14).segments[0].d, 'M7 2.25A4.75 4.75 0 1 1 7 11.75A4.75 4.75 0 1 1 7 2.25')
  })

  test('no entries: the empty ring alone', () => {
    const g = donutSegments([], 18)
    assert.equal(g.layout, 'empty')
    assert.deepEqual(
      g.segments.map((s) => [s.state, s.start, s.end]),
      [['track', 0, 360]],
    )
  })

  test('a failed entry keeps its own arc', () => {
    const g = donutSegments(['done', 'failed', 'ahead'], 14)
    assert.equal(g.segments[1].state, 'failed')
  })
})

describe('donutSegments, more than twelve entries', () => {
  test('twelve still draw one arc each', () => {
    assert.equal(donutSegments(many(3, 12)).layout, 'arcs')
    assert.equal(donutSegments(many(3, 12)).segments.length, 12)
  })

  test('thirteen draw the done share as one smooth arc over the ring', () => {
    const g = donutSegments(many(4, 13), 18)
    assert.equal(g.layout, 'smooth')
    assert.deepEqual(
      g.segments.map((s) => [s.state, s.start, s.end]),
      [
        ['track', 0, 360],
        ['done', 0, 110.77],
      ],
    )
  })

  test('working and failed entries do not count toward the share', () => {
    const arcs: DonutArc[] = [...many(2, 10), 'working', 'failed', 'working', 'working']
    const g = donutSegments(arcs, 18)
    assert.equal(g.segments[1].end, Math.round((2 / 14) * 360 * 100) / 100)
  })

  test('all done is one whole done ring; none done is the ring alone', () => {
    assert.deepEqual(
      donutSegments(many(20, 20)).segments.map((s) => s.state),
      ['done'],
    )
    assert.deepEqual(
      donutSegments(many(0, 20)).segments.map((s) => s.state),
      ['track'],
    )
  })
})

describe('arcPath', () => {
  test('a sweep over half the ring sets the large-arc flag', () => {
    assert.equal(arcPath(9, 6, 0, 90), 'M9 3A6 6 0 0 1 15 9')
    assert.equal(arcPath(9, 6, 0, 270), 'M9 3A6 6 0 1 1 3 9')
  })
})

describe('donutCentre', () => {
  test('a dot while something waits on the person, even when all is done', () => {
    assert.equal(donutCentre(['done', 'working'], true), 'dot')
    assert.equal(donutCentre(['done', 'done'], true), 'dot')
  })

  test('a check when every entry is done and nothing waits', () => {
    assert.equal(donutCentre(['done', 'done', 'done'], false), 'check')
  })

  test('nothing otherwise, and nothing for an empty set', () => {
    assert.equal(donutCentre(['done', 'failed'], false), 'none')
    assert.equal(donutCentre([], false), 'none')
  })
})

describe('donutLabel', () => {
  test('done of total, then what waits', () => {
    assert.equal(donutLabel(['done', 'working', 'ahead'], true), '1 of 3 done, waits on you')
    assert.equal(donutLabel(['done', 'done'], false), '2 of 2 done')
  })

  test('failed entries are named', () => {
    assert.equal(donutLabel(['done', 'failed', 'ahead'], false), '1 of 3 done, 1 failed')
  })

  test('an empty set', () => {
    assert.equal(donutLabel([], false), 'nothing yet')
    assert.equal(donutLabel([], true), 'nothing yet, waits on you')
  })
})
