import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { BarChart, BAR_SCREEN_MASK_ID } from '../src/design-system/patterns/BarChart'
import {
  BAR_CHART_ASPECT,
  BAR_CHART_TOP_PX,
  RING_RADIUS,
  barChartLayout,
  highestIndex,
} from '../src/design-system/patterns/bar-chart-layout'

/* Weeks 40 to 52: sold through week 45, then the fit; last year's weeks as rings. */
const VALUES = [3.9, 4.1, 4.0, 4.2, 3.3, 3.1, 3.2, 4.3, 4.5, 4.7, 5.2, 5.6, 3.8]
const LAST = [3.7, 3.9, 3.9, 4.0, 3.2, 3.0, 3.1, 4.1, 4.3, 4.4, 4.9, 5.3, 3.6]
const SERIES = VALUES.map((value, i) => ({ label: String(40 + i), value }))
const RANGE = { from: 4, to: 6, label: 'weeks 44 to 46' }

const layout = (width = 600, compare: Array<number | null> = LAST) =>
  barChartLayout({ series: SERIES, measuredCount: 6, compare, range: RANGE, width })

describe('the bar chart scale', () => {
  test('bars stand on one zero baseline, each as tall as its value on one scale', () => {
    const l = layout()
    for (const b of l.bars) {
      assert.equal(b.y + b.height, l.baseline, `bar ${b.index} ends on the baseline`)
      assert.ok(Math.abs(b.height - SERIES[b.index].value * l.scale) <= 0.5, `bar ${b.index} height follows the scale`)
    }
  })

  test('the tallest mark fits under the room for its label', () => {
    for (const width of [320, 600, 940]) {
      const l = layout(width)
      const tallest = l.bars[highestIndex(SERIES)]
      assert.ok(tallest.y >= BAR_CHART_TOP_PX - 0.5, `at ${width} px the tallest bar starts at ${tallest.y}`)
      for (const r of l.rings) assert.ok(r.cy - r.r >= 0, `ring ${r.index} is in the box`)
      assert.ok(l.bars.every((b) => b.x >= 0 && b.x + b.width <= l.width), `at ${width} px every bar is inside`)
    }
  })

  test('a compared value above every bar sets the scale, so its ring fits too', () => {
    const high = LAST.map((v, i) => (i === 2 ? 9 : v))
    const l = layout(600, high)
    const ring = l.rings.find((r) => r.index === 2)!
    assert.ok(ring.cy >= BAR_CHART_TOP_PX - 0.5)
  })

  test('the chart keeps its aspect at every width', () => {
    for (const width of [320, 600, 940]) {
      const l = layout(width)
      assert.equal(l.height, Math.round(width * BAR_CHART_ASPECT))
    }
  })

  test('nothing but zeros draws no bar and no error', () => {
    const l = barChartLayout({ series: [{ label: '1', value: 0 }], measuredCount: 1, width: 300 })
    assert.equal(l.scale, 0)
    assert.equal(l.bars[0].height, 0)
  })
})

describe('which bars are screened', () => {
  test('the first measuredCount are solid, the rest are the forecast', () => {
    const l = layout()
    assert.deepEqual(
      l.bars.filter((b) => !b.screened).map((b) => b.index),
      [0, 1, 2, 3, 4, 5],
    )
    assert.deepEqual(
      l.bars.filter((b) => b.screened).map((b) => b.index),
      [6, 7, 8, 9, 10, 11, 12],
    )
  })

  test('the screen is a mask defined once per page, used by the forecast bars only', () => {
    const html = renderToStaticMarkup(
      <BarChart series={SERIES} measuredCount={6} compare={LAST} range={RANGE} ariaLabel="Weekly sales" measuredLabel="sold" forecastLabel="the fit" compareLabel="the same week last year" unit="¥ million a week" />,
    )
    const bars = html.match(/<rect class="sl-bar-chart-bar"[^>]*>/g) ?? []
    assert.equal(bars.length, 13)
    assert.equal(bars.filter((b) => b.includes(`mask="url(#${BAR_SCREEN_MASK_ID})"`)).length, 7)
    assert.ok(bars.slice(0, 6).every((b) => !b.includes('mask=')))
    /* The chart itself defines no pattern or mask: the page holds the one definition. */
    assert.doesNotMatch(html, /<pattern|<mask/)
    assert.match(html, /role="img" aria-label="Weekly sales"/)
  })
})

describe('labels', () => {
  test('two value labels: the last measured bar and the highest bar', () => {
    const l = layout()
    assert.deepEqual(
      l.valueLabels.map((v) => [v.index, v.text]),
      [
        [5, '3.1'],
        [11, '5.6'],
      ],
    )
  })

  test('one label when the last measured bar is the highest', () => {
    const l = barChartLayout({ series: SERIES.slice(0, 4), measuredCount: 4, width: 400 })
    assert.deepEqual(
      l.valueLabels.map((v) => v.index),
      [3],
    )
  })

  test('each value label sits clear of its bar and of its ring', () => {
    for (const width of [320, 600, 940]) {
      const l = layout(width)
      for (const v of l.valueLabels) {
        const bar = l.bars[v.index]
        const ring = l.rings.find((r) => r.index === v.index)!
        /* The label's box: about 8 px above its baseline, 2 px below. */
        const bottom = v.y + 2
        assert.ok(bottom < bar.y, `label ${v.index} is above its bar`)
        assert.ok(bottom < ring.cy - RING_RADIUS, `label ${v.index} is above its ring`)
        assert.equal(v.x, bar.centre)
      }
    }
  })

  test('a ring above its bar lifts the label over the ring', () => {
    const lifted = LAST.map((v, i) => (i === 5 ? 4.5 : v))
    const l = layout(600, lifted)
    const label = l.valueLabels.find((v) => v.index === 5)!
    const ring = l.rings.find((r) => r.index === 5)!
    assert.ok(ring.cy - ring.r < l.bars[5].y)
    assert.ok(Math.abs(label.y - (ring.cy - ring.r - 6)) < 0.01)
  })

  test('every fourth period under the axis, and the bracket under the range', () => {
    const l = layout()
    assert.deepEqual(
      l.axisLabels.map((a) => a.text),
      ['40', '44', '48', '52'],
    )
    assert.ok(l.range)
    assert.equal(l.range.x0, l.bars[4].x)
    assert.equal(l.range.x1, l.bars[6].x + l.bars[6].width)
    assert.ok(l.range.label.y > l.baseline + 24)
  })

  test('the legend names each mark the chart has, then the unit', () => {
    const html = renderToStaticMarkup(
      <BarChart series={SERIES} measuredCount={6} compare={LAST} ariaLabel="Weekly sales" measuredLabel="sold" forecastLabel="the fit" compareLabel="the same week last year" unit="¥ million a week" />,
    )
    const legend = html.slice(html.indexOf('sl-bar-chart-legend'))
    const words = ['sold', 'the fit', 'the same week last year', '¥ million a week'].map((w) => legend.indexOf(w))
    assert.ok(words.every((at) => at > 0))
    assert.deepEqual([...words].sort((a, b) => a - b), words)
    /* All measured: no forecast entry. */
    const measured = renderToStaticMarkup(<BarChart series={SERIES} measuredCount={13} ariaLabel="Weekly sales" measuredLabel="sold" forecastLabel="the fit" />)
    assert.doesNotMatch(measured, /the fit/)
  })
})
