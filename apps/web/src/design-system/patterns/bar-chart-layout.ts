/* The bar chart as geometry: amounts per period as bars from a zero
   baseline, the first `measuredCount` measured and the rest a forecast,
   an optional second value per period as a ring on the bar's column, and
   an optional bracket under the axis. Laid out in CSS pixels at a measured
   width, so the type keeps its size while the chart keeps its aspect.
   Pure, so it is tested without a DOM. */

export interface BarPeriod {
  /* The period's name under the axis: `40` for week 40. */
  label: string
  value: number
}

export interface BarRange {
  /* First and last period index of the bracket, inclusive. */
  from: number
  to: number
  label: string
}

/* The format of the value labels: the caller's function, else a fixed
   number of digits after the point (data without a function can say how
   many), else the number as it is. A function wins over digits. */
export function barValueFormat(formatValue?: (value: number) => string, decimals?: number): (value: number) => string {
  if (formatValue) return formatValue
  if (decimals !== undefined && Number.isInteger(decimals) && decimals >= 0 && decimals <= 20) return (value) => value.toFixed(decimals)
  return String
}

export interface BarChartInput {
  series: readonly BarPeriod[]
  /* The first n periods are measured; the rest are a forecast. */
  measuredCount: number
  /* A second value per period (null where there is none), drawn as a ring. */
  compare?: readonly (number | null | undefined)[]
  range?: BarRange
  /* The width to lay out in, in CSS pixels. */
  width: number
  formatValue?: (value: number) => string
}

export interface BarMark {
  index: number
  x: number
  y: number
  width: number
  height: number
  /* A forecast bar: drawn screened. */
  screened: boolean
  /* The centre of the bar's column. */
  centre: number
}

export interface BarRing {
  index: number
  cx: number
  cy: number
  r: number
}

/* A text label: x is its centre, y its baseline. */
export interface BarLabel {
  index: number
  x: number
  y: number
  text: string
}

export interface BarChartLayout {
  width: number
  height: number
  /* The zero line, in pixels from the top. */
  baseline: number
  /* Pixels per unit of value. */
  scale: number
  bars: BarMark[]
  rings: BarRing[]
  /* Every fourth period, from the first. */
  axisLabels: BarLabel[]
  /* The last measured bar and the highest bar. */
  valueLabels: BarLabel[]
  range: { path: string; x0: number; x1: number; label: BarLabel } | null
}

/* The chart's proportions: 600 by 190 at full size. */
export const BAR_CHART_ASPECT = 190 / 600
/* Room above the highest mark for its value label. */
export const BAR_CHART_TOP_PX = 24
/* The band under the zero line: the axis labels, and the bracket with its
   label when there is a range. */
export const BAR_CHART_AXIS_PX = 22
export const BAR_CHART_RANGE_PX = 48
/* Space at each side of the bars. */
export const BAR_CHART_SIDE_PX = 12
/* A bar's share of its period's slot. */
export const BAR_SHARE = 2 / 3
export const RING_RADIUS = 3
/* Every how many periods the axis is labelled. */
export const AXIS_LABEL_EVERY = 4
/* The gap between a value label's baseline and the mark under it. */
export const VALUE_LABEL_GAP_PX = 6

const round2 = (n: number) => Math.round(n * 100) / 100

/* The index of the highest value (the first one, on a tie). */
export function highestIndex(series: readonly BarPeriod[]): number {
  let best = -1
  for (let i = 0; i < series.length; i++) if (best < 0 || series[i].value > series[best].value) best = i
  return best
}

/* The baseline of a value label over bar `bar`: clear of the bar's top
   and of the ring's top, whichever is higher. */
export function valueLabelBaseline(bar: BarMark, ring: BarRing | undefined): number {
  const top = Math.min(bar.y, ring ? ring.cy - ring.r : Infinity)
  return round2(top - VALUE_LABEL_GAP_PX)
}

export function barChartLayout({ series, measuredCount, compare = [], range, width, formatValue = String }: BarChartInput): BarChartLayout {
  const w = Math.max(1, Math.round(width))
  const height = Math.round(w * BAR_CHART_ASPECT)
  const band = range ? BAR_CHART_RANGE_PX : BAR_CHART_AXIS_PX
  const baseline = height - band
  const n = series.length
  const peak = Math.max(0, ...series.map((p) => p.value), ...compare.map((c) => c ?? 0))
  const scale = peak > 0 ? Math.max(0, baseline - BAR_CHART_TOP_PX) / peak : 0
  const slot = n ? (w - 2 * BAR_CHART_SIDE_PX) / n : 0
  const barWidth = Math.max(2, Math.round(slot * BAR_SHARE))

  const bars: BarMark[] = series.map((p, index) => {
    const x = Math.round(BAR_CHART_SIDE_PX + index * slot + (slot - barWidth) / 2)
    const h = Math.round(Math.max(0, p.value) * scale)
    return { index, x, y: baseline - h, width: barWidth, height: h, screened: index >= measuredCount, centre: x + barWidth / 2 }
  })

  const rings: BarRing[] = []
  compare.forEach((c, index) => {
    if (c == null || index >= n) return
    rings.push({ index, cx: bars[index].centre, cy: round2(baseline - Math.max(0, c) * scale), r: RING_RADIUS })
  })
  const ringAt = (index: number) => rings.find((r) => r.index === index)

  const axisLabels = bars
    .filter((b) => b.index % AXIS_LABEL_EVERY === 0)
    .map((b) => ({ index: b.index, x: b.centre, y: baseline + 15, text: series[b.index].label }))

  const picked = [Math.min(measuredCount, n) - 1, highestIndex(series)].filter((i, k, all) => i >= 0 && all.indexOf(i) === k)
  const valueLabels = picked.map((index) => ({
    index,
    x: bars[index].centre,
    y: valueLabelBaseline(bars[index], ringAt(index)),
    text: formatValue(series[index].value),
  }))

  let rangeMark: BarChartLayout['range'] = null
  if (range && n && range.from >= 0 && range.to < n && range.from <= range.to) {
    const x0 = bars[range.from].x
    const x1 = bars[range.to].x + barWidth
    const top = baseline + 24
    rangeMark = {
      path: `M${x0} ${top}v4H${x1}v-4`,
      x0,
      x1,
      label: { index: range.from, x: round2((x0 + x1) / 2), y: baseline + 42, text: range.label },
    }
  }

  return { width: w, height, baseline, scale, bars, rings, axisLabels, valueLabels, range: rangeMark }
}
