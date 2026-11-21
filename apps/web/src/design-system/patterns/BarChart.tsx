import * as React from 'react'
import { cx, mergeRefs, useIsomorphicLayoutEffect } from '../lib/react-utils'
import { barChartLayout, barValueFormat, valueLabelBaseline, type BarPeriod, type BarRange } from './bar-chart-layout'

/* The width the chart lays out in before it is measured. */
const DEFAULT_WIDTH_PX = 600

/* The screen of a forecast bar: a 4 px checker used as a mask, so the bar
   keeps its own ink. It is defined once per page, in an element appended
   to the body that is always drawn: a pattern inside a hidden subtree
   paints nothing, even for a chart that is shown. */
export const BAR_SCREEN_MASK_ID = 'sl-bar-screen'
const SVG_NS = 'http://www.w3.org/2000/svg'
let screenUsers = 0

function useScreenMask() {
  useIsomorphicLayoutEffect(() => {
    screenUsers++
    if (!document.getElementById(BAR_SCREEN_MASK_ID)) {
      const svg = document.createElementNS(SVG_NS, 'svg')
      svg.setAttribute('width', '0')
      svg.setAttribute('height', '0')
      svg.setAttribute('aria-hidden', 'true')
      svg.setAttribute('focusable', 'false')
      svg.dataset.slBarScreen = ''
      svg.style.position = 'absolute'
      svg.innerHTML =
        `<defs><pattern id="${BAR_SCREEN_MASK_ID}-cells" width="4" height="4" patternUnits="userSpaceOnUse">` +
        '<rect width="2" height="2" fill="white"/><rect x="2" y="2" width="2" height="2" fill="white"/></pattern>' +
        `<mask id="${BAR_SCREEN_MASK_ID}" maskUnits="userSpaceOnUse" x="-10000" y="-10000" width="20000" height="20000">` +
        `<rect x="-10000" y="-10000" width="20000" height="20000" fill="url(#${BAR_SCREEN_MASK_ID}-cells)"/></mask></defs>`
      document.body.appendChild(svg)
    }
    return () => {
      screenUsers--
      if (screenUsers === 0) document.querySelector('svg[data-sl-bar-screen]')?.remove()
    }
  }, [])
}

export interface BarChartProps extends Omit<React.ComponentPropsWithRef<'figure'>, 'children'> {
  /* Each period's label and its amount. */
  series: readonly BarPeriod[]
  /* The first n periods are measured (solid); the rest are a forecast
     (screened). */
  measuredCount: number
  /* A second value per period, drawn as a ring on the bar's column. */
  compare?: readonly (number | null | undefined)[]
  /* A bracket under the axis from one period to another, with a label. */
  range?: BarRange
  /* The unit, said once at the end of the legend. */
  unit?: string
  /* The legend's words for a measured bar, a forecast bar and a ring;
     an entry shows when its word is given and the chart has such marks. */
  measuredLabel?: string
  forecastLabel?: string
  compareLabel?: string
  /* The chart's accessible name: what it shows, in one sentence. */
  ariaLabel: string
  /* The value labels' format. */
  formatValue?: (value: number) => string
  /* Digits after the point on the value labels, for data that carries no
     function; formatValue wins when both are given. */
  decimals?: number
}

/* Amounts per period as bars from zero, in ink tones only: a measured bar
   solid, a forecast bar screened, a ring for the compared value. Two value
   labels (the last measured bar and the highest), every fourth period
   under the axis, and a legend line under the chart. It fills its
   container's width and keeps its aspect; resting on a column shows that
   period's value. */
export function BarChart({
  ref,
  series,
  measuredCount,
  compare,
  range,
  unit,
  measuredLabel,
  forecastLabel,
  compareLabel,
  ariaLabel,
  formatValue: formatValueProp,
  decimals,
  className,
  ...props
}: BarChartProps) {
  const formatValue = barValueFormat(formatValueProp, decimals)
  const rootRef = React.useRef<HTMLElement | null>(null)
  const [width, setWidth] = React.useState(DEFAULT_WIDTH_PX)
  const [hover, setHover] = React.useState<number | null>(null)
  useScreenMask()

  useIsomorphicLayoutEffect(() => {
    const root = rootRef.current
    if (!root || typeof ResizeObserver === 'undefined') return
    const measure = () => {
      const w = Math.round(root.clientWidth)
      if (w > 0) setWidth(w)
    }
    measure()
    const observer = new ResizeObserver(measure)
    observer.observe(root)
    return () => observer.disconnect()
  }, [])

  const layout = barChartLayout({ series, measuredCount, compare, range, width, formatValue })
  const shown = new Set(layout.valueLabels.map((l) => l.index))
  const hovered = hover !== null && !shown.has(hover) ? layout.bars[hover] : undefined
  const hasForecast = layout.bars.some((b) => b.screened)
  const hasMeasured = layout.bars.some((b) => !b.screened)

  return (
    <figure ref={mergeRefs(ref, rootRef)} className={cx('sl-bar-chart', className)} {...props}>
      <svg
        className="sl-bar-chart-plot"
        viewBox={`0 0 ${layout.width} ${layout.height}`}
        width={layout.width}
        height={layout.height}
        role="img"
        aria-label={ariaLabel}
        onPointerLeave={() => setHover(null)}
      >
        {layout.bars.map((b) => (
          <rect
            key={b.index}
            className="sl-bar-chart-bar"
            data-screened={b.screened ? '' : undefined}
            data-hover={hover === b.index ? '' : undefined}
            x={b.x}
            y={b.y}
            width={b.width}
            height={b.height}
            mask={b.screened ? `url(#${BAR_SCREEN_MASK_ID})` : undefined}
          />
        ))}
        {layout.rings.map((r) => (
          <circle key={r.index} className="sl-bar-chart-ring" cx={r.cx} cy={r.cy} r={r.r} />
        ))}
        {layout.axisLabels.map((l) => (
          <text key={l.index} className="sl-bar-chart-axis" x={l.x} y={l.y} textAnchor="middle">
            {l.text}
          </text>
        ))}
        {layout.valueLabels.map((l) => (
          <text key={l.index} className="sl-bar-chart-value" x={l.x} y={l.y} textAnchor="middle">
            {l.text}
          </text>
        ))}
        {hovered ? (
          <text
            className="sl-bar-chart-value"
            x={hovered.centre}
            y={valueLabelBaseline(hovered, layout.rings.find((r) => r.index === hovered.index))}
            textAnchor="middle"
            aria-hidden="true"
          >
            {formatValue(series[hovered.index].value)}
          </text>
        ) : null}
        {layout.range ? (
          <>
            <path className="sl-bar-chart-bracket" d={layout.range.path} />
            <text className="sl-bar-chart-range" x={layout.range.label.x} y={layout.range.label.y} textAnchor="middle">
              {layout.range.label.text}
            </text>
          </>
        ) : null}
        {/* The column of each period takes the pointer. */}
        {layout.bars.map((b) => (
          <rect
            key={`hit-${b.index}`}
            className="sl-bar-chart-hit"
            x={b.centre - (layout.bars.length > 1 ? (layout.bars[1].x - layout.bars[0].x) / 2 : b.width / 2)}
            y={0}
            width={layout.bars.length > 1 ? layout.bars[1].x - layout.bars[0].x : b.width}
            height={layout.baseline}
            onPointerEnter={() => setHover(b.index)}
          />
        ))}
      </svg>
      <figcaption className="sl-bar-chart-legend">
        {measuredLabel && hasMeasured ? (
          <span>
            <svg viewBox="0 0 10 10" width="10" height="10" aria-hidden="true" focusable="false">
              <rect className="sl-bar-chart-key" width="10" height="10" />
            </svg>
            {measuredLabel}
          </span>
        ) : null}
        {forecastLabel && hasForecast ? (
          <span>
            <svg viewBox="0 0 10 10" width="10" height="10" aria-hidden="true" focusable="false">
              <rect className="sl-bar-chart-key" width="10" height="10" mask={`url(#${BAR_SCREEN_MASK_ID})`} />
            </svg>
            {forecastLabel}
          </span>
        ) : null}
        {compareLabel && layout.rings.length ? (
          <span>
            <svg viewBox="0 0 10 10" width="10" height="10" aria-hidden="true" focusable="false">
              <circle className="sl-bar-chart-ring" cx="5" cy="5" r="3.3" />
            </svg>
            {compareLabel}
          </span>
        ) : null}
        {unit ? <span>{unit}</span> : null}
      </figcaption>
    </figure>
  )
}
