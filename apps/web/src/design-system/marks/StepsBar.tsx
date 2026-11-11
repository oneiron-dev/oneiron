import * as React from 'react'
import { cx, useSafeId } from '../lib/react-utils'
import { stepsBarCells, stepsBarLabel, type Step } from './steps-bar-cells'

/* The bar's drawn size and the gap between cells, in CSS pixels. */
const BAR_WIDTH = 84
const BAR_HEIGHT = 6
const BAR_GAP = 2

export interface StepsBarProps extends Omit<React.ComponentPropsWithRef<'span'>, 'children'> {
  steps: readonly Step[]
  /* Accessible name; defaults to "n of m steps done". */
  label?: string
}

/* A run's plan as a bar: filled done, half-tone working (its sub-progress
   filling it), empty ahead. Past eight steps it becomes twelve fixed cells.
   The caller derives each step's state from the run; the bar keeps no
   clock. */
export function StepsBar({ steps, label, className, ...props }: StepsBarProps) {
  const patternId = useSafeId('sl-steps-halftone')
  const { layout, cells } = stepsBarCells(steps)
  const n = cells.length
  const w = n ? (BAR_WIDTH - BAR_GAP * (n - 1)) / n : 0
  return (
    <span
      role="img"
      aria-label={label ?? stepsBarLabel(steps)}
      className={cx('sl-steps-bar', className)}
      data-layout={layout}
      {...props}
    >
      <svg
        width={BAR_WIDTH}
        height={BAR_HEIGHT}
        viewBox={`0 0 ${BAR_WIDTH} ${BAR_HEIGHT}`}
        shapeRendering="crispEdges"
        aria-hidden="true"
        focusable="false"
      >
        <defs>
          <pattern id={patternId} width="2" height="2" patternUnits="userSpaceOnUse">
            <rect className="sl-steps-ink" width="1" height="1" />
            <rect className="sl-steps-ink" x="1" y="1" width="1" height="1" />
          </pattern>
        </defs>
        {cells.map((cell, i) => {
          const x = i * (w + BAR_GAP)
          return (
            <g key={i} data-state={cell.state}>
              <rect className="sl-steps-track" x={x} y="0" width={w} height={BAR_HEIGHT} />
              {cell.halftone > 0 ? (
                <rect x={x} y="0" width={w * cell.halftone} height={BAR_HEIGHT} fill={`url(#${patternId})`} />
              ) : null}
              {cell.solid > 0 ? (
                <rect className="sl-steps-ink" x={x} y="0" width={w * cell.solid} height={BAR_HEIGHT} />
              ) : null}
            </g>
          )
        })}
      </svg>
    </span>
  )
}
