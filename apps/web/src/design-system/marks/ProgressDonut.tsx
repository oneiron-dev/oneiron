import * as React from 'react'
import { Tooltip } from '../overlays/Tooltip'
import { cx } from '../lib/react-utils'
import { donutCentre, donutLabel, donutSegments, type DonutArc, type DonutSize } from './donut-segments'

export interface ProgressDonutProps extends Omit<React.ComponentPropsWithRef<'span'>, 'children'> {
  /* One entry per task of a set, or per step of one task, in order. */
  arcs: readonly DonutArc[]
  /* Something in the set waits on the person: a dot in the middle. */
  needsYou?: boolean
  size?: DonutSize
  /* The tooltip and accessible name; `1 of 3 done, waits on you` by default. */
  label?: string
}

/* Progress of a set of tasks, or of one task's steps, as a ring of arcs:
   done in the reading ink, working one step quieter, ahead in the track
   tone, failed as a dashed arc. The middle holds a dot when something
   waits on the person, a check when all is done. Nothing in it moves. */
export function ProgressDonut({ arcs, needsYou = false, size = 18, label, className, ...props }: ProgressDonutProps) {
  const geometry = donutSegments(arcs, size)
  const centre = donutCentre(arcs, needsYou)
  const name = label ?? donutLabel(arcs, needsYou)
  const mid = size / 2
  return (
    <Tooltip label={name}>
      <span
        role="img"
        aria-label={name}
        className={cx('sl-progress-donut', className)}
        data-size={size}
        data-layout={geometry.layout}
        {...props}
      >
        <svg viewBox={`0 0 ${size} ${size}`} width={size} height={size} aria-hidden="true" focusable="false">
          {geometry.segments.map((segment, i) => (
            <path key={i} className="sl-donut-arc" data-state={segment.state} d={segment.d} strokeWidth={geometry.stroke} />
          ))}
          {centre === 'dot' ? <circle className="sl-donut-dot" cx={mid} cy={mid} r={geometry.dot} /> : null}
          {centre === 'check' ? (
            <path className="sl-donut-check" d={geometry.check} strokeWidth={geometry.checkStroke} />
          ) : null}
        </svg>
      </span>
    </Tooltip>
  )
}
