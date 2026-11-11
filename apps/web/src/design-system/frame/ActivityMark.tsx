import * as React from 'react'
import { GuestRing } from '../marks/GuestRing'
import { StatusDot } from '../marks/StatusDot'
import { Icon } from '../primitives/Icon'
import { cx } from '../lib/react-utils'

export type ActivityKind = 'needs-you' | 'running' | 'mention' | 'done' | 'reaction' | 'outside'

/* What a screen reader hears for each mark. */
export const ACTIVITY_KIND_LABEL: Record<ActivityKind, string> = {
  'needs-you': 'waits on you',
  running: 'working',
  mention: 'mentioned you',
  done: 'done',
  reaction: 'reacted',
  outside: 'from another vault',
}

/* The working mark: a short half-tone segment, the steps bar's working
   screen (one 1 px dot on every other pixel of a 12 x 6 box). */
const HALFTONE = Array.from({ length: 12 * 6 }, (_, i) => [i % 12, Math.floor(i / 12)] as const)
  .filter(([x, y]) => (x + y) % 2 === 0)
  .map(([x, y]) => `M${x} ${y}h1v1h-1z`)
  .join('')

export interface ActivityMarkProps extends Omit<React.ComponentPropsWithRef<'span'>, 'children'> {
  kind: ActivityKind
  /* Accessible name; defaults to the kind said in words. */
  label?: string
}

/* What happened, as one mark: a ring waits on you, half-tone is working,
   the at sign is a mention, a guest ring comes from outside, a check is
   done, a face is a reaction. The mark is the state; no word is shown. */
export function ActivityMark({ kind, label, className, ...props }: ActivityMarkProps) {
  const name = label ?? ACTIVITY_KIND_LABEL[kind]
  const own = { className: cx('sl-activity-mark', className), 'data-kind': kind }
  if (kind === 'needs-you') return <StatusDot state="waiting" label={name} {...own} {...props} />
  if (kind === 'outside') return <GuestRing label={name} {...own} {...props} />
  let mark: React.ReactNode
  if (kind === 'running') {
    mark = (
      <svg viewBox="0 0 12 6" width="12" height="6" shapeRendering="crispEdges" aria-hidden="true" focusable="false">
        <path d={HALFTONE} />
      </svg>
    )
  } else {
    mark = <Icon name={kind === 'mention' ? 'at' : kind === 'done' ? 'check' : 'smile'} size={15} />
  }
  return (
    <span role="img" aria-label={name} {...own} {...props}>
      {mark}
    </span>
  )
}
