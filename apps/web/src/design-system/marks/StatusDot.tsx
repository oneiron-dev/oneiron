import * as React from 'react'
import { cx } from '../lib/react-utils'

export type StatusDotState = 'live' | 'approved' | 'proposed' | 'idle' | 'waiting'

const DEFAULT_LABEL: Record<StatusDotState, string> = {
  live: 'live',
  approved: 'approved',
  proposed: 'proposed',
  idle: 'idle',
  waiting: 'waits on you',
}

export interface StatusDotProps extends Omit<React.ComponentPropsWithRef<'span'>, 'children'> {
  state: StatusDotState
  /* Accessible name; defaults to the state. */
  label?: string
}

/* A state as a mark, every state the same 8 px dot. `live` is the only red
   mark, solid at full strength, at most one at rest in a view. `approved`
   is filled, `proposed` hollow, `idle` a faint filled dot, `waiting` a ring
   in the first ink: something waits on the person. */
export function StatusDot({ state, label, className, ...props }: StatusDotProps) {
  return (
    <span
      role="img"
      aria-label={label ?? DEFAULT_LABEL[state]}
      className={cx('sl-status-dot', className)}
      data-state={state}
      {...props}
    />
  )
}
