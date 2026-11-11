import * as React from 'react'
import { cx } from '../lib/react-utils'

export type StatusDotState = 'live' | 'approved' | 'proposed' | 'idle'

const DEFAULT_LABEL: Record<StatusDotState, string> = {
  live: 'live',
  approved: 'approved',
  proposed: 'proposed',
  idle: 'idle',
}

export interface StatusDotProps extends Omit<React.ComponentPropsWithRef<'span'>, 'children'> {
  state: StatusDotState
  /* Accessible name; defaults to the state. */
  label?: string
}

/* A state as a mark, every state the same 8 px dot. `live` is the only red
   mark, solid at full strength, at most one at rest in a view. `approved`
   is filled, `proposed` hollow, `idle` a faint filled dot. */
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
