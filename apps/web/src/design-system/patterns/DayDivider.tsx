import * as React from 'react'
import { cx } from '../lib/react-utils'

export interface DayDividerProps extends React.ComponentPropsWithRef<'div'> {}

/* The day a run of messages was written, at the left edge, with a
   hairline after it to the end of the list. */
export function DayDivider({ className, children, ...props }: DayDividerProps) {
  return (
    <div className={cx('sl-day-divider', className)} {...props}>
      <span>{children}</span>
    </div>
  )
}
