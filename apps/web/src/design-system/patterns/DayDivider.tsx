import * as React from 'react'
import { cx } from '../lib/react-utils'

export interface DayDividerProps extends React.ComponentPropsWithRef<'div'> {}

/* A hairline across the list with the day centred on it. */
export function DayDivider({ className, children, ...props }: DayDividerProps) {
  return (
    <div className={cx('sl-day-divider', className)} {...props}>
      <span>{children}</span>
    </div>
  )
}
