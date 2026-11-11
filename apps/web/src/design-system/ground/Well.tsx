import * as React from 'react'
import { cx } from '../lib/react-utils'

export interface WellProps extends React.ComponentPropsWithRef<'div'> {
  /* `sunk` is a well inside the island (one step deeper); `island` is the
     island's own tone, for a well set on a sunk ground. */
  tone?: 'sunk' | 'island'
}

/* A tone step inside the island: the well's ground and the radius, nothing
   else. Padding and layout belong to the caller. */
export function Well({ className, tone = 'sunk', ...props }: WellProps) {
  return <div className={cx('sl-well', className)} data-tone={tone} {...props} />
}
