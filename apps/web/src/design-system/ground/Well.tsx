import * as React from 'react'
import { cx } from '../lib/react-utils'

export interface WellProps extends React.ComponentPropsWithRef<'div'> {
  /* `well` is a recess, one step darker than the ground it is carved in;
     `island` is the island's own tone, for a well set on another tone. */
  tone?: 'well' | 'island'
}

/* A recess: the well's tone and the radius, nothing else. No ring, no
   shadow, no outline. Padding and layout belong to the caller. */
export function Well({ className, tone = 'well', ...props }: WellProps) {
  return <div className={cx('sl-well', className)} data-tone={tone} {...props} />
}
