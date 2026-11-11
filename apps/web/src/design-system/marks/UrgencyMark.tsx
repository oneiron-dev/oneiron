import * as React from 'react'
import { cx } from '../lib/react-utils'

export interface UrgencyMarkProps extends React.ComponentPropsWithRef<'span'> {
  /* Accessible name when no reason follows the mark. */
  label?: string
}

/* The small triangle of an urgent item. The reason, if any, is the
   caller's text (children) and follows the mark. */
export function UrgencyMark({ label = 'urgent', className, children, ...props }: UrgencyMarkProps) {
  const reason = children !== undefined && children !== null && children !== false
  return (
    <span className={cx('sl-urgency', className)} {...props}>
      <span
        className="sl-urgency-mark"
        role={reason ? undefined : 'img'}
        aria-label={reason ? undefined : label}
        aria-hidden={reason ? true : undefined}
      />
      {reason ? children : null}
    </span>
  )
}
