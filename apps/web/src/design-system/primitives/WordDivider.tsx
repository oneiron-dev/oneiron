import * as React from 'react'
import { cx } from '../lib/react-utils'

export interface WordDividerProps extends React.ComponentPropsWithRef<'p'> {}

/* A hairline with one quiet word in its middle, between two ways of doing
   the same thing: `or` by default. The word is read; the lines are not. */
export function WordDivider({ className, children = 'or', ...props }: WordDividerProps) {
  return (
    <p className={cx('sl-word-divider', className)} {...props}>
      <span className="sl-word-divider-word">{children}</span>
    </p>
  )
}
