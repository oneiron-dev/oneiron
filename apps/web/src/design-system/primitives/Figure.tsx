import * as React from 'react'
import { cx } from '../lib/react-utils'

interface FigureOwnProps {
  /* `figure` is the 12.5 px figure; `badge` the 11 px badge figure. */
  size?: 'figure' | 'badge'
}

export type FigureProps =
  | (FigureOwnProps & { as?: 'span' } & React.ComponentPropsWithRef<'span'>)
  | (FigureOwnProps & { as: 'time' } & React.ComponentPropsWithRef<'time'>)

/* A figure: counts, times, durations, ids. Mono, tabular, never a word. */
export function Figure(props: FigureProps) {
  const { as = 'span', size = 'figure', className, ...rest } = props
  const Tag = as as 'span'
  return (
    <Tag
      className={cx('sl-figure', className)}
      data-size={size}
      {...(rest as React.ComponentPropsWithRef<'span'>)}
    />
  )
}
