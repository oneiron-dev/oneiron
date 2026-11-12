import * as React from 'react'
import { cx } from '../lib/react-utils'

export type SealAuthor = 'person' | 'agent' | 'system'

const DEFAULT_LABEL: Record<SealAuthor, string> = {
  person: 'written by a person',
  agent: 'written by an agent',
  system: 'written by the system',
}

export interface SealProps extends Omit<React.ComponentPropsWithRef<'span'>, 'children'> {
  by: SealAuthor
  size?: 12 | 16
  label?: string
}

/* Who wrote a record: a filled square for a person, an outlined square for
   an agent, a dashed square for the system. */
export function Seal({ by, size = 12, label, className, ...props }: SealProps) {
  return (
    <span
      role="img"
      aria-label={label ?? DEFAULT_LABEL[by]}
      className={cx('sl-seal', className)}
      data-by={by}
      data-size={size}
      {...props}
    />
  )
}
