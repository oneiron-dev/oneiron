import * as React from 'react'
import { cx, useSafeId } from '../lib/react-utils'

export interface FileGroupProps extends Omit<React.ComponentPropsWithRef<'section'>, 'title'> {
  /* What the files were born from: a thread's title, or `Not in a thread`. */
  title: React.ReactNode
  /* One verb at the right of the head, a Verb. */
  action?: React.ReactNode
}

/* A group of FileRows under a section head with one verb at its right. */
export function FileGroup({ title, action, className, children, ...props }: FileGroupProps) {
  const headId = useSafeId('sl-file-group')
  return (
    <section aria-labelledby={headId} className={cx('sl-file-group', className)} {...props}>
      <div className="sl-file-group-head">
        <h3 id={headId}>{title}</h3>
        {action}
      </div>
      {children}
    </section>
  )
}
