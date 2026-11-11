import * as React from 'react'
import { Figure } from '../primitives/Figure'
import { Icon, type IconName } from '../primitives/Icon'
import { Seal, type SealAuthor } from '../marks/Seal'
import { cx } from '../lib/react-utils'

export interface FileRowProps extends Omit<React.ComponentPropsWithRef<'button'>, 'name'> {
  /* The file's kind, as its icon. */
  kind: IconName
  /* The kind in words, for the accessible name: `sheet`, `note`. */
  kindLabel?: string
  name: React.ReactNode
  /* Who made it: a person, an agent or the system. */
  maker: SealAuthor
  author: React.ReactNode
  /* When it last changed, as a figure. */
  time?: string
}

/* One file: its kind, its name, the maker's seal and name, and a time. */
export function FileRow({ kind, kindLabel, name, maker, author, time, className, type = 'button', ...props }: FileRowProps) {
  return (
    <button type={type} className={cx('sl-file-row', className)} {...props}>
      <Icon name={kind} aria-label={kindLabel} role={kindLabel ? 'img' : undefined} aria-hidden={kindLabel ? undefined : true} />
      <span className="sl-file-name">{name}</span>
      <span className="sl-file-author">
        <Seal by={maker} />
        <span>{author}</span>
      </span>
      {time ? <Figure className="sl-file-time">{time}</Figure> : <span />}
    </button>
  )
}
