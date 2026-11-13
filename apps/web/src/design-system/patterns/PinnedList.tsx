import * as React from 'react'
import { cx } from '../lib/react-utils'
import { FileRow } from './FileRow'

/* What the list says about its pins, once, at its top. */
export const PINNED_LIST_NOTE = 'Everyone in this room sees these, and the agents working here keep them in view.'

export interface PinnedListProps extends React.ComponentPropsWithRef<'section'> {
  /* The sentence at the top. */
  note?: React.ReactNode
}

/* The pins of a room as one list: the sentence, a head row (`pinned by`),
   then one FileRow per pin: its kind icon, or the portrait of a pinned
   message's writer (`mark`); its name or first words; who pinned it and
   when. The caller's onOpen on each row opens the thing, or goes to the
   message. */
export function PinnedList({ note = PINNED_LIST_NOTE, className, children, 'aria-label': ariaLabel = 'pinned in this room', ...props }: PinnedListProps) {
  return (
    <section aria-label={ariaLabel} className={cx('sl-pinned-list', className)} {...props}>
      <p className="sl-pinned-list-note">{note}</p>
      <FileRow.List whoHead="pinned by" timeHead={null}>
        {children}
      </FileRow.List>
    </section>
  )
}
