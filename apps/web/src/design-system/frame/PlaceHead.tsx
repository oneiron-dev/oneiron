import * as React from 'react'
import { cx } from '../lib/react-utils'

export interface PlaceHeadProps extends Omit<React.ComponentPropsWithRef<'header'>, 'title'> {
  /* A symbol before the title: an Icon, or a Glyph in its line form. */
  icon?: React.ReactNode
  /* The place's name at the place size, the largest words on the screen.
     It never wraps. */
  title: React.ReactNode
  /* One quiet line under the title: where the place comes from (`a task
     of` and a Verb that goes back). */
  origin?: React.ReactNode
  /* The title's heading level: 1 for the place on screen. */
  level?: 1 | 2
}

/* The head line of the work area: the symbol, the title, the origin line
   under it, and at the right the children (the crew, actions). When the
   head is narrower than 520 px the right slot shrinks first: its parts drop
   whole, the first child first, so the last (the most used action) stays
   longest. Only once the slot is gone does the title lose letters, and
   then to an ellipsis. */
export function PlaceHead({ icon, title, origin, level = 1, className, children, ...props }: PlaceHeadProps) {
  const Heading = level === 1 ? 'h1' : 'h2'
  const parts = React.Children.toArray(children)
  return (
    <header className={cx('sl-place-head', className)} {...props}>
      <div className="sl-place-head-main">
        <div className="sl-place-head-line">
          {icon !== undefined ? (
            <span className="sl-place-head-icon" aria-hidden="true">
              {icon}
            </span>
          ) : null}
          <Heading className="sl-place-head-title">{title}</Heading>
        </div>
        {origin !== undefined ? <p className="sl-place-head-origin">{origin}</p> : null}
      </div>
      {parts.length ? (
        <div className="sl-place-head-end">
          {/* Laid out from the right edge, last child first: a part that
              no longer fits wraps onto a hidden line, first child first,
              while focus still moves in the written order. */}
          {parts.map((part, i) => (
            <span key={i} className="sl-place-head-part" style={{ order: parts.length - i }}>
              {part}
            </span>
          ))}
        </div>
      ) : null}
    </header>
  )
}
