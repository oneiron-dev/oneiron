import * as React from 'react'
import { Figure } from '../primitives/Figure'
import { soundPress } from '../lib/press'
import { cx, useSafeId } from '../lib/react-utils'

const OutlineContext = React.createContext<{ onOpen?: (id: string) => void } | null>(null)

export interface RoomOutlineProps extends React.ComponentPropsWithRef<'nav'> {
  /* A row was pressed: the caller opens its thing, its tasks or its
     thread, or goes to the message. */
  onOpen?: (id: string) => void
}

/* A map of one room for a list pane: groups under quiet labels (pinned,
   tasks, threads), one row per thing. Children: RoomOutline.Group, each
   holding RoomOutline.Row. */
function RoomOutlineRoot({ onOpen, className, 'aria-label': ariaLabel = 'outline of this room', ...props }: RoomOutlineProps) {
  const ctx = React.useMemo(() => ({ onOpen }), [onOpen])
  return (
    <OutlineContext.Provider value={ctx}>
      <nav aria-label={ariaLabel} className={cx('sl-room-outline', className)} {...props} />
    </OutlineContext.Provider>
  )
}

export interface RoomOutlineGroupProps extends React.ComponentPropsWithRef<'div'> {
  /* The group's quiet label: `pinned`, `tasks`, `threads`. */
  label: string
}

/* One group: its label at the figure size in the quiet ink, then its rows. */
function RoomOutlineGroup({ label, className, children, ...props }: RoomOutlineGroupProps) {
  const labelId = useSafeId('sl-room-outline-label')
  return (
    <div role="group" aria-labelledby={labelId} className={cx('sl-room-outline-group', className)} {...props}>
      <p id={labelId} className="sl-room-outline-label">
        {label}
      </p>
      {children}
    </div>
  )
}

export interface RoomOutlineRowProps extends Omit<React.ComponentPropsWithRef<'button'>, 'id'> {
  /* What onOpen receives. */
  id: string
  /* The thing's mark: its kind as an Icon, a ProgressDonut for tasks (its
     tooltip off), the thread icon for a thread. */
  mark: React.ReactNode
  /* Who wrote it or holds it, at weight 600 before the words. */
  who?: React.ReactNode
  /* When, as a figure at the right. */
  time?: string
}

/* One thing: its mark, who, its first words (the children; past the row's
   width they end in an ellipsis), and the time. A button that opens it. */
function RoomOutlineRow({ id, mark, who, time, className, onClick, type = 'button', children, ...props }: RoomOutlineRowProps) {
  const outline = React.useContext(OutlineContext)
  return (
    <button
      type={type}
      className={cx('sl-room-outline-row', className)}
      data-outline-id={id}
      onClick={(event) => {
        onClick?.(event)
        if (event.defaultPrevented) return
        soundPress(event)
        outline?.onOpen?.(id)
      }}
      {...props}
    >
      <span className="sl-room-outline-mark">{mark}</span>
      <span className="sl-room-outline-words">
        {who !== undefined ? (
          <>
            <span className="sl-room-outline-who">{who}</span>{' '}
          </>
        ) : null}
        {children}
      </span>
      {time ? <Figure className="sl-room-outline-time">{time}</Figure> : null}
    </button>
  )
}

/* Compound parts: RoomOutline, .Group, .Row. */
export const RoomOutline = Object.assign(RoomOutlineRoot, { Group: RoomOutlineGroup, Row: RoomOutlineRow })
