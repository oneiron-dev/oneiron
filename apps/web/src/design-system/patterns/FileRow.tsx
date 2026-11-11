import * as React from 'react'
import { Figure } from '../primitives/Figure'
import { Icon, type IconName } from '../primitives/Icon'
import { Seal, type SealAuthor } from '../marks/Seal'
import { soundPress } from '../lib/press'
import { cx } from '../lib/react-utils'

/* Rows inside FileRow.List take the list's columns. */
const InList = React.createContext(false)

export interface FileRowProps extends Omit<React.ComponentPropsWithRef<'button'>, 'name'> {
  /* The file's kind, as its icon. */
  kind?: IconName
  /* The kind in words, for the accessible name: `sheet`, `note`. */
  kindLabel?: string
  /* A mark in place of the kind's icon: the portrait of a pinned
     message's writer. */
  mark?: React.ReactNode
  name: React.ReactNode
  /* Who made it: a person, an agent or the system, as a seal. */
  maker?: SealAuthor
  /* Who made it as a portrait instead (a Glyph at 18 px), in a list. */
  portrait?: React.ReactNode
  author: React.ReactNode
  /* When it last changed, as a figure. */
  time?: string
  /* Pinned in the room: a pin mark after the name, in a list. */
  pinned?: boolean
  /* Pressing the row: the caller opens the file beside the list. */
  onOpen?: () => void
}

/* One file: its kind, its name, who made it, and a time. In a
   FileRow.List: the kind, the name, a pin mark when pinned, the maker's
   portrait and name, and the time at the right, on a 40 px row. */
function FileRowRoot({
  kind,
  kindLabel,
  mark,
  name,
  maker,
  portrait,
  author,
  time,
  pinned = false,
  onOpen,
  className,
  type = 'button',
  onClick,
  ...props
}: FileRowProps) {
  const inList = React.useContext(InList)
  const symbol =
    mark !== undefined ? (
      <span className="sl-file-mark">{mark}</span>
    ) : kind ? (
      <Icon name={kind} aria-label={kindLabel} role={kindLabel ? 'img' : undefined} aria-hidden={kindLabel ? undefined : true} />
    ) : (
      <span />
    )
  const who = (
    <span className="sl-file-author">
      {portrait !== undefined ? portrait : maker ? <Seal by={maker} /> : null}
      <span>{author}</span>
    </span>
  )
  return (
    <button
      type={type}
      className={cx('sl-file-row', className)}
      data-layout={inList ? 'list' : undefined}
      onClick={(event) => {
        onClick?.(event)
        if (event.defaultPrevented || !onOpen) return
        soundPress(event)
        onOpen()
      }}
      {...props}
    >
      {symbol}
      <span className="sl-file-name">{name}</span>
      {inList ? (
        pinned ? (
          <span className="sl-file-pin" role="img" aria-label="pinned in this room">
            <Icon name="pin" size={14} />
          </span>
        ) : (
          <span />
        )
      ) : null}
      {who}
      {time ? <Figure className="sl-file-time">{time}</Figure> : <span />}
    </button>
  )
}

export interface FileRowListProps extends React.ComponentPropsWithRef<'div'> {
  /* The head over the who column: `made by`, or `pinned by`. */
  whoHead?: React.ReactNode
  /* The head over the time column: `changed`. */
  timeHead?: React.ReactNode
}

/* A list of files with one head row naming the who and the time columns.
   As wide as the messages column and its portrait gutter. */
function FileRowList({ whoHead = 'made by', timeHead = 'changed', className, children, ...props }: FileRowListProps) {
  return (
    <div className={cx('sl-file-list', className)} {...props}>
      <div className="sl-file-list-head" aria-hidden="true">
        <span />
        <span />
        <span />
        <span>{whoHead}</span>
        <span className="sl-file-list-time">{timeHead}</span>
      </div>
      <InList.Provider value={true}>{children}</InList.Provider>
    </div>
  )
}

/* Compound parts: FileRow, .List. */
export const FileRow = Object.assign(FileRowRoot, { List: FileRowList })
