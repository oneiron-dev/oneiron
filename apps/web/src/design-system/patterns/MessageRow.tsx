import * as React from 'react'
import { Figure } from '../primitives/Figure'
import { Icon, type IconName } from '../primitives/Icon'
import { IconAction } from '../primitives/IconAction'
import { Unfold } from '../primitives/Unfold'
import { ProgressDonut } from '../marks/ProgressDonut'
import type { DonutArc } from '../marks/donut-segments'
import { soundPress } from '../lib/press'
import { cx } from '../lib/react-utils'
import { taskCountWords } from './task-group'

export interface MessageRowProps extends React.ComponentPropsWithRef<'article'> {
  /* Who wrote it: a Glyph. */
  author: React.ReactNode
  name: React.ReactNode
  /* When, as a figure at the end of the name line: `31 min ago`, `14:02`. */
  time?: string
  /* Machine-readable time for the figure. */
  dateTime?: string
  /* Not yet accepted by a member: the text prints one ink step fainter. */
  provisional?: boolean
}

/* One message: the author's mark, the name line with its time, then the
   text and only what the row lacks (an attachment, a fold, the thread
   line, reactions). It carries no state caption and no presence mark. */
function MessageRowRoot({ author, name, time, dateTime, provisional = false, className, children, ...props }: MessageRowProps) {
  return (
    <article className={cx('sl-message-row', className)} data-provisional={provisional ? '' : undefined} {...props}>
      <span className="sl-message-author">{author}</span>
      <div className="sl-message-body">
        <div className="sl-message-name-line">
          <span className="sl-message-name">{name}</span>
          {time ? (
            <Figure as="time" dateTime={dateTime}>
              {time}
            </Figure>
          ) : null}
        </div>
        {children}
      </div>
    </article>
  )
}

export interface MessageRowTextProps extends React.ComponentPropsWithRef<'p'> {}

function MessageRowText({ className, ...props }: MessageRowTextProps) {
  return <p className={cx('sl-message-text', className)} {...props} />
}

export interface MessageRowAttachmentsProps extends React.ComponentPropsWithRef<'div'> {}

/* The row's attachments, side by side. */
function MessageRowAttachments({ className, ...props }: MessageRowAttachmentsProps) {
  return <div className={cx('sl-message-attachments', className)} {...props} />
}

export interface MessageRowAttachmentProps extends React.ComponentPropsWithRef<'button'> {
  /* The file's kind. */
  icon: IconName
}

/* One attached file: its kind and its name, on a sunk tone. */
function MessageRowAttachment({ icon, className, type = 'button', children, ...props }: MessageRowAttachmentProps) {
  return (
    <button type={type} className={cx('sl-message-attachment', className)} {...props}>
      <Icon name={icon} />
      <span className="sl-message-attachment-name">{children}</span>
    </button>
  )
}

export interface MessageRowFoldProps extends Omit<React.ComponentPropsWithRef<'div'>, 'onChange'> {
  /* The folded line: a receipt, or where an answer came from. */
  summary: React.ReactNode
  open?: boolean
  defaultOpen?: boolean
  onOpenChange?: (open: boolean) => void
}

/* One folded line under the row; it unfolds its detail in place. */
function MessageRowFold({ summary, open, defaultOpen, onOpenChange, className, children, ...props }: MessageRowFoldProps) {
  return (
    <Unfold open={open} defaultOpen={defaultOpen} onOpenChange={onOpenChange} className={cx('sl-message-fold', className)} {...props}>
      <Unfold.Trigger className="sl-fold-line">
        <Icon name="chevron" size={12} className="sl-fold-chevron" />
        <span>{summary}</span>
      </Unfold.Trigger>
      <Unfold.Content>
        <div className="sl-message-fold-detail">{children}</div>
      </Unfold.Content>
    </Unfold>
  )
}

export interface MessageRowThreadLineProps extends React.ComponentPropsWithRef<'button'> {
  replies: number
  /* When the last reply came, as a figure. */
  lastReply?: string
  /* The marks of who took part. */
  participants?: React.ReactNode
  unread?: boolean
}

/* The line under a parent message: who took part, the reply count in
   words (`2 replies`, serif) and the last reply's time as a figure. Hover
   and focus swap the time for `view thread`. */
function MessageRowThreadLine({
  replies,
  lastReply,
  participants,
  unread = false,
  className,
  type = 'button',
  'aria-label': ariaLabel,
  ...props
}: MessageRowThreadLineProps) {
  const count = `${replies} ${replies === 1 ? 'reply' : 'replies'}`
  return (
    <button
      type={type}
      className={cx('sl-thread-line', className)}
      aria-label={ariaLabel ?? `${count}${unread ? ', unread' : ''}, view thread`}
      {...props}
    >
      {participants ? <span className="sl-thread-line-people">{participants}</span> : null}
      {unread ? <span className="sl-thread-line-unread" aria-hidden="true" /> : null}
      <span className="sl-thread-line-count">{count}</span>
      {lastReply ? <Figure className="sl-thread-line-last">{lastReply}</Figure> : null}
      <span className="sl-thread-line-view">view thread</span>
    </button>
  )
}

export interface MessageRowTaskLineProps extends React.ComponentPropsWithRef<'button'> {
  /* One entry per task the work was split into, for the donut. */
  arcs: readonly DonutArc[]
  /* A task waits on the person: a dot in the donut. */
  needsYou?: boolean
  /* Who has the work. */
  who?: React.ReactNode
  /* How many tasks, said in words after the name: `3 tasks`. */
  count?: number
  /* Opens the task list. */
  onOpen?: () => void
}

/* The line under a message whose work was split into tasks: the donut,
   who has it, how many tasks. The whole line is one button that opens the
   list. A message shows this line or a thread line, never both. */
function MessageRowTaskLine({
  arcs,
  needsYou = false,
  who,
  count,
  onOpen,
  className,
  type = 'button',
  onClick,
  ...props
}: MessageRowTaskLineProps) {
  return (
    <button
      type={type}
      className={cx('sl-task-line', className)}
      onClick={(event) => {
        onClick?.(event)
        if (!event.defaultPrevented) onOpen?.()
      }}
      {...props}
    >
      <ProgressDonut arcs={arcs} needsYou={needsYou} />
      {who !== undefined ? <span className="sl-task-line-who">{who}</span> : null}
      {count !== undefined ? <span className="sl-task-line-count">{taskCountWords(count)}</span> : null}
    </button>
  )
}

export interface MessageRowReactionsProps extends React.ComponentPropsWithRef<'div'> {
  /* Shows the add icon after the reactions. */
  onAdd?: (event: React.MouseEvent<HTMLButtonElement>) => void
  addLabel?: string
}

/* The reactions under a row, then an add icon that shows on the row's hover. */
function MessageRowReactions({ onAdd, addLabel = 'Add a reaction', className, children, ...props }: MessageRowReactionsProps) {
  return (
    <div className={cx('sl-reactions', className)} {...props}>
      {children}
      {onAdd ? (
        <IconAction label={addLabel} size="sm" className="sl-reaction-add" onClick={onAdd}>
          <Icon name="smile" />
        </IconAction>
      ) : null}
    </div>
  )
}

export interface MessageRowReactionProps extends React.ComponentPropsWithRef<'button'> {
  emoji: string
  count: number
  /* Yours among them: the count prints in the brighter ink. */
  pressed?: boolean
  /* Who reacted, for the hover title. */
  who?: string
}

/* One reaction: the emoji and its count as a figure. */
function MessageRowReaction({ emoji, count, pressed = false, who, className, type = 'button', onClick, ...props }: MessageRowReactionProps) {
  return (
    <button
      type={type}
      className={cx('sl-reaction', className)}
      aria-pressed={pressed}
      aria-label={`${emoji} ${count}${who ? `, ${who}` : ''}`}
      title={who}
      onClick={(event) => {
        onClick?.(event)
        soundPress(event)
      }}
      {...props}
    >
      <span className="sl-reaction-emoji" aria-hidden="true">
        {emoji}
      </span>
      <Figure aria-hidden="true">{count}</Figure>
    </button>
  )
}

/* Compound parts: MessageRow, .Text, .Attachments, .Attachment, .Fold,
   .ThreadLine, .TaskLine, .Reactions, .Reaction. */
export const MessageRow = Object.assign(MessageRowRoot, {
  Text: MessageRowText,
  Attachments: MessageRowAttachments,
  Attachment: MessageRowAttachment,
  Fold: MessageRowFold,
  ThreadLine: MessageRowThreadLine,
  TaskLine: MessageRowTaskLine,
  Reactions: MessageRowReactions,
  Reaction: MessageRowReaction,
})
