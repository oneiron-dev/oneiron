import * as React from 'react'
import { ProgressDonut } from '../marks/ProgressDonut'
import type { DonutArc } from '../marks/donut-segments'
import { Unfold } from '../primitives/Unfold'
import { Verb } from '../primitives/Verb'
import { cx, useControllableState, useIsomorphicLayoutEffect } from '../lib/react-utils'
import { taskCountWords } from './task-group'
import { Composer, type ComposerProps } from './Composer'

/* ── the list's open row ───────────────────────────────────────────────── */

export interface TaskListContextValue {
  openId: string | null
  setOpenId: (id: string | null) => void
}

/* Provided by TaskList: which of its rows is open. */
export const TaskListContext = React.createContext<TaskListContextValue | null>(null)

/* ── a row ──────────────────────────────────────────────────────────────── */

export interface TaskRowProps extends Omit<React.ComponentPropsWithRef<'div'>, 'id'> {
  id: string
  /* The task's steps, in order, for its donut. */
  arcs: readonly DonutArc[]
  /* The task waits on the person: a dot in the donut. */
  needsYou?: boolean
  /* What the task is: one serif line. */
  name: React.ReactNode
  /* Who has it: at the right, in a quieter ink. */
  who?: React.ReactNode
  /* Outside a TaskList the row holds its own open state; inside one, the
     list does (one open row at a time). */
  open?: boolean
  defaultOpen?: boolean
  onOpenChange?: (open: boolean) => void
}

/* One task under a message: its donut, what it is, who has it. A click
   unfolds its children (a TaskRow.Body) in place under the row; Escape
   inside folds it and puts focus back on the row. */
function TaskRowRoot({
  id,
  arcs,
  needsYou = false,
  name,
  who,
  open: openProp,
  defaultOpen = false,
  onOpenChange,
  className,
  onKeyDown,
  children,
  ...props
}: TaskRowProps) {
  const list = React.useContext(TaskListContext)
  const [ownOpen, setOwnOpen] = useControllableState(openProp, defaultOpen, list ? undefined : onOpenChange)
  const open = list ? list.openId === id : ownOpen
  const triggerRef = React.useRef<HTMLButtonElement | null>(null)

  const setOpen = (next: boolean) => {
    if (list) list.setOpenId(next ? id : null)
    else setOwnOpen(next)
  }

  /* Inside a list, the row also closes when another row opens: report
     every change of the row's own state from here. */
  const reported = React.useRef(open)
  const onOpenChangeRef = React.useRef(onOpenChange)
  useIsomorphicLayoutEffect(() => {
    onOpenChangeRef.current = onOpenChange
  })
  React.useEffect(() => {
    if (!list || reported.current === open) return
    reported.current = open
    onOpenChangeRef.current?.(open)
  }, [list, open])

  return (
    <Unfold
      open={open}
      onOpenChange={setOpen}
      role="listitem"
      className={cx('sl-task', className)}
      data-task-id={id}
      onKeyDown={(event: React.KeyboardEvent<HTMLDivElement>) => {
        onKeyDown?.(event)
        if (event.defaultPrevented || event.key !== 'Escape' || !open) return
        event.preventDefault()
        setOpen(false)
        triggerRef.current?.focus()
      }}
      {...props}
    >
      <Unfold.Trigger ref={triggerRef} className="sl-task-row">
        <ProgressDonut arcs={arcs} needsYou={needsYou} />
        <span className="sl-task-name">{name}</span>
        {who !== undefined ? <span className="sl-task-who">{who}</span> : null}
      </Unfold.Trigger>
      <Unfold.Content className="sl-task-fold">{children}</Unfold.Content>
    </Unfold>
  )
}

/* ── the body and its parts ─────────────────────────────────────────────── */

export interface TaskRowBodyProps extends React.ComponentPropsWithRef<'div'> {}

/* What unfolds under the row, with a hairline at its left: the task's last
   lines, what it asks (a question and a NeedsYou.Picks line inside a
   NeedsYou.Answer), the small write box, its own tasks. */
function TaskRowBody({ className, ...props }: TaskRowBodyProps) {
  return <div className={cx('sl-task-body', className)} {...props} />
}

export interface TaskRowLastProps extends React.ComponentPropsWithRef<'div'> {}

/* The task's last lines. */
function TaskRowLast({ className, ...props }: TaskRowLastProps) {
  return <div className={cx('sl-task-last', className)} {...props} />
}

export interface TaskRowQuestionProps extends React.ComponentPropsWithRef<'p'> {}

/* What the task asks the person, one serif line above its picks. */
function TaskRowQuestion({ className, ...props }: TaskRowQuestionProps) {
  return <p className={cx('sl-task-question', className)} {...props} />
}

export interface TaskRowWriteProps extends Omit<ComposerProps, 'size'> {}

/* One line to write to the task: the small write box. Enter sends; Escape
   leaves the field and folds the row. */
function TaskRowWrite({ placeholder = 'Write to this task', className, ...props }: TaskRowWriteProps) {
  return <Composer size="small" className={cx('sl-task-write', className)} placeholder={placeholder} {...props} />
}

export interface TaskRowOwnProps extends Omit<React.ComponentPropsWithRef<'div'>, 'children'> {
  /* The task's own tasks, one entry each, for the small donut. */
  arcs: readonly DonutArc[]
  needsYou?: boolean
  /* Shows `open as a room`. */
  onOpenRoom?: () => void
}

/* A task that has tasks of its own: a small donut, the count in words, and
   `open as a room`. */
function TaskRowOwn({ arcs, needsYou = false, onOpenRoom, className, ...props }: TaskRowOwnProps) {
  return (
    <div className={cx('sl-task-own', className)} {...props}>
      <ProgressDonut arcs={arcs} needsYou={needsYou} size={14} />
      <span className="sl-task-own-count">{taskCountWords(arcs.length)} of its own</span>
      {onOpenRoom ? (
        <Verb className="sl-task-own-open" onClick={onOpenRoom}>
          open as a room
        </Verb>
      ) : null}
    </div>
  )
}

/* Compound parts: TaskRow, .Body, .Last, .Question, .Write, .Own. */
export const TaskRow = Object.assign(TaskRowRoot, {
  Body: TaskRowBody,
  Last: TaskRowLast,
  Question: TaskRowQuestion,
  Write: TaskRowWrite,
  Own: TaskRowOwn,
})
