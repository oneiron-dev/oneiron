import * as React from 'react'
import { Icon } from '../primitives/Icon'
import { ProgressDonut } from '../marks/ProgressDonut'
import type { DonutArc } from '../marks/donut-segments'
import { soundPress } from '../lib/press'
import { cx, mergeRefs, useIsomorphicLayoutEffect } from '../lib/react-utils'

const FlowContext = React.createContext<{ onOpen?: (taskId: string) => void } | null>(null)

export interface TaskFlowProps extends React.ComponentPropsWithRef<'ol'> {
  /* A task was pressed: the caller opens it (the room's tasks, that task
     open). */
  onOpen?: (taskId: string) => void
}

/* Marks each task that ends a row the next task wraps from. */
function markRowEnds(list: HTMLElement) {
  const items = [...list.children] as HTMLElement[]
  items.forEach((item, i) => {
    const next = items[i + 1]
    if (next && next.offsetTop > item.offsetTop + 1) item.setAttribute('data-row-end', '')
    else item.removeAttribute('data-row-end')
  })
}

/* The tasks of one message in the order they feed each other: tone chips
   (TaskFlow.Task) joined by a short line. The row wraps; a row that wraps
   ends without its line. */
function TaskFlowRoot({ ref, onOpen, className, 'aria-label': ariaLabel = 'tasks', ...props }: TaskFlowProps) {
  const ctx = React.useMemo(() => ({ onOpen }), [onOpen])
  const listRef = React.useRef<HTMLOListElement | null>(null)
  useIsomorphicLayoutEffect(() => {
    const list = listRef.current
    if (!list) return
    let alive = true
    const mark = () => alive && markRowEnds(list)
    mark()
    document.fonts?.ready.then(mark)
    if (typeof ResizeObserver === 'undefined') return () => void (alive = false)
    const observer = new ResizeObserver(mark)
    observer.observe(list)
    return () => {
      alive = false
      observer.disconnect()
    }
  })
  return (
    <FlowContext.Provider value={ctx}>
      <ol ref={mergeRefs(ref, listRef)} aria-label={ariaLabel} className={cx('sl-task-flow', className)} {...props} />
    </FlowContext.Provider>
  )
}

export interface TaskFlowTaskProps extends Omit<React.ComponentPropsWithRef<'button'>, 'id'> {
  id: string
  /* Done: a check. Otherwise the progress donut of `arcs`. */
  done?: boolean
  /* The task's steps for its donut, in order. */
  arcs?: readonly DonutArc[]
  /* Something in the task waits on the person: the dot in the donut. */
  needsYou?: boolean
  /* Who has the task: a Glyph at 16 px. */
  who?: React.ReactNode
}

/* One task: its state mark, its name (the children) and the portrait of
   who has it. A chip that opens the task. */
function TaskFlowTask({ id, done = false, arcs = [], needsYou = false, who, className, onClick, type = 'button', children, ...props }: TaskFlowTaskProps) {
  const flow = React.useContext(FlowContext)
  return (
    <li className="sl-task-flow-item">
      <button
        type={type}
        className={cx('sl-task-flow-task', className)}
        data-task-id={id}
        data-state={done ? 'done' : needsYou ? 'waiting' : 'open'}
        onClick={(event) => {
          onClick?.(event)
          if (event.defaultPrevented) return
          soundPress(event)
          flow?.onOpen?.(id)
        }}
        {...props}
      >
        <span className="sl-task-flow-mark">
          {done ? (
            <Icon name="check" size={15} role="img" aria-label="done" aria-hidden={undefined} />
          ) : (
            <ProgressDonut arcs={arcs} needsYou={needsYou} />
          )}
        </span>
        <span className="sl-task-flow-name">{children}</span>
        {who !== undefined ? <span className="sl-task-flow-who">{who}</span> : null}
      </button>
    </li>
  )
}

/* Compound parts: TaskFlow, .Task. */
export const TaskFlow = Object.assign(TaskFlowRoot, { Task: TaskFlowTask })
