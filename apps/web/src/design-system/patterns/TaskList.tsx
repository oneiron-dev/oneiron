import * as React from 'react'
import { Figure } from '../primitives/Figure'
import { Icon } from '../primitives/Icon'
import { Unfold } from '../primitives/Unfold'
import { cx, useControllableState } from '../lib/react-utils'
import { TASK_DONE_FOLD_AFTER, TASK_GROUPS, groupTasks } from './task-group'
import { TaskListContext, TaskRow, type TaskRowProps } from './TaskRow'

export interface TaskListProps extends React.ComponentPropsWithRef<'div'> {
  /* The open row's id; one row is open at a time, or none. */
  openId?: string | null
  defaultOpenId?: string | null
  onOpenChange?: (id: string | null) => void
  /* Rows sit under three quiet heads: needs you, working, done. */
  grouped?: boolean
}

/* TaskRow elements among the children, in order, through fragments. */
function taskRows(children: React.ReactNode, out: React.ReactElement<TaskRowProps>[] = []) {
  React.Children.forEach(children, (child) => {
    if (!React.isValidElement(child)) return
    if (child.type === TaskRow) out.push(child as React.ReactElement<TaskRowProps>)
    else if (child.type === React.Fragment) taskRows((child.props as { children?: React.ReactNode }).children, out)
  })
  return out
}

/* The tasks under one message: TaskRow children, one open at a time.
   `grouped` sorts them under needs you, working and done (in that order,
   each head only when it has rows); a done group of more than three folds
   to its count. */
export function TaskList({
  openId: openIdProp,
  defaultOpenId = null,
  onOpenChange,
  grouped = false,
  className,
  children,
  'aria-label': ariaLabel = 'tasks',
  ...props
}: TaskListProps) {
  const [openId, setOpenId] = useControllableState<string | null>(openIdProp, defaultOpenId, onOpenChange)
  const ctx = React.useMemo(() => ({ openId, setOpenId }), [openId, setOpenId])

  let body: React.ReactNode
  if (!grouped) {
    body = (
      <div role="list" className="sl-task-list-rows">
        {children}
      </div>
    )
  } else {
    const groups = groupTasks(
      taskRows(children).map((element) => ({
        id: element.props.id,
        arcs: element.props.arcs,
        needsYou: element.props.needsYou,
        element,
      })),
    )
    body = TASK_GROUPS.filter(({ group }) => groups[group].length > 0).map(({ group, head }) => {
      const rows = groups[group].map((task) => <React.Fragment key={task.id}>{task.element}</React.Fragment>)
      if (group === 'done' && rows.length > TASK_DONE_FOLD_AFTER) {
        return (
          <Unfold key={group} role="group" aria-label={head} className="sl-task-group" data-group={group}>
            <Unfold.Trigger className="sl-task-group-head" data-folds="">
              <Icon name="chevron" size={12} className="sl-task-group-chevron" />
              {head}
              <Figure>{rows.length}</Figure>
            </Unfold.Trigger>
            <Unfold.Content>
              <div role="list" className="sl-task-list-rows">
                {rows}
              </div>
            </Unfold.Content>
          </Unfold>
        )
      }
      return (
        <div key={group} role="group" aria-label={head} className="sl-task-group" data-group={group}>
          <div className="sl-task-group-head" aria-hidden="true">
            {head}
          </div>
          <div role="list" className="sl-task-list-rows">
            {rows}
          </div>
        </div>
      )
    })
  }

  return (
    <TaskListContext.Provider value={ctx}>
      <div
        role="group"
        aria-label={ariaLabel}
        className={cx('sl-task-list', className)}
        data-grouped={grouped ? '' : undefined}
        {...props}
      >
        {body}
      </div>
    </TaskListContext.Provider>
  )
}
