import * as React from 'react'
import { Figure } from '../primitives/Figure'
import { Icon } from '../primitives/Icon'
import { IconAction } from '../primitives/IconAction'
import { Tabs, type TabsPinProps } from '../primitives/Tabs'
import { Tooltip } from '../overlays/Tooltip'
import { ProgressDonut } from '../marks/ProgressDonut'
import type { DonutArc } from '../marks/donut-segments'
import { soundPress } from '../lib/press'
import { cx } from '../lib/react-utils'
import { PlaceHead, type PlaceHeadProps } from './PlaceHead'

/* What a room carries on its head line. `head`: talk, files, then the
   room's pins and the add action. `tab`: three fixed tabs, talk, files and
   pinned. `none`: no tabs; the outline action at the right. */
export type RoomPins = 'head' | 'tab' | 'none'

/* The values of a room's fixed views. */
export const ROOM_VIEWS = { talk: 'talk', files: 'files', pinned: 'pinned' } as const

export interface RoomHeadProps extends Omit<PlaceHeadProps, 'tabs' | 'children'> {
  pins?: RoomPins
  /* How many files the room has: the figure on the files tab. */
  filesCount?: number
  /* How many pins the room has, on the pinned tab; by default the count of
     the Tabs.Pin children. */
  pinnedCount?: number
  /* The room's tasks, one arc each, for the donut at the right. */
  tasks?: readonly DonutArc[]
  /* Something in the room's tasks waits on the person. */
  tasksNeedYou?: boolean
  onOpenTasks?: () => void
  /* The room's crew: a CrewStack. */
  crew?: React.ReactNode
  /* `none`: the outline action opens the outline of the room. */
  onOpenOutline?: () => void
  /* The outline is open: the action shows as pressed. */
  outlineOpen?: boolean
  /* `head`: the add action at the end of the pins. */
  onAddPin?: () => void
  /* The room's pins: Tabs.Pin elements, in order. */
  children?: React.ReactNode
  /* The id of the region that shows the room's view, when no Tabs.Panel
     draws it: the fixed tabs and the folded pins name it. */
  controls?: string
}

/* The head line of a room: its name (PlaceHead), the tabs on the same
   line, and at the right the room's tasks (a donut and their count) and
   its crew. With tabs it sits inside a Tabs whose value is the view on
   screen. Narrower than 520 px the crew hides before the name loses a
   letter; the pins fold into one tab when the line is too narrow for them. */
export function RoomHead({
  pins = 'head',
  filesCount,
  pinnedCount,
  tasks,
  tasksNeedYou = false,
  onOpenTasks,
  crew,
  onOpenOutline,
  outlineOpen,
  onAddPin,
  icon,
  controls,
  className,
  children,
  ...props
}: RoomHeadProps) {
  const pinParts = React.Children.toArray(children).filter(
    (c): c is React.ReactElement<TabsPinProps> => React.isValidElement(c) && c.type === Tabs.Pin,
  )
  let tabs: React.ReactNode
  if (pins === 'head') {
    tabs = (
      <Tabs.List foldValue={ROOM_VIEWS.pinned} foldControls={controls} aria-label="views of this room" className="sl-room-head-tabs">
        <Tabs.Tab value={ROOM_VIEWS.talk} controls={controls}>
          talk
        </Tabs.Tab>
        <Tabs.Tab value={ROOM_VIEWS.files} count={filesCount} controls={controls}>
          files
        </Tabs.Tab>
        <Tabs.Divider />
        {pinParts}
        <Tabs.Add onClick={onAddPin} />
      </Tabs.List>
    )
  } else if (pins === 'tab') {
    tabs = (
      <Tabs.List aria-label="views of this room" className="sl-room-head-tabs">
        <Tabs.Tab value={ROOM_VIEWS.talk} controls={controls}>
          talk
        </Tabs.Tab>
        <Tabs.Tab value={ROOM_VIEWS.files} count={filesCount} controls={controls}>
          files
        </Tabs.Tab>
        <Tabs.Tab value={ROOM_VIEWS.pinned} count={pinnedCount ?? pinParts.length} controls={controls}>
          pinned
        </Tabs.Tab>
      </Tabs.List>
    )
  }

  const taskCount = tasks?.length ?? 0
  const tasksLabel = `${taskCount} ${taskCount === 1 ? 'task' : 'tasks'} in this room`

  return (
    <PlaceHead
      icon={icon ?? <Icon name="hash" />}
      tabs={tabs}
      className={cx('sl-room-head', className)}
      data-pins={pins}
      {...props}
    >
      {pins !== 'none' && taskCount ? (
        <Tooltip label={tasksLabel} caption={tasksNeedYou ? 'Something here waits on you.' : undefined}>
          <button
            type="button"
            aria-label={tasksNeedYou ? `${tasksLabel}, something waits on you` : tasksLabel}
            className="sl-room-head-tasks"
            onClick={(event) => {
              soundPress(event)
              onOpenTasks?.()
            }}
          >
            <ProgressDonut arcs={tasks ?? []} needsYou={tasksNeedYou} tooltip={false} aria-hidden="true" />
            <Figure>{taskCount}</Figure>
          </button>
        </Tooltip>
      ) : null}
      {crew !== undefined ? <span className="sl-room-head-crew">{crew}</span> : null}
      {pins === 'none' ? (
        <IconAction label="Outline of this room" aria-expanded={outlineOpen} onClick={onOpenOutline} className="sl-room-head-outline">
          <Icon name="tree" />
        </IconAction>
      ) : null}
    </PlaceHead>
  )
}
