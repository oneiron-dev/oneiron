import * as React from 'react'
import { GuestRing } from '../marks/GuestRing'
import { StatusDot } from '../marks/StatusDot'
import { NeedsYou, useNeedsYouAnswerStatus } from '../patterns/NeedsYou'
import { Figure } from '../primitives/Figure'
import { Icon } from '../primitives/Icon'
import { cx } from '../lib/react-utils'

export type ActivityKind = 'needs-you' | 'running' | 'mention' | 'done' | 'reaction' | 'outside'
export type ActivityAge = 'today' | 'yesterday' | 'older'

/* What a screen reader hears for each mark. */
const KIND_WORD: Record<ActivityKind, string> = {
  'needs-you': 'waits on you',
  running: 'running',
  mention: 'mentioned you',
  done: 'done',
  reaction: 'reacted',
  outside: 'from another vault',
}

/* The working mark: a short half-tone segment, the steps bar's working
   screen (one 1 px dot on every other pixel of a 12 x 6 box). */
const HALFTONE = Array.from({ length: 12 * 6 }, (_, i) => [i % 12, Math.floor(i / 12)] as const)
  .filter(([x, y]) => (x + y) % 2 === 0)
  .map(([x, y]) => `M${x} ${y}h1v1h-1z`)
  .join('')

function KindMark({ kind }: { kind: ActivityKind }) {
  const word = KIND_WORD[kind]
  let mark: React.ReactNode
  switch (kind) {
    case 'needs-you':
      return <StatusDot state="waiting" label={word} className="sl-activity-mark" data-kind={kind} />
    case 'outside':
      return <GuestRing label={word} className="sl-activity-mark" data-kind={kind} />
    case 'running':
      mark = (
        <svg viewBox="0 0 12 6" width="12" height="6" shapeRendering="crispEdges" aria-hidden="true" focusable="false">
          <path d={HALFTONE} />
        </svg>
      )
      break
    case 'mention':
      mark = <Icon name="at" size={15} />
      break
    case 'done':
      mark = <Icon name="check" size={15} />
      break
    case 'reaction':
      mark = <Icon name="smile" size={15} />
      break
  }
  return (
    <span role="img" aria-label={word} className="sl-activity-mark" data-kind={kind}>
      {mark}
    </span>
  )
}

/* ── the list ───────────────────────────────────────────────────────────── */

export interface ActivityListProps extends React.ComponentPropsWithRef<'section'> {}

/* The threads that are live for the person, one row each, under day heads.
   The who and where columns line up down the list. */
export function ActivityList({ className, 'aria-label': ariaLabel = 'activity', ...props }: ActivityListProps) {
  return <section aria-label={ariaLabel} className={cx('sl-activity-list', className)} {...props} />
}

export interface ActivityDayProps extends React.ComponentPropsWithRef<'h3'> {}

/* A day's head in the list: `Today`, `Yesterday`. */
export function ActivityDay({ className, ...props }: ActivityDayProps) {
  return <h3 className={cx('sl-activity-day', className)} {...props} />
}

/* ── a row ──────────────────────────────────────────────────────────────── */

export interface ActivityRowProps extends Omit<React.ComponentPropsWithRef<'div'>, 'id'> {
  id?: string
  /* What happened: one mark. */
  kind: ActivityKind
  /* Who: their Glyph (line form for a resident, the initial for a person). */
  glyph: React.ReactNode
  name: React.ReactNode
  /* Where: a room's name; the hash symbol comes with it. */
  where?: React.ReactNode
  /* One sentence; it truncates. */
  sentence: React.ReactNode
  /* When: set as a figure at the right. */
  when: React.ReactNode
  /* Older rows print one or two ink steps fainter. */
  age?: ActivityAge
  /* An open needs-you row shows its children as a second line (a
     NeedsYou.Picks line); a pick there applies with the undo window. */
  open?: boolean
  onOpen?: () => void
  /* The open row's answer stood through its window; the row folds away. */
  onSettle?: (id: string, value: string) => void
  onLater?: (id: string) => void
}

/* One thread in five fixed slots: what happened, who, where, one sentence,
   when. */
export function ActivityRow({
  id,
  kind,
  open = false,
  onSettle,
  onLater,
  children,
  ...props
}: ActivityRowProps) {
  const second = kind === 'needs-you' && open && children !== undefined
  if (!second) return <ActivityRowBody id={id} kind={kind} {...props} />
  return (
    <NeedsYou.Answer id={id ?? ''} onSettle={onSettle} onLater={onLater}>
      <ActivityRowBody id={id} kind={kind} open {...props}>
        {children}
      </ActivityRowBody>
    </NeedsYou.Answer>
  )
}

type ActivityRowBodyProps = Omit<ActivityRowProps, 'onSettle' | 'onLater'>

function ActivityRowBody({
  id,
  kind,
  glyph,
  name,
  where,
  sentence,
  when,
  age = 'today',
  open = false,
  onOpen,
  className,
  children,
  ...props
}: ActivityRowBodyProps) {
  const settle = useNeedsYouAnswerStatus()
  return (
    <div
      className={cx('sl-activity-row', className)}
      data-activity-id={id}
      data-kind={kind}
      data-age={age}
      data-open={open ? '' : undefined}
      data-settle={settle ?? undefined}
      inert={settle === 'settled'}
      {...props}
    >
      <div className="sl-activity-row-inner">
        <button type="button" className="sl-activity-row-main" onClick={onOpen}>
          <span className="sl-activity-slot" data-slot="what">
            <KindMark kind={kind} />
          </span>
          <span className="sl-activity-slot" data-slot="who">
            <span className="sl-activity-glyph">{glyph}</span>
            <span className="sl-activity-name">{name}</span>
          </span>
          <span className="sl-activity-slot" data-slot="where">
            {where !== undefined ? (
              <>
                <Icon name="hash" size={14} />
                <span className="sl-activity-where">{where}</span>
              </>
            ) : null}
          </span>
          <span className="sl-activity-slot" data-slot="say">
            {sentence}
          </span>
          <span className="sl-activity-slot" data-slot="when">
            <Figure>{when}</Figure>
          </span>
        </button>
        {open && children !== undefined ? <div className="sl-activity-row-line">{children}</div> : null}
      </div>
    </div>
  )
}
