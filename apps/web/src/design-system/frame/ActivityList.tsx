import * as React from 'react'
import { NeedsYou, useNeedsYouAnswerStatus } from '../patterns/NeedsYou'
import { Figure } from '../primitives/Figure'
import { Icon } from '../primitives/Icon'
import { cx } from '../lib/react-utils'
import { ActivityMark, type ActivityKind } from './ActivityMark'

export type { ActivityKind } from './ActivityMark'
export type ActivityAge = 'today' | 'yesterday' | 'older'

/* ── the list ───────────────────────────────────────────────────────────── */

export type ActivityDensity = 'full' | 'compact'

/* The list's density, read by its rows. */
const ActivityDensityContext = React.createContext<ActivityDensity>('full')

export interface ActivityListProps extends React.ComponentPropsWithRef<'section'> {
  /* `full`: one line per row in five slots. `compact`: for a sidebar about
     230 px wide, two lines per row (the mark, who and the time; under them
     the sentence, truncated). A needs-you row in compact form opens
     elsewhere (onOpen) and never unfolds its picks in the list. */
  density?: ActivityDensity
}

/* The threads that are live for the person, one row each, under day heads.
   The who and where columns line up down the list. */
export function ActivityList({
  density = 'full',
  className,
  'aria-label': ariaLabel = 'activity',
  ...props
}: ActivityListProps) {
  return (
    <ActivityDensityContext.Provider value={density}>
      <section aria-label={ariaLabel} className={cx('sl-activity-list', className)} data-density={density} {...props} />
    </ActivityDensityContext.Provider>
  )
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
  /* The row whose item is open elsewhere on the screen (the work area, a
     pane): aria-current and the lit tone. */
  selected?: boolean
  /* An open needs-you row shows its children as a second line (a
     NeedsYou.Picks line); a pick there applies with the undo window. */
  open?: boolean
  onOpen?: () => void
  /* The open row's answer stood through its window; the row folds away. */
  onSettle?: (id: string, value: string) => void
  onLater?: (id: string) => void
}

/* One thread in five fixed slots: what happened, who, where, one sentence,
   when. In a compact list: the mark, who and when on one line, the
   sentence under them. */
export function ActivityRow({
  id,
  kind,
  open = false,
  onSettle,
  onLater,
  children,
  ...props
}: ActivityRowProps) {
  const density = React.useContext(ActivityDensityContext)
  if (density === 'compact') return <ActivityRowCompact id={id} kind={kind} {...props} />
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
  selected = false,
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
      data-selected={selected ? '' : undefined}
      data-settle={settle ?? undefined}
      inert={settle === 'settled'}
      {...props}
    >
      <div className="sl-activity-row-inner">
        <button type="button" className="sl-activity-row-main" aria-current={selected ? 'true' : undefined} onClick={onOpen}>
          <span className="sl-activity-slot" data-slot="what">
            <ActivityMark kind={kind} />
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

type ActivityRowCompactProps = Omit<ActivityRowProps, 'open' | 'onSettle' | 'onLater' | 'children'>

/* A row of a compact list: the same button and state as a full row, in two
   lines. Where the thread lives is said to a screen reader only. */
function ActivityRowCompact({
  id,
  kind,
  glyph,
  name,
  where,
  sentence,
  when,
  age = 'today',
  selected = false,
  onOpen,
  className,
  ...props
}: ActivityRowCompactProps) {
  return (
    <div
      className={cx('sl-activity-row', className)}
      data-activity-id={id}
      data-kind={kind}
      data-age={age}
      data-selected={selected ? '' : undefined}
      {...props}
    >
      <button type="button" className="sl-activity-row-main" aria-current={selected ? 'true' : undefined} onClick={onOpen}>
        <span className="sl-activity-slot" data-slot="what">
          <ActivityMark kind={kind} />
        </span>
        <span className="sl-activity-slot" data-slot="who">
          <span className="sl-activity-glyph">{glyph}</span>
          <span className="sl-activity-name">{name}</span>
          {where !== undefined ? <span className="sl-activity-where-said"> in {where}</span> : null}
        </span>
        <span className="sl-activity-slot" data-slot="when">
          <Figure>{when}</Figure>
        </span>
        <span className="sl-activity-slot" data-slot="say">
          {sentence}
        </span>
      </button>
    </div>
  )
}
