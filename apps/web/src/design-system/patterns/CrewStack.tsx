import * as React from 'react'
import { Icon } from '../primitives/Icon'
import { IconAction } from '../primitives/IconAction'
import { Popover } from '../overlays/Popover'
import { Tooltip } from '../overlays/Tooltip'
import { cx } from '../lib/react-utils'

/* Each shown member's stacking order: the first sits on top. */
const StackOrder = React.createContext<number | undefined>(undefined)

export interface CrewStackProps extends React.ComponentPropsWithRef<'div'> {
  /* Members shown before `+N`. */
  max?: number
  /* Shows the invite icon at the end. */
  onInvite?: (event: React.MouseEvent<HTMLButtonElement>) => void
  inviteLabel?: string
  inviteCaption?: string
  /* The name of the full list behind `+N`. */
  listLabel?: string
}

/* The people in a place as overlapping marks: the first `max` members, then
   `+N` that opens the full list (the CrewStack.List child), then the invite
   icon. The order is the caller's: people before residents. A member may be
   wrapped in a Popover with the member as its trigger. */
function CrewStackRoot({
  max = 5,
  onInvite,
  inviteLabel = 'Add to this room',
  inviteCaption = 'a resident, or a person as a guest',
  listLabel = 'Everyone in the room',
  className,
  children,
  'aria-label': ariaLabel = 'crew',
  ...props
}: CrewStackProps) {
  const all = React.Children.toArray(children)
  const list = all.find((c) => React.isValidElement(c) && c.type === CrewStackList) as
    | React.ReactElement<CrewStackListProps>
    | undefined
  const members = all.filter((c) => c !== list)
  const shown = members.slice(0, max)
  const rest = members.length - shown.length
  return (
    <div role="group" aria-label={ariaLabel} className={cx('sl-crew-stack', className)} {...props}>
      {shown.map((member, i) => (
        <StackOrder.Provider key={React.isValidElement(member) && member.key != null ? member.key : i} value={shown.length + 1 - i}>
          {member}
        </StackOrder.Provider>
      ))}
      {rest > 0 ? (
        <Popover>
          <Tooltip label={listLabel}>
            <Popover.Trigger className="sl-crew-member sl-crew-more" aria-label={`${listLabel}, ${members.length}`}>
              +{rest}
            </Popover.Trigger>
          </Tooltip>
          <Popover.Content side="bottom" align="end" offset={10} className="sl-crew-list" aria-label={listLabel}>
            {list?.props.children}
          </Popover.Content>
        </Popover>
      ) : null}
      {onInvite ? (
        <IconAction label={inviteLabel} caption={inviteCaption} className="sl-crew-invite" onClick={onInvite}>
          <Icon name="circlePlus" />
        </IconAction>
      ) : null}
    </div>
  )
}

export interface CrewStackMemberProps extends React.ComponentPropsWithRef<'button'> {
  /* The tooltip's first line; the Glyph inside carries the accessible name. */
  name?: string
  /* One tooltip line: what they are doing, or where a guest comes from. */
  caption?: string
}

/* One member: a Glyph cut out of the ground, overlapping the next. It is a
   button when it acts (a click handler, or as a Popover.Trigger), else a
   focusable mark that names itself on hover. */
function CrewStackMember({ name, caption, className, style, onClick, children, type = 'button', ...props }: CrewStackMemberProps) {
  const order = React.useContext(StackOrder)
  const interactive = !!onClick
  const shared = {
    className: cx('sl-crew-member', className),
    style: order !== undefined ? { zIndex: order, ...style } : style,
  }
  const el = interactive ? (
    <button type={type} onClick={onClick} {...shared} {...props}>
      {children}
    </button>
  ) : (
    <span tabIndex={name ? 0 : undefined} {...shared} {...(props as React.ComponentPropsWithRef<'span'>)}>
      {children}
    </span>
  )
  return name ? (
    <Tooltip label={name} caption={caption}>
      {el}
    </Tooltip>
  ) : (
    el
  )
}

export interface CrewStackListProps {
  children?: React.ReactNode
}

/* The full list behind `+N`. Rendered by the stack inside its popover. */
function CrewStackList({ children }: CrewStackListProps) {
  return <>{children}</>
}

export type CrewStackListRowProps = { glyph: React.ReactNode; className?: string; children?: React.ReactNode } & (
  | ({ href: string } & Omit<React.ComponentPropsWithRef<'a'>, 'children' | 'className'>)
  | ({ href?: undefined } & Omit<React.ComponentPropsWithRef<'button'>, 'children' | 'className'>)
)

/* A row of the full list: the mark and the name; the name opens the profile. */
function CrewStackListRow({ glyph, className, children, ...props }: CrewStackListRowProps) {
  return (
    <div className={cx('sl-crew-row', className)}>
      {glyph}
      {props.href !== undefined ? (
        <a className="sl-crew-row-name" {...(props as React.ComponentPropsWithRef<'a'>)}>
          {children}
        </a>
      ) : (
        <button type="button" className="sl-crew-row-name" {...(props as React.ComponentPropsWithRef<'button'>)}>
          {children}
        </button>
      )}
    </div>
  )
}

/* Compound parts: CrewStack, .Member, .List, .ListRow. */
export const CrewStack = Object.assign(CrewStackRoot, {
  Member: CrewStackMember,
  List: CrewStackList,
  ListRow: CrewStackListRow,
})
