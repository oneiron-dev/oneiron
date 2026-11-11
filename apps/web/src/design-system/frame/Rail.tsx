import * as React from 'react'
import { Tooltip } from '../overlays/Tooltip'
import { Figure } from '../primitives/Figure'
import { Icon } from '../primitives/Icon'
import { IconAction } from '../primitives/IconAction'
import { cx, mergeSlotProps, useControllableState, useSafeId } from '../lib/react-utils'
import { useReorder } from './use-reorder'

/* ── the root ───────────────────────────────────────────────────────────── */

interface RailContextValue {
  ground: 'field' | 'paper'
  collapsed: boolean
  announce: (message: string) => void
}

const RailContext = React.createContext<RailContextValue | null>(null)

function useRail(part: string): RailContextValue {
  const ctx = React.useContext(RailContext)
  if (!ctx) throw new Error(`${part} must be inside a Rail`)
  return ctx
}

export interface RailProps extends React.ComponentPropsWithRef<'nav'> {
  /* `field`: bare on the printed field; words carry the on-field ink (and
     its soft shadow by day). `paper`: on a near-opaque strip of the ground. */
  ground?: 'field' | 'paper'
  /* Symbols only; names show in a tooltip. */
  collapsed?: boolean
  /* The groups below the head were reordered (drag a group by its label, or
     Alt+ArrowUp / Alt+ArrowDown on the label). Each group needs an `id`.
     The caller renders the new order. */
  onGroupReorder?: (ids: string[]) => void
}

/* The list of places at the left. Children: one Rail.Head, then Rail.Groups. */
function RailRoot({
  ground = 'field',
  collapsed = false,
  onGroupReorder,
  className,
  children,
  'aria-label': ariaLabel = 'places',
  ...props
}: RailProps) {
  const [message, setMessage] = React.useState('')
  const reorder = useReorder<HTMLDivElement>({
    itemAttribute: 'data-rail-group-id',
    handle: '[data-rail-group-handle]',
    onReorder: onGroupReorder,
    announce: setMessage,
  })
  const parts = React.Children.toArray(children)
  const heads = parts.filter((c) => React.isValidElement(c) && c.type === RailHead)
  const groups = parts.filter((c) => !heads.includes(c))
  const ctx = React.useMemo(() => ({ ground, collapsed, announce: setMessage }), [ground, collapsed])

  return (
    <RailContext.Provider value={ctx}>
      <nav
        aria-label={ariaLabel}
        className={cx('sl-rail', className)}
        data-ground={ground}
        data-collapsed={collapsed ? '' : undefined}
        {...props}
      >
        {heads}
        <div ref={reorder.containerRef} className="sl-rail-groups" {...reorder.containerProps}>
          {groups}
        </div>
        <span className="sl-rail-status" role="status">
          {message}
        </span>
      </nav>
    </RailContext.Provider>
  )
}

/* ── the head ───────────────────────────────────────────────────────────── */

export interface RailHeadProps extends React.ComponentPropsWithRef<'div'> {}

/* The top of the rail: the vault switch, then icon actions at the right. */
function RailHead({ className, ...props }: RailHeadProps) {
  return <div className={cx('sl-rail-head', className)} {...props} />
}

/* ── a group ────────────────────────────────────────────────────────────── */

export interface RailGroupProps extends Omit<React.ComponentPropsWithRef<'div'>, 'id'> {
  /* Names the group for reordering. */
  id?: string
  /* The group's head; with one the group folds. */
  label?: string
  open?: boolean
  defaultOpen?: boolean
  onOpenChange?: (open: boolean) => void
  /* The rows can be reordered (each row needs an `id`); the new order goes
     to `onReorder` and the caller renders it. */
  reorderable?: boolean
  onReorder?: (ids: string[]) => void
}

function RailGroup({
  id,
  label,
  open: openProp,
  defaultOpen = true,
  onOpenChange,
  reorderable = false,
  onReorder,
  className,
  children,
  ...props
}: RailGroupProps) {
  const rail = useRail('Rail.Group')
  const [openState, setOpen] = useControllableState(openProp, defaultOpen, onOpenChange)
  /* An icon rail shows every row; a group without a head never folds. */
  const open = rail.collapsed || !label || openState
  const listId = useSafeId('sl-rail-group')
  const reorder = useReorder<HTMLDivElement>({
    itemAttribute: 'data-rail-row-id',
    onReorder: reorderable ? onReorder : undefined,
    announce: rail.announce,
  })

  return (
    <div
      className={cx('sl-rail-group', className)}
      data-rail-group-id={id}
      data-reorder-label={label}
      data-state={open ? 'open' : 'closed'}
      {...props}
    >
      {label ? (
        <button
          type="button"
          className="sl-rail-group-label"
          data-rail-group-handle=""
          aria-expanded={open}
          aria-controls={listId}
          tabIndex={rail.collapsed ? -1 : undefined}
          draggable={false}
          onClick={() => setOpen(!openState)}
        >
          {label}
          <Icon name="chevron" size={12} className="sl-rail-group-chevron" />
        </button>
      ) : null}
      <div className="sl-rail-group-fold" data-state={open ? 'open' : 'closed'}>
        <div
          ref={reorder.containerRef}
          id={listId}
          role="list"
          aria-label={label}
          className="sl-rail-group-list"
          inert={!open}
          {...reorder.containerProps}
        >
          {children}
        </div>
      </div>
    </div>
  )
}

/* ── a row ──────────────────────────────────────────────────────────────── */

export interface RailRowProps extends Omit<React.ComponentPropsWithRef<'button'>, 'id'> {
  /* Names the row for reordering. */
  id?: string
  /* The symbol before the label: an Icon. */
  icon?: React.ReactNode
  /* Or a resident's mark: a Glyph (line form). */
  glyph?: React.ReactNode
  label: React.ReactNode
  /* A short word at the right in a quieter ink. */
  caption?: React.ReactNode
  /* A badge figure at the right. */
  count?: number | string
  /* The place on screen now. */
  current?: boolean
  /* Nesting under the row above: 0 to 2. */
  depth?: 0 | 1 | 2
  /* Shared with another vault: the aperture diamond after the label. */
  shared?: boolean
  /* Render the single child element (a router link) as the row. */
  asChild?: boolean
  /* With a handler the row shows a pin action on hover and focus. */
  pinned?: boolean
  onPinChange?: (pinned: boolean) => void
}

function SharedMark() {
  return (
    <svg className="sl-rail-row-shared" viewBox="0 0 10 10" role="img" aria-label="shared with another vault">
      <path d="M5 .8 9.2 5 5 9.2 .8 5Z" />
    </svg>
  )
}

function RailRow({
  id,
  icon,
  glyph,
  label,
  caption,
  count,
  current = false,
  depth = 0,
  shared = false,
  asChild = false,
  pinned = false,
  onPinChange,
  className,
  children,
  type = 'button',
  ...props
}: RailRowProps) {
  const rail = useRail('Rail.Row')
  const content = (
    <>
      <span className="sl-rail-row-mark" data-slot={glyph ? 'glyph' : 'icon'} aria-hidden="true">
        {glyph ?? icon}
      </span>
      <span className="sl-rail-row-words">
        <span className="sl-rail-row-label">{label}</span>
        {shared ? <SharedMark /> : null}
        {caption !== undefined ? <span className="sl-rail-row-caption">{caption}</span> : null}
      </span>
      {count !== undefined ? (
        <Figure size="badge" className="sl-rail-row-count">
          {count}
        </Figure>
      ) : null}
    </>
  )
  const own = {
    className: cx('sl-rail-row', className),
    'aria-current': current ? ('page' as const) : undefined,
    'data-current': current ? '' : undefined,
    draggable: false,
    ...props,
  }
  let control: React.ReactElement
  if (asChild && React.isValidElement(children)) {
    const child = children as React.ReactElement<Record<string, unknown>>
    control = React.cloneElement(child, mergeSlotProps(own, child.props), content)
  } else {
    control = (
      <button type={type} {...own}>
        {content}
      </button>
    )
  }
  if (rail.collapsed && typeof label === 'string') {
    control = (
      <Tooltip label={label} caption={typeof caption === 'string' ? caption : undefined} side="right">
        {control}
      </Tooltip>
    )
  }

  return (
    <div
      role="listitem"
      className="sl-rail-item"
      data-rail-row-id={id}
      data-reorder-label={typeof label === 'string' ? label : undefined}
      data-depth={depth}
      data-pinnable={onPinChange ? '' : undefined}
    >
      {control}
      {onPinChange ? (
        <IconAction
          label="Pin"
          size="sm"
          tooltipSide="right"
          className="sl-rail-row-pin"
          aria-pressed={pinned}
          data-reorder-ignore=""
          onClick={() => onPinChange(!pinned)}
        >
          <Icon name="pin" />
        </IconAction>
      ) : null}
    </div>
  )
}

/* Compound parts: Rail, Rail.Head, Rail.Group, Rail.Row. */
export const Rail = Object.assign(RailRoot, { Head: RailHead, Group: RailGroup, Row: RailRow })
