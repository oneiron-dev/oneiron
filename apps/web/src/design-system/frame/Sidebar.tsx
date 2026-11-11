import * as React from 'react'
import { Tooltip } from '../overlays/Tooltip'
import { Figure } from '../primitives/Figure'
import { Icon } from '../primitives/Icon'
import { IconAction } from '../primitives/IconAction'
import { cx, mergeSlotProps, useControllableState, useSafeId } from '../lib/react-utils'
import { useReorder } from './use-reorder'

/* ── the root ───────────────────────────────────────────────────────────── */

interface SidebarContextValue {
  ground: 'field' | 'paper'
  collapsed: boolean
  announce: (message: string) => void
}

const SidebarContext = React.createContext<SidebarContextValue | null>(null)

function useSidebar(part: string): SidebarContextValue {
  const ctx = React.useContext(SidebarContext)
  if (!ctx) throw new Error(`${part} must be inside a Sidebar`)
  return ctx
}

export interface SidebarProps extends React.ComponentPropsWithRef<'nav'> {
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

/* The list of places at the left. Children: one Sidebar.Head, then Sidebar.Groups. */
function SidebarRoot({
  ground = 'field',
  collapsed = false,
  onGroupReorder,
  className,
  children,
  'aria-label': ariaLabel = 'places',
  ...props
}: SidebarProps) {
  const [message, setMessage] = React.useState('')
  const reorder = useReorder<HTMLDivElement>({
    itemAttribute: 'data-sidebar-group-id',
    handle: '[data-sidebar-group-handle]',
    onReorder: onGroupReorder,
    announce: setMessage,
  })
  const parts = React.Children.toArray(children)
  const heads = parts.filter((c) => React.isValidElement(c) && c.type === SidebarHead)
  const groups = parts.filter((c) => !heads.includes(c))
  const ctx = React.useMemo(() => ({ ground, collapsed, announce: setMessage }), [ground, collapsed])

  return (
    <SidebarContext.Provider value={ctx}>
      <nav
        aria-label={ariaLabel}
        className={cx('sl-sidebar', className)}
        data-ground={ground}
        data-collapsed={collapsed ? '' : undefined}
        {...props}
      >
        {heads}
        <div ref={reorder.containerRef} className="sl-sidebar-groups" {...reorder.containerProps}>
          {groups}
        </div>
        <span className="sl-sidebar-status" role="status">
          {message}
        </span>
      </nav>
    </SidebarContext.Provider>
  )
}

/* ── the head ───────────────────────────────────────────────────────────── */

export interface SidebarHeadProps extends React.ComponentPropsWithRef<'div'> {}

/* The top of the sidebar: the vault switch, then icon actions at the right. */
function SidebarHead({ className, ...props }: SidebarHeadProps) {
  return <div className={cx('sl-sidebar-head', className)} {...props} />
}

/* ── a group ────────────────────────────────────────────────────────────── */

export interface SidebarGroupProps extends Omit<React.ComponentPropsWithRef<'div'>, 'id'> {
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

function SidebarGroup({
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
}: SidebarGroupProps) {
  const sidebar = useSidebar('Sidebar.Group')
  const [openState, setOpen] = useControllableState(openProp, defaultOpen, onOpenChange)
  /* Collapsed to icons, every row shows; a group without a head never folds. */
  const open = sidebar.collapsed || !label || openState
  const listId = useSafeId('sl-sidebar-group')
  const reorder = useReorder<HTMLDivElement>({
    itemAttribute: 'data-sidebar-row-id',
    onReorder: reorderable ? onReorder : undefined,
    announce: sidebar.announce,
  })

  return (
    <div
      className={cx('sl-sidebar-group', className)}
      data-sidebar-group-id={id}
      data-reorder-label={label}
      data-state={open ? 'open' : 'closed'}
      {...props}
    >
      {label ? (
        <button
          type="button"
          className="sl-sidebar-group-label"
          data-sidebar-group-handle=""
          aria-expanded={open}
          aria-controls={listId}
          tabIndex={sidebar.collapsed ? -1 : undefined}
          draggable={false}
          onClick={() => setOpen(!openState)}
        >
          {label}
          <Icon name="chevron" size={12} className="sl-sidebar-group-chevron" />
        </button>
      ) : null}
      <div className="sl-sidebar-group-fold" data-state={open ? 'open' : 'closed'}>
        <div
          ref={reorder.containerRef}
          id={listId}
          role="list"
          aria-label={label}
          className="sl-sidebar-group-list"
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

export interface SidebarRowProps extends Omit<React.ComponentPropsWithRef<'button'>, 'id'> {
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
    <svg className="sl-sidebar-row-shared" viewBox="0 0 10 10" role="img" aria-label="shared with another vault">
      <path d="M5 .8 9.2 5 5 9.2 .8 5Z" />
    </svg>
  )
}

function SidebarRow({
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
}: SidebarRowProps) {
  const sidebar = useSidebar('Sidebar.Row')
  const content = (
    <>
      <span className="sl-sidebar-row-mark" data-slot={glyph ? 'glyph' : 'icon'} aria-hidden="true">
        {glyph ?? icon}
      </span>
      <span className="sl-sidebar-row-words">
        <span className="sl-sidebar-row-label">{label}</span>
        {shared ? <SharedMark /> : null}
        {caption !== undefined ? <span className="sl-sidebar-row-caption">{caption}</span> : null}
      </span>
      {count !== undefined ? (
        <Figure size="badge" className="sl-sidebar-row-count">
          {count}
        </Figure>
      ) : null}
    </>
  )
  const own = {
    className: cx('sl-sidebar-row', className),
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
  if (sidebar.collapsed && typeof label === 'string') {
    control = (
      <Tooltip label={label} caption={typeof caption === 'string' ? caption : undefined} side="right">
        {control}
      </Tooltip>
    )
  }

  return (
    <div
      role="listitem"
      className="sl-sidebar-item"
      data-sidebar-row-id={id}
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
          className="sl-sidebar-row-pin"
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

/* Compound parts: Sidebar, Sidebar.Head, Sidebar.Group, Sidebar.Row. */
export const Sidebar = Object.assign(SidebarRoot, { Head: SidebarHead, Group: SidebarGroup, Row: SidebarRow })
