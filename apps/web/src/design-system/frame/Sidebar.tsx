import * as React from 'react'
import { Tooltip } from '../overlays/Tooltip'
import { Figure } from '../primitives/Figure'
import { Icon } from '../primitives/Icon'
import { IconAction } from '../primitives/IconAction'
import { Verb } from '../primitives/Verb'
import { cx, mergeRefs, mergeSlotProps, useControllableState, useSafeId } from '../lib/react-utils'
import { splitChildRows } from './sidebar-tree'
import { useReorder } from './use-reorder'

/* ── the root ───────────────────────────────────────────────────────────── */

interface SidebarContextValue {
  collapsed: boolean
  announce: (message: string) => void
  /* Keeps the list at its present height until the pointer or focus
     leaves the sidebar, so a group folding above the end of a scrolled
     list does not pull the list (and the label just pressed) down. */
  holdHeight: () => void
}

/* True inside a row's child rows: the tree has two levels, never more. */
const ChildRowContext = React.createContext(false)

const SidebarContext = React.createContext<SidebarContextValue | null>(null)

function useSidebar(part: string): SidebarContextValue {
  const ctx = React.useContext(SidebarContext)
  if (!ctx) throw new Error(`${part} must be inside a Sidebar`)
  return ctx
}

export interface SidebarProps extends React.ComponentPropsWithRef<'nav'> {
  /* Symbols only; names show in a tooltip. */
  collapsed?: boolean
  /* `icon`: a child row sits one icon step in, its symbol under the
     parent's label. `none`: child rows sit flush with their parent, each
     keeping its own symbol. */
  childIndent?: 'icon' | 'none'
  /* The groups below the head were reordered (drag a group by its label, or
     Alt+ArrowUp / Alt+ArrowDown on the label). Each group needs an `id`.
     The caller renders the new order. */
  onGroupReorder?: (ids: string[]) => void
}

/* The list of places at the left, in the sheet's inks; it has no surface
   of its own (in the frame it stands on the sidebar's tone, in a peek on
   the popover's). Children: one Sidebar.Head, then Sidebar.Groups, each a
   direct child (the head is found by its type, so a component that
   renders a Sidebar.Head lands among the groups). The
   tree has two levels: a group's rows, and under a row its child rows
   (`childRows`). A group label is quiet; the rows carry a symbol each.
   Folding or unfolding a group never moves the label that was pressed. */
function SidebarRoot({
  collapsed = false,
  childIndent = 'icon',
  onGroupReorder,
  className,
  children,
  'aria-label': ariaLabel = 'places',
  onPointerLeave,
  onBlur,
  ...props
}: SidebarProps) {
  const [message, setMessage] = React.useState('')
  const groupsRef = React.useRef<HTMLDivElement | null>(null)
  const holdHeight = React.useCallback(() => {
    const groups = groupsRef.current
    if (groups) groups.style.minHeight = `${groups.offsetHeight}px`
  }, [])
  const releaseHeight = () => {
    const groups = groupsRef.current
    if (groups) groups.style.minHeight = ''
  }
  const reorder = useReorder<HTMLDivElement>({
    itemAttribute: 'data-sidebar-group-id',
    handle: '[data-sidebar-group-handle]',
    onReorder: onGroupReorder,
    announce: setMessage,
  })
  const parts = React.Children.toArray(children)
  const heads = parts.filter((c) => React.isValidElement(c) && c.type === SidebarHead)
  const groups = parts.filter((c) => !heads.includes(c))
  const ctx = React.useMemo(() => ({ collapsed, announce: setMessage, holdHeight }), [collapsed, holdHeight])

  return (
    <SidebarContext.Provider value={ctx}>
      <nav
        aria-label={ariaLabel}
        className={cx('sl-sidebar', className)}
        data-collapsed={collapsed ? '' : undefined}
        data-child-indent={childIndent}
        onPointerLeave={(event) => {
          onPointerLeave?.(event)
          if (event.pointerType !== 'touch') releaseHeight()
        }}
        onBlur={(event) => {
          onBlur?.(event)
          const to = event.relatedTarget as Node | null
          if (!to || !event.currentTarget.contains(to)) releaseHeight()
        }}
        {...props}
      >
        {heads}
        <div
          ref={mergeRefs(groupsRef, reorder.containerRef)}
          className="sl-sidebar-groups"
          {...reorder.containerProps}
        >
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

/* The first line of a sidebar. On Home: the vault's name and a chevron at
   the left (a VaultSwitch, the menu of the person's vaults), then at the
   right IconAction search and the fold action (AppFrame.Fold). Elsewhere
   the place's name takes the left. */
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
          onClick={() => {
            sidebar.holdHeight()
            setOpen(!openState)
          }}
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
  /* A short word at the right in a quieter ink. When the label and the
     caption do not fit on one line, the caption wraps under the label. */
  caption?: React.ReactNode
  /* A badge figure at the right. */
  count?: number | string
  /* The place on screen now. */
  current?: boolean
  /* The rows under this one (Sidebar.Row elements), one level only: a
     child row takes no child rows. A child row keeps its own symbol (`#`
     for a room). Past five, the rest fold behind `show more`. */
  childRows?: React.ReactNode
  /* The folded child rows show. */
  showAll?: boolean
  defaultShowAll?: boolean
  onShowAllChange?: (showAll: boolean) => void
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

/* The Sidebar.Row elements of a node, through fragments, in order. */
function rowElements(node: React.ReactNode, out: React.ReactElement<SidebarRowProps>[] = []) {
  React.Children.forEach(node, (child) => {
    if (!React.isValidElement(child)) return
    if (child.type === React.Fragment) rowElements((child.props as { children?: React.ReactNode }).children, out)
    else out.push(child as React.ReactElement<SidebarRowProps>)
  })
  return out
}

function SidebarRow({
  id,
  icon,
  glyph,
  label,
  caption,
  count,
  current = false,
  childRows,
  showAll: showAllProp,
  defaultShowAll,
  onShowAllChange,
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
  const isChild = React.useContext(ChildRowContext)
  const kids = childRows === undefined ? [] : rowElements(childRows)
  if (isChild && kids.length) throw new Error('A child Sidebar.Row takes no child rows: the sidebar tree has two levels')
  const split = splitChildRows(kids.length)
  /* A folded child that is the current place starts unfolded. */
  const currentFolded = kids.slice(split.shown).some((kid) => kid.props.current)
  const [showAll, setShowAll] = useControllableState(showAllProp, defaultShowAll ?? currentFolded, onShowAllChange)
  const restId = useSafeId('sl-sidebar-rest')
  const content = (
    <>
      <span className="sl-sidebar-row-mark" data-slot={glyph ? 'glyph' : 'icon'} aria-hidden="true">
        {glyph ?? icon}
      </span>
      <span className="sl-sidebar-row-words">
        <span className="sl-sidebar-row-name">
          <span className="sl-sidebar-row-label">{label}</span>
          {shared ? <SharedMark /> : null}
        </span>
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
      data-level={isChild ? 1 : 0}
      data-pinnable={onPinChange ? '' : undefined}
    >
      <div className="sl-sidebar-line">
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
      {kids.length ? (
        <ChildRowContext.Provider value={true}>
          <div role="list" aria-label={typeof label === 'string' ? label : undefined} className="sl-sidebar-children">
            {kids.slice(0, split.shown)}
            {split.folded ? (
              <>
                <div role="none" className="sl-sidebar-rest" data-state={showAll ? 'open' : 'closed'}>
                  <div role="none" id={restId} className="sl-sidebar-rest-rows" inert={!showAll}>
                    {kids.slice(split.shown)}
                  </div>
                </div>
                <div role="listitem" className="sl-sidebar-more">
                  <Verb aria-expanded={showAll} aria-controls={restId} onClick={() => setShowAll(!showAll)}>
                    {showAll ? 'show fewer' : 'show more'}
                  </Verb>
                  {showAll ? null : <Figure>{split.folded}</Figure>}
                </div>
              </>
            ) : null}
          </div>
        </ChildRowContext.Provider>
      ) : null}
    </div>
  )
}

/* Compound parts: Sidebar, Sidebar.Head, Sidebar.Group, Sidebar.Row. */
export const Sidebar = Object.assign(SidebarRoot, { Head: SidebarHead, Group: SidebarGroup, Row: SidebarRow })
