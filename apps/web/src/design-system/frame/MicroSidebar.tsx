import * as React from 'react'
import { Menu } from '../overlays/Menu'
import { usePopoverContext } from '../overlays/Popover'
import { Tooltip } from '../overlays/Tooltip'
import { StatusDot } from '../marks/StatusDot'
import { Figure } from '../primitives/Figure'
import { Icon } from '../primitives/Icon'
import { cx, mergeRefs, mergeSlotProps, useIsomorphicLayoutEffect } from '../lib/react-utils'
import { AppFrameContext } from './app-frame-context'
import { useReorder } from './use-reorder'

/* A press held this long on a touch screen opens a pinned item's menu. */
const LONG_PRESS_MS = 500
/* A touch that travels this far is a scroll, not a long press. */
const LONG_PRESS_SLOP_PX = 8

/* ── the root ───────────────────────────────────────────────────────────── */

interface MicroSidebarContextValue {
  labels: 'none' | 'word'
  announce: (message: string) => void
}

const MicroSidebarContext = React.createContext<MicroSidebarContextValue | null>(null)

function useMicroSidebar(part: string): MicroSidebarContextValue {
  const ctx = React.useContext(MicroSidebarContext)
  if (!ctx) throw new Error(`${part} must be inside a MicroSidebar`)
  return ctx
}

/* True inside MicroSidebar.Pinned: its items are list items that reorder. */
const PinnedContext = React.createContext(false)

export interface MicroSidebarProps extends React.ComponentPropsWithRef<'nav'> {
  /* `none`: the symbol alone, its name in a tooltip. `word`: a small word
     under each symbol. */
  labels?: 'none' | 'word'
  /* `field`: bare on the printed field, in the on-field inks. `paper`: on
     a near-opaque strip of the ground. */
  ground?: 'field' | 'paper'
}

/* The narrow strip at the far left that never hides: the places a person
   goes to, one symbol each. Children: MicroSidebar.Item, .Divider,
   .Pinned, and one .Foot at the bottom. */
function MicroSidebarRoot({
  labels = 'none',
  ground = 'field',
  className,
  children,
  'aria-label': ariaLabel = 'places',
  ...props
}: MicroSidebarProps) {
  const [message, setMessage] = React.useState('')
  const parts = React.Children.toArray(children)
  const feet = parts.filter((c) => React.isValidElement(c) && c.type === MicroSidebarFoot)
  const items = parts.filter((c) => !feet.includes(c))
  const ctx = React.useMemo(() => ({ labels, announce: setMessage }), [labels])

  return (
    <MicroSidebarContext.Provider value={ctx}>
      <nav
        aria-label={ariaLabel}
        className={cx('sl-micro-sidebar', className)}
        data-labels={labels}
        data-ground={ground}
        {...props}
      >
        <div className="sl-micro-sidebar-items">{items}</div>
        {feet}
        <span className="sl-micro-sidebar-status" role="status">
          {message}
        </span>
      </nav>
    </MicroSidebarContext.Provider>
  )
}

/* ── an item ────────────────────────────────────────────────────────────── */

/* Inside a Menu with an anchor: hands back a function that opens it with
   focus in the menu, as a press on a trigger would. */
function MenuOpener({ handle }: { handle: React.RefObject<(() => void) | null> }) {
  const popover = usePopoverContext('MicroSidebar.Item')
  useIsomorphicLayoutEffect(() => {
    handle.current = () => popover.setOpen(true, { focusContent: true, returnFocus: true })
    return () => {
      handle.current = null
    }
  })
  return null
}

export interface MicroSidebarItemProps extends Omit<React.ComponentPropsWithRef<'button'>, 'id' | 'children'> {
  /* Names the item: for the frame's peek (`peek(id)`) and for reordering
     inside MicroSidebar.Pinned. */
  id?: string
  /* The symbol: an Icon, or a Glyph in its line form. */
  icon: React.ReactNode
  /* The place's name: the tooltip, or the word under the symbol. */
  label: string
  /* The place on screen now: one tone step. */
  current?: boolean
  /* A badge figure at the symbol's corner. */
  count?: number | string
  /* Something there waits on the person: the waiting ring at the corner. */
  needsYou?: boolean
  /* Render the single child element (a router link) as the item. */
  asChild?: boolean
  children?: React.ReactElement
  /* Inside MicroSidebar.Pinned: right-click or a long press opens a small
     menu with `unpin`. */
  onUnpin?: () => void
}

function MicroSidebarItem({
  ref,
  id,
  icon,
  label,
  current = false,
  count,
  needsYou = false,
  asChild = false,
  onUnpin,
  className,
  children,
  type = 'button',
  onKeyDown,
  onContextMenu,
  ...props
}: MicroSidebarItemProps) {
  const micro = useMicroSidebar('MicroSidebar.Item')
  const pinned = React.useContext(PinnedContext)
  const frame = React.useContext(AppFrameContext)
  const controlRef = React.useRef<HTMLElement | null>(null)
  const openMenu = React.useRef<(() => void) | null>(null)
  const press = React.useRef<{ timer: ReturnType<typeof setTimeout>; x: number; y: number } | null>(null)
  const peeking = !!frame && !!id && frame.peekId === id

  React.useEffect(() => () => clearTimeout(press.current?.timer), [])

  const name = `${label}${count !== undefined ? `, ${count}` : ''}${needsYou ? ', waits on you' : ''}`
  const content = (
    <>
      <span className="sl-micro-item-mark" aria-hidden="true">
        {icon}
        {count !== undefined ? (
          <Figure size="badge" className="sl-micro-item-count">
            {count}
          </Figure>
        ) : null}
        {needsYou ? <StatusDot state="waiting" className="sl-micro-item-needs" /> : null}
      </span>
      {micro.labels === 'word' ? (
        <span className="sl-micro-item-word" aria-hidden="true">
          {label}
        </span>
      ) : null}
    </>
  )
  const own = {
    ref: mergeRefs(ref as React.Ref<HTMLElement>, controlRef),
    className: cx('sl-micro-item-control', className),
    'aria-label': name,
    'aria-current': current ? ('page' as const) : undefined,
    'data-current': current ? '' : undefined,
    'data-has-count': count !== undefined ? '' : undefined,
    draggable: false,
    onKeyDown: (event: React.KeyboardEvent<HTMLElement>) => {
      onKeyDown?.(event as React.KeyboardEvent<HTMLButtonElement>)
      if (!event.defaultPrevented && frame && id) frame.itemKeyDown(id, event)
    },
    onContextMenu: (event: React.MouseEvent<HTMLElement>) => {
      onContextMenu?.(event as React.MouseEvent<HTMLButtonElement>)
      if (event.defaultPrevented || !onUnpin) return
      event.preventDefault()
      openMenu.current?.()
    },
    ...props,
  }
  let control: React.ReactElement
  if (asChild && React.isValidElement(children)) {
    const child = children as React.ReactElement<Record<string, unknown>>
    control = React.cloneElement(child, mergeSlotProps(own, child.props), content)
  } else {
    control = (
      <button type={type} {...(own as React.ComponentPropsWithRef<'button'>)}>
        {content}
      </button>
    )
  }
  if (micro.labels === 'none') {
    control = (
      <Tooltip label={label} side="right" open={peeking ? false : undefined}>
        {control}
      </Tooltip>
    )
  }

  const clearPress = () => {
    clearTimeout(press.current?.timer)
    press.current = null
  }

  return (
    <div
      role={pinned ? 'listitem' : undefined}
      className="sl-micro-item"
      data-micro-sidebar-id={id}
      data-reorder-label={label}
      onPointerEnter={frame && id ? (event) => frame.itemPointerEnter(id, event) : undefined}
      onPointerLeave={(event) => {
        clearPress()
        if (frame && id) frame.itemPointerLeave(id, event)
      }}
      onPointerDown={(event) => {
        if (frame && id) frame.itemPointerDown(id, event)
        if (onUnpin && event.pointerType === 'touch') {
          clearPress()
          press.current = {
            x: event.clientX,
            y: event.clientY,
            timer: setTimeout(() => {
              press.current = null
              openMenu.current?.()
            }, LONG_PRESS_MS),
          }
        }
      }}
      onPointerMove={(event) => {
        const p = press.current
        if (p && Math.hypot(event.clientX - p.x, event.clientY - p.y) > LONG_PRESS_SLOP_PX) clearPress()
      }}
      onPointerUp={clearPress}
      onPointerCancel={clearPress}
    >
      {control}
      {onUnpin ? (
        <Menu anchorRef={controlRef}>
          <MenuOpener handle={openMenu} />
          <Menu.Content side="right" align="start" aria-label={`${label}, pinned`} data-reorder-ignore="">
            <Menu.Item icon={<Icon name="pin" />} onClick={onUnpin}>
              unpin
            </Menu.Item>
          </Menu.Content>
        </Menu>
      ) : null}
    </div>
  )
}

/* ── the divider, the pinned group, the foot ────────────────────────────── */

export interface MicroSidebarDividerProps extends React.ComponentPropsWithRef<'div'> {}

/* A short hairline between the fixed places and the pinned ones. */
function MicroSidebarDivider({ className, ...props }: MicroSidebarDividerProps) {
  return <div role="separator" className={cx('sl-micro-sidebar-divider', className)} {...props} />
}

export interface MicroSidebarPinnedProps extends React.ComponentPropsWithRef<'div'> {
  /* The person reordered the pinned items (drag one, or Alt+ArrowUp /
     Alt+ArrowDown on it). Each item needs an `id`; the caller renders the
     new order. */
  onReorder?: (ids: string[]) => void
}

/* The places the person pinned, under the divider: they reorder, and each
   unpins from its own small menu. */
function MicroSidebarPinned({
  ref,
  onReorder,
  className,
  children,
  'aria-label': ariaLabel = 'pinned',
  ...props
}: MicroSidebarPinnedProps) {
  const micro = useMicroSidebar('MicroSidebar.Pinned')
  const reorder = useReorder<HTMLDivElement>({
    itemAttribute: 'data-micro-sidebar-id',
    onReorder,
    announce: micro.announce,
  })
  return (
    <PinnedContext.Provider value={true}>
      <div
        role="list"
        aria-label={ariaLabel}
        className={cx('sl-micro-sidebar-pinned', className)}
        {...props}
        ref={mergeRefs(ref, reorder.containerRef)}
        {...reorder.containerProps}
      >
        {children}
      </div>
    </PinnedContext.Provider>
  )
}

export interface MicroSidebarFootProps extends React.ComponentPropsWithRef<'div'> {}

/* The bottom of the strip: the person's portrait (a MicroSidebar.Item
   whose symbol is their Glyph, opening the account menu). */
function MicroSidebarFoot({ className, ...props }: MicroSidebarFootProps) {
  return <div className={cx('sl-micro-sidebar-foot', className)} {...props} />
}

/* Compound parts: MicroSidebar, .Item, .Divider, .Pinned, .Foot. */
export const MicroSidebar = Object.assign(MicroSidebarRoot, {
  Item: MicroSidebarItem,
  Divider: MicroSidebarDivider,
  Pinned: MicroSidebarPinned,
  Foot: MicroSidebarFoot,
})
