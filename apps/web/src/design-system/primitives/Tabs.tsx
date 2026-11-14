import * as React from 'react'
import { Figure } from './Figure'
import { Icon, type IconName } from './Icon'
import { IconAction } from './IconAction'
import { Tooltip } from '../overlays/Tooltip'
import { soundPress } from '../lib/press'
import { cx, mergeRefs, useControllableState, useIsomorphicLayoutEffect, useSafeId } from '../lib/react-utils'

interface TabsContextValue {
  value: string
  setValue: (value: string) => void
  baseId: string
}

const TabsContext = React.createContext<TabsContextValue | null>(null)

function useTabsContext(part: string): TabsContextValue {
  const ctx = React.useContext(TabsContext)
  if (!ctx) throw new Error(`${part} must be inside Tabs`)
  return ctx
}

/* Values become part of element ids. */
const idPart = (value: string) => value.replace(/[^a-zA-Z0-9_-]/g, '_')

/* What a pin says about itself in its tooltip, after who pinned it. */
export const PIN_NOTE = 'Everyone here sees it, and the agents working in this room keep it in view.'

/* The pins, the divider and the add action fold into one tab when the list
   is narrower than its content: `needed` is the content's width measured
   unfolded, `available` the list's own width. */
export function pinsFold(available: number, needed: number): boolean {
  return needed > available + 0.5
}

/* Pressing a pin: a pinned view is selected; a pinned message is not a
   view, so pressing it goes to the message and selects nothing. */
export function pinPress(pin: { value?: string; onGo?: unknown }): 'select' | 'go' {
  return pin.onGo ? 'go' : 'select'
}

type TabsValueProps =
  | { value: string; defaultValue?: never; onValueChange?: (value: string) => void }
  | { value?: never; defaultValue: string; onValueChange?: (value: string) => void }

export type TabsProps = TabsValueProps & Omit<React.ComponentPropsWithRef<'div'>, 'defaultValue'>

/* Views of the same thing. */
function TabsRoot({ value: valueProp, defaultValue, onValueChange, className, ...props }: TabsProps) {
  const [value, setValue] = useControllableState(valueProp, defaultValue ?? '', onValueChange)
  const baseId = useSafeId('sl-tabs')
  const ctx = React.useMemo(() => ({ value, setValue, baseId }), [value, setValue, baseId])
  return (
    <TabsContext.Provider value={ctx}>
      <div className={cx('sl-tabs', className)} {...props} />
    </TabsContext.Provider>
  )
}

export interface TabsListProps extends React.ComponentPropsWithRef<'div'> {
  /* The value of the pinned list. With it, when the list is narrower than
     its content, the pins (Tabs.Pin), Tabs.Divider and Tabs.Add fold into
     one tab, the pin symbol and the count of pins, that selects it. */
  foldValue?: string
  /* The folded tab's tooltip and accessible name. */
  foldLabel?: string
}

/* The row of tabs. Left and Right move focus and select (wrapping); Home and
   End jump to the ends. Only the selected tab is in the tab order. The
   element with role tablist holds only tabs: a Tabs.Add among the children
   is drawn after it, in the same row, where the last pin ends. */
function TabsList({ ref, foldValue, foldLabel = 'Pinned in this room', className, onKeyDown, children, ...props }: TabsListProps) {
  const ctx = useTabsContext('Tabs.List')
  const listRef = React.useRef<HTMLDivElement | null>(null)
  const rowRef = React.useRef<HTMLDivElement | null>(null)
  const parts = React.Children.toArray(children)
  const adds = parts.filter((c) => React.isValidElement(c) && c.type === TabsAdd)
  const tabs = adds.length ? parts.filter((c) => !adds.includes(c)) : parts
  const pins = parts.filter(
    (c): c is React.ReactElement<TabsPinProps> => React.isValidElement(c) && c.type === TabsPin,
  )
  const pinValues = pins.map((p) => p.props.value).filter((v): v is string => v !== undefined)
  /* The pins as one string: when they change, the content is measured again. */
  const signature = pins.map((p) => `${p.key ?? ''}:${p.props.value ?? ''}`).join('|')
  const canFold = foldValue !== undefined && pins.length > 0

  const [folded, setFolded] = React.useState(false)
  const foldedRef = React.useRef(false)
  foldedRef.current = folded
  const needed = React.useRef(Infinity)

  /* New pins: unfold, so the next pass measures them. */
  useIsomorphicLayoutEffect(() => {
    setFolded(false)
  }, [signature])

  /* With an add action after the list, the row holds both and is what
     is measured. */
  useIsomorphicLayoutEffect(() => {
    const list = rowRef.current ?? listRef.current
    if (!canFold || !list) return
    let alive = true
    const check = () => {
      if (!alive) return
      if (!foldedRef.current) {
        const content = list.scrollWidth
        if (pinsFold(list.clientWidth, content)) {
          needed.current = content
          setFolded(true)
        }
      } else if (!pinsFold(list.clientWidth, needed.current)) {
        setFolded(false)
      }
    }
    check()
    document.fonts?.ready.then(check)
    if (typeof ResizeObserver === 'undefined') return () => void (alive = false)
    const observer = new ResizeObserver(check)
    observer.observe(list)
    return () => {
      alive = false
      observer.disconnect()
    }
  }, [canFold, signature, folded])

  const isFolded = canFold && folded
  const foldSelected = foldValue !== undefined && (ctx.value === foldValue || (isFolded && pinValues.includes(ctx.value)))

  const list = (
    <div
      ref={mergeRefs(ref, listRef)}
      role="tablist"
      className={cx('sl-tabs-list', className)}
      data-folded={isFolded ? '' : undefined}
      onKeyDown={(event) => {
        onKeyDown?.(event)
        if (event.defaultPrevented) return
        if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return
        /* Only the tabs on screen: folded pins are skipped. */
        const tabs = [...event.currentTarget.querySelectorAll<HTMLButtonElement>('[role="tab"]:not(:disabled)')].filter(
          (tab) => tab.getClientRects().length > 0,
        )
        if (!tabs.length) return
        event.preventDefault()
        const i = tabs.indexOf(document.activeElement as HTMLButtonElement)
        const next =
          event.key === 'Home'
            ? 0
            : event.key === 'End'
              ? tabs.length - 1
              : event.key === 'ArrowRight'
                ? (i + 1) % tabs.length
                : (i - 1 + tabs.length) % tabs.length
        const tab = tabs[next]
        tab.focus()
        const value = tab.dataset.value
        if (value !== undefined) ctx.setValue(value)
      }}
      {...props}
    >
      {tabs}
      {canFold ? (
        <Tooltip label={foldLabel}>
          <button
            type="button"
            role="tab"
            id={`${ctx.baseId}-tab-${idPart(foldValue)}`}
            aria-label={`${foldLabel}, ${pins.length}`}
            aria-selected={foldSelected}
            aria-controls={`${ctx.baseId}-panel-${idPart(foldValue)}`}
            tabIndex={foldSelected ? 0 : -1}
            data-value={foldValue}
            data-state={foldSelected ? 'active' : 'inactive'}
            className="sl-tab sl-tab-fold"
            onClick={() => ctx.setValue(foldValue)}
          >
            <Icon name="pin" size={16} />
            <Figure>{pins.length}</Figure>
          </button>
        </Tooltip>
      ) : null}
    </div>
  )
  if (!adds.length) return list
  return (
    <div ref={rowRef} className="sl-tabs-row" data-folded={isFolded ? '' : undefined}>
      {list}
      {adds}
    </div>
  )
}

export interface TabsTabProps extends Omit<React.ComponentPropsWithRef<'button'>, 'value'> {
  value: string
  /* A count after the name, as a figure. */
  count?: number | string
}

function TabsTab({ value, count, className, type = 'button', onClick, children, ...props }: TabsTabProps) {
  const ctx = useTabsContext('Tabs.Tab')
  const selected = ctx.value === value
  return (
    <button
      type={type}
      role="tab"
      id={`${ctx.baseId}-tab-${idPart(value)}`}
      aria-selected={selected}
      aria-controls={`${ctx.baseId}-panel-${idPart(value)}`}
      tabIndex={selected ? 0 : -1}
      data-value={value}
      data-state={selected ? 'active' : 'inactive'}
      className={cx('sl-tab', className)}
      onClick={(event) => {
        onClick?.(event)
        if (!event.defaultPrevented) ctx.setValue(value)
      }}
      {...props}
    >
      {children}
      {count !== undefined ? <Figure>{count}</Figure> : null}
    </button>
  )
}

type TabsPinTarget =
  | { /* A pinned view of the room (a file, a lens): selected like a tab. */ value: string; onGo?: never }
  | { /* A pinned message: pressing it goes to the message. */ onGo: () => void; value?: never }

export type TabsPinProps = TabsPinTarget &
  Omit<React.ComponentPropsWithRef<'button'>, 'value'> & {
    /* The kind's symbol at 16 px. */
    icon?: IconName
    /* A portrait at 16 px instead, for a pinned message. */
    mark?: React.ReactNode
    /* Who pinned it, for the tooltip's first line. */
    pinnedBy: string
    /* The tooltip's sentence. */
    note?: string
  }

/* A tab for a pinned thing: its kind symbol (or the portrait of a pinned
   message's writer) and its name, cut at 17 characters. The tooltip says
   who pinned it and what a pin does. A pinned message is not a view: it
   never becomes selected; pressing it calls onGo. */
function TabsPin({ value, onGo, icon, mark, pinnedBy, note = PIN_NOTE, className, type = 'button', onClick, children, ...props }: TabsPinProps) {
  const ctx = useTabsContext('Tabs.Pin')
  const goes = pinPress({ value, onGo }) === 'go'
  const selected = !goes && ctx.value === value
  return (
    <Tooltip label={`Pinned by ${pinnedBy}`} caption={note}>
      <button
        type={type}
        role="tab"
        id={goes ? undefined : `${ctx.baseId}-tab-${idPart(value ?? '')}`}
        aria-selected={selected}
        aria-controls={goes ? undefined : `${ctx.baseId}-panel-${idPart(value ?? '')}`}
        tabIndex={selected ? 0 : -1}
        data-value={goes ? undefined : value}
        data-state={selected ? 'active' : 'inactive'}
        data-pin={goes ? 'message' : 'view'}
        data-pin-part=""
        className={cx('sl-tab sl-tab-pin', className)}
        onClick={(event) => {
          onClick?.(event)
          if (event.defaultPrevented) return
          if (goes) {
            soundPress(event)
            onGo?.()
          } else if (value !== undefined) ctx.setValue(value)
        }}
        {...props}
      >
        {mark !== undefined ? (
          <span className="sl-tab-pin-mark">{mark}</span>
        ) : icon ? (
          <Icon name={icon} size={16} />
        ) : null}
        <span className="sl-tab-pin-name">{children}</span>
      </button>
    </Tooltip>
  )
}

export interface TabsDividerProps extends Omit<React.ComponentPropsWithRef<'span'>, 'children'> {}

/* A 16 px hairline between the fixed tabs and the pins. */
function TabsDivider({ className, ...props }: TabsDividerProps) {
  return <span aria-hidden="true" data-pin-part="" className={cx('sl-tabs-divider', className)} {...props} />
}

export interface TabsAddProps extends Omit<React.ComponentPropsWithRef<'button'>, 'children'> {
  label?: string
}

/* The `+` at the end of the pins. Place it last among Tabs.List's
   children; the list draws it after its tabs, outside the tablist. */
function TabsAdd({ label = 'Pin a message, a file or a lens to this room', className, ...props }: TabsAddProps) {
  return (
    <IconAction label={label} className={cx('sl-tabs-add', className)} data-pin-part="" {...props}>
      <Icon name="plus" />
    </IconAction>
  )
}

export interface TabsPanelProps extends React.ComponentPropsWithRef<'div'> {
  value: string
}

function TabsPanel({ value, className, ...props }: TabsPanelProps) {
  const ctx = useTabsContext('Tabs.Panel')
  const selected = ctx.value === value
  return (
    <div
      role="tabpanel"
      id={`${ctx.baseId}-panel-${idPart(value)}`}
      aria-labelledby={`${ctx.baseId}-tab-${idPart(value)}`}
      hidden={!selected}
      tabIndex={0}
      data-state={selected ? 'active' : 'inactive'}
      className={cx('sl-tab-panel', className)}
      {...props}
    />
  )
}

/* Compound parts: Tabs, Tabs.List, Tabs.Tab, Tabs.Pin, Tabs.Divider,
   Tabs.Add, Tabs.Panel. */
export const Tabs = Object.assign(TabsRoot, {
  List: TabsList,
  Tab: TabsTab,
  Pin: TabsPin,
  Divider: TabsDivider,
  Add: TabsAdd,
  Panel: TabsPanel,
})
