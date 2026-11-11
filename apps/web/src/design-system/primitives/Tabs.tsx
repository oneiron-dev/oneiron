import * as React from 'react'
import { Figure } from './Figure'
import { cx, useControllableState, useSafeId } from '../lib/react-utils'

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

export interface TabsListProps extends React.ComponentPropsWithRef<'div'> {}

/* The row of tabs. Left and Right move focus and select (wrapping); Home and
   End jump to the ends. Only the selected tab is in the tab order. */
function TabsList({ className, onKeyDown, ...props }: TabsListProps) {
  const ctx = useTabsContext('Tabs.List')
  return (
    <div
      role="tablist"
      className={cx('sl-tabs-list', className)}
      onKeyDown={(event) => {
        onKeyDown?.(event)
        if (event.defaultPrevented) return
        if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return
        const tabs = [...event.currentTarget.querySelectorAll<HTMLButtonElement>('[role="tab"]:not(:disabled)')]
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
    />
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

/* Compound parts: Tabs, Tabs.List, Tabs.Tab, Tabs.Panel. */
export const Tabs = Object.assign(TabsRoot, { List: TabsList, Tab: TabsTab, Panel: TabsPanel })
