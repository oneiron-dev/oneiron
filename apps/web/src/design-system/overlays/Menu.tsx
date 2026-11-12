import * as React from 'react'
import { PickDiamond } from '../marks/PickDiamond'
import { soundPress } from '../lib/press'
import { cx } from '../lib/react-utils'
import { PopoverContent, PopoverRoot, PopoverTrigger, usePopoverContext, type PopoverContentProps, type PopoverProps } from './Popover'

const ITEM_SELECTOR = '[role="menuitem"]:not(:disabled), [role="menuitemradio"]:not(:disabled), [role="menuitemcheckbox"]:not(:disabled)'

export interface MenuContentProps extends PopoverContentProps {
  /* `wide` holds longer rows (an account menu, an invite form). */
  width?: 'default' | 'wide'
}

/* The menu layer. Arrow keys move between items (wrapping), Home and End
   jump, Tab closes and moves on. */
function MenuContent({ className, width = 'default', onKeyDown, children, ...props }: MenuContentProps) {
  const ctx = usePopoverContext('Menu.Content')
  return (
    <PopoverContent
      role="menu"
      className={cx('sl-menu', className)}
      data-width={width}
      initialFocus={ITEM_SELECTOR}
      onKeyDown={(event: React.KeyboardEvent<HTMLDivElement>) => {
        onKeyDown?.(event)
        if (event.defaultPrevented) return
        if (event.key === 'Tab') {
          ctx.setOpen(false)
          return
        }
        if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return
        if ((event.target as HTMLElement).matches('input, textarea')) return
        const items = [...event.currentTarget.querySelectorAll<HTMLElement>(ITEM_SELECTOR)]
        if (!items.length) return
        event.preventDefault()
        const i = items.indexOf(document.activeElement as HTMLElement)
        const next =
          event.key === 'Home'
            ? 0
            : event.key === 'End'
              ? items.length - 1
              : event.key === 'ArrowDown'
                ? (i + 1) % items.length
                : (i - 1 + items.length) % items.length
        items[next].focus()
      }}
      {...props}
    >
      {children}
    </PopoverContent>
  )
}

export interface MenuItemProps extends React.ComponentPropsWithRef<'button'> {
  /* A symbol before the words. */
  icon?: React.ReactNode
  /* Present for a pick among options: the diamond at the end shows it. */
  checked?: boolean
  /* Close the menu after the item acts. On by default. */
  closeOnSelect?: boolean
}

/* One action in a menu. A figure placed among its children sits at the end
   of the row. */
function MenuItem({ icon, checked, closeOnSelect = true, className, type = 'button', onClick, children, ...props }: MenuItemProps) {
  const ctx = usePopoverContext('Menu.Item')
  const pick = checked !== undefined
  return (
    <button
      type={type}
      role={pick ? 'menuitemradio' : 'menuitem'}
      aria-checked={pick ? checked : undefined}
      tabIndex={-1}
      className={cx('sl-menu-item', className)}
      onClick={(event) => {
        onClick?.(event)
        soundPress(event)
        if (closeOnSelect && !event.defaultPrevented) ctx.setOpen(false, { returnFocus: true })
      }}
      {...props}
    >
      {icon ? (
        <span className="sl-menu-item-icon" aria-hidden="true">
          {icon}
        </span>
      ) : null}
      {children}
      {pick ? <PickDiamond chosen={checked} className="sl-menu-item-pick" /> : null}
    </button>
  )
}

export interface MenuHeadingProps extends React.ComponentPropsWithRef<'div'> {}

/* A group head inside the menu. */
function MenuHeading({ className, ...props }: MenuHeadingProps) {
  return <div role="presentation" className={cx('sl-menu-heading', className)} {...props} />
}

export interface MenuSeparatorProps extends React.ComponentPropsWithRef<'div'> {}

/* Space between groups; spacing separates, never a line. */
function MenuSeparator({ className, ...props }: MenuSeparatorProps) {
  return <div role="separator" className={cx('sl-menu-separator', className)} {...props} />
}

export interface MenuLineProps extends React.ComponentPropsWithRef<'div'> {
  icon?: React.ReactNode
}

/* A text line that does not act: a device row, a receipt. A figure among
   its children sits at the end. */
function MenuLine({ icon, className, children, ...props }: MenuLineProps) {
  return (
    <div role="presentation" className={cx('sl-menu-line', className)} {...props}>
      {icon ? (
        <span className="sl-menu-item-icon" aria-hidden="true">
          {icon}
        </span>
      ) : null}
      {children}
    </div>
  )
}

/* Compound parts on Popover: Menu, Menu.Trigger, Menu.Content, Menu.Item,
   Menu.Heading, Menu.Separator, Menu.Line. */
export const Menu = Object.assign(
  function Menu(props: PopoverProps) {
    return <PopoverRoot hasPopup="menu" {...props} />
  },
  {
    Trigger: PopoverTrigger,
    Content: MenuContent,
    Item: MenuItem,
    Heading: MenuHeading,
    Separator: MenuSeparator,
    Line: MenuLine,
  },
)
