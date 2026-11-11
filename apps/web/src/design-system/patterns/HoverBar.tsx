import * as React from 'react'
import { cx } from '../lib/react-utils'

export interface HoverBarProps extends React.ComponentPropsWithRef<'div'> {}

/* The actions of a row as icons (react, reply, forward, save, more), shown
   on the row's hover after a short delay and hidden at once when the
   pointer leaves. Keyboard focus shows it at once; Left and Right move
   between its actions. Children are IconActions (tooltipSide="top"). */
export function HoverBar({ className, onKeyDown, 'aria-label': ariaLabel = 'actions', ...props }: HoverBarProps) {
  return (
    <div
      role="toolbar"
      aria-label={ariaLabel}
      className={cx('sl-hover-bar', className)}
      onKeyDown={(event) => {
        onKeyDown?.(event)
        if (event.defaultPrevented || (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft')) return
        const actions = [...event.currentTarget.querySelectorAll<HTMLElement>('button:not(:disabled)')]
        const i = actions.indexOf(document.activeElement as HTMLElement)
        if (i < 0 || !actions.length) return
        event.preventDefault()
        const step = event.key === 'ArrowRight' ? 1 : actions.length - 1
        actions[(i + step) % actions.length].focus()
      }}
      {...props}
    />
  )
}
