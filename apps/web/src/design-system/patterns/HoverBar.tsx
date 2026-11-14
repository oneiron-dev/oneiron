import * as React from 'react'
import { cx, mergeRefs, useIsomorphicLayoutEffect } from '../lib/react-utils'
import { rovingMoveForKey, rovingTarget, setRovingStop } from '../lib/roving-focus'

export interface HoverBarProps extends React.ComponentPropsWithRef<'div'> {}

const ACTION_SELECTOR = 'button:not(:disabled), a[href]'

/* The bar's own actions, in order: the controls inside it, without those
   in a layer it opened (the items of its `more` menu). */
export function toolbarActions(bar: Pick<HTMLElement, 'querySelectorAll' | 'contains'>): HTMLElement[] {
  return [...bar.querySelectorAll<HTMLElement>(ACTION_SELECTOR)].filter((action) => {
    const layer = action.closest('[popover]')
    return !layer || !bar.contains(layer)
  })
}

/* The actions of a row as icons (react, reply, forward, save, more), shown
   on the row's hover after a short delay and hidden at once when the
   pointer leaves. Keyboard focus shows it at once. A toolbar: one tab stop
   (the action focused last, the first at the start); Left and Right move
   between its actions and wrap, Home and End go to the ends. Children are
   IconActions (tooltipSide="top"). */
export function HoverBar({ ref, className, onKeyDown, onFocus, 'aria-label': ariaLabel = 'actions', ...props }: HoverBarProps) {
  const barRef = React.useRef<HTMLDivElement | null>(null)
  /* The action that holds the tab stop. */
  const stop = React.useRef<HTMLElement | null>(null)

  /* Keep one stop as actions come and go (a disabled action, a menu that
     mounts its trigger later). */
  useIsomorphicLayoutEffect(() => {
    const bar = barRef.current
    if (!bar) return
    const sync = () => {
      const actions = toolbarActions(bar)
      setRovingStop(actions, stop.current ? actions.indexOf(stop.current) : 0)
    }
    sync()
    if (typeof MutationObserver === 'undefined') return
    const observer = new MutationObserver(sync)
    observer.observe(bar, { childList: true, subtree: true, attributes: true, attributeFilter: ['disabled'] })
    return () => observer.disconnect()
  }, [])

  return (
    <div
      ref={mergeRefs(ref, barRef)}
      role="toolbar"
      aria-label={ariaLabel}
      className={cx('sl-hover-bar', className)}
      onFocus={(event) => {
        onFocus?.(event)
        const actions = toolbarActions(event.currentTarget)
        const i = actions.indexOf(event.target as HTMLElement)
        if (i < 0) return
        stop.current = actions[i]
        setRovingStop(actions, i)
      }}
      onKeyDown={(event) => {
        onKeyDown?.(event)
        const move = rovingMoveForKey(event.key)
        if (event.defaultPrevented || !move) return
        const actions = toolbarActions(event.currentTarget)
        /* Keys from inside an opened menu are the menu's. */
        const i = actions.indexOf(event.target as HTMLElement)
        if (i < 0) return
        event.preventDefault()
        actions[rovingTarget(move, i, actions.length)]?.focus()
      }}
      {...props}
    />
  )
}
