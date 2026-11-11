import * as React from 'react'
import { Tooltip } from '../overlays/Tooltip'
import type { Side } from '../lib/placement'
import { soundPress } from '../lib/press'
import { cx } from '../lib/react-utils'

export interface IconActionProps extends Omit<React.ComponentPropsWithRef<'button'>, 'aria-label'> {
  /* The action's name: its accessible name and the tooltip's first line. */
  label: string
  /* One caption line under the name in the tooltip. */
  caption?: string
  size?: 'md' | 'sm'
  tone?: 'plain' | 'consent'
  tooltipSide?: Side
}

/* A frequent tool action drawn as a symbol (the child), named by its
   tooltip. */
export function IconAction({
  label,
  caption,
  size = 'md',
  tone = 'plain',
  tooltipSide = 'bottom',
  className,
  type = 'button',
  onClick,
  ...props
}: IconActionProps) {
  return (
    <Tooltip label={label} caption={caption} side={tooltipSide}>
      <button
        type={type}
        aria-label={label}
        className={cx('sl-icon-action', className)}
        data-size={size}
        data-tone={tone}
        onClick={(event) => {
          onClick?.(event)
          soundPress(event)
        }}
        {...props}
      />
    </Tooltip>
  )
}
