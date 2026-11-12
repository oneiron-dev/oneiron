import * as React from 'react'
import { cx } from '../lib/react-utils'

export interface GuestRingProps extends Omit<React.ComponentPropsWithRef<'span'>, 'children'> {
  /* Accessible name when the ring stands alone; decorative without one. */
  label?: string
}

/* The person mark: a small ring in the outside hue, set at a glyph's corner
   (or inline after a count). It says this one comes from another vault. */
export function GuestRing({ label, className, ...props }: GuestRingProps) {
  return (
    <span
      className={cx('sl-guest-ring', className)}
      role={label ? 'img' : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
      {...props}
    />
  )
}
