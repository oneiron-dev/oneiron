import * as React from 'react'
import { cx } from '../lib/react-utils'

export interface PickDiamondProps extends Omit<React.ComponentPropsWithRef<'svg'>, 'children'> {
  chosen?: boolean
}

/* The pick: the aperture diamond, hollow at rest, filled when chosen. A
   drawn shape, so its weight never depends on a font. It also fills inside
   a control that reports aria-pressed or aria-checked as true. */
export function PickDiamond({ chosen = false, className, ...props }: PickDiamondProps) {
  return (
    <svg
      className={cx('sl-pick-diamond', className)}
      viewBox="0 0 10 10"
      data-chosen={chosen ? '' : undefined}
      aria-hidden="true"
      focusable="false"
      {...props}
    >
      <path d="M5 .8 9.2 5 5 9.2 .8 5Z" />
    </svg>
  )
}
