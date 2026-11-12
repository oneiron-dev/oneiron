import * as React from 'react'
import { Tooltip } from '../overlays/Tooltip'
import { Icon } from '../primitives/Icon'
import { cx } from '../lib/react-utils'

export interface PinMarkProps extends Omit<React.ComponentPropsWithRef<'span'>, 'children'> {
  /* The tooltip and the accessible name. */
  label?: string
}

/* The pin after a message's time: the message is pinned in its room. A
   mark, not a control; place it in MessageRow's `marks`. */
export function PinMark({ label = 'Pinned in this room', className, ...props }: PinMarkProps) {
  return (
    <Tooltip label={label}>
      <span role="img" aria-label={label} className={cx('sl-pin-mark', className)} {...props}>
        <Icon name="pin" size={14} />
      </span>
    </Tooltip>
  )
}
