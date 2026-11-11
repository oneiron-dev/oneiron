import * as React from 'react'
import { Figure } from '../primitives/Figure'
import { Icon } from '../primitives/Icon'
import { IconAction } from '../primitives/IconAction'
import { Verb } from '../primitives/Verb'
import { cx, useControllableState } from '../lib/react-utils'

export interface VersionSwitchProps extends Omit<React.ComponentPropsWithRef<'div'>, 'defaultValue' | 'onChange'> {
  /* How many versions the reply has. */
  count?: number
  /* The version on screen, 1 to count; the newest by default. */
  value?: number
  defaultValue?: number
  onValueChange?: (value: number) => void
  /* Shows `try again`. */
  onTryAgain?: () => void
}

const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v))

/* Under the newest reply only: `try again`, and once the reply has more
   than one version, a step back, the version as a figure (`2 of 2`) and a
   step on. While the newest version is on screen, a new one takes its
   place on screen as it arrives. */
export function VersionSwitch({
  count = 1,
  value: valueProp,
  defaultValue,
  onValueChange,
  onTryAgain,
  className,
  'aria-label': ariaLabel = 'versions of this reply',
  ...props
}: VersionSwitchProps) {
  const [value, setValue] = useControllableState(valueProp, defaultValue ?? count, onValueChange)
  const shown = clamp(Math.round(value), 1, Math.max(1, count))

  const previousCount = React.useRef(count)
  React.useEffect(() => {
    const before = previousCount.current
    previousCount.current = count
    if (valueProp === undefined && count > before && value === before) setValue(count)
  }, [count, value, valueProp, setValue])

  return (
    <div role="group" aria-label={ariaLabel} className={cx('sl-version-switch', className)} {...props}>
      {onTryAgain ? <Verb onClick={onTryAgain}>try again</Verb> : null}
      {count > 1 ? (
        <span className="sl-version-step">
          <IconAction label="Earlier version" size="sm" tooltipSide="top" disabled={shown <= 1} onClick={() => setValue(shown - 1)}>
            <Icon name="chevron" className="sl-version-back" />
          </IconAction>
          <Figure aria-live="polite" className="sl-version-value">
            {shown} of {count}
          </Figure>
          <IconAction label="Later version" size="sm" tooltipSide="top" disabled={shown >= count} onClick={() => setValue(shown + 1)}>
            <Icon name="chevron" className="sl-version-on" />
          </IconAction>
        </span>
      ) : null}
    </div>
  )
}
