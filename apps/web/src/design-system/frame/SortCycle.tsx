import * as React from 'react'
import { IconAction, type IconActionProps } from '../primitives/IconAction'
import { Icon } from '../primitives/Icon'
import { cx, useControllableState } from '../lib/react-utils'

export interface SortCycleOption {
  value: string
  /* Names the order: `most urgent first`. */
  label: string
}

export interface SortCycleProps
  extends Omit<IconActionProps, 'label' | 'caption' | 'value' | 'defaultValue' | 'children'> {
  options: SortCycleOption[]
  value?: string
  defaultValue?: string
  onValueChange?: (value: string) => void
}

/* One icon action that steps through sort orders, wrapping round. Its
   tooltip names the order in force. */
export function SortCycle({ options, value: valueProp, defaultValue, onValueChange, className, onClick, ...props }: SortCycleProps) {
  const [value, setValue] = useControllableState(valueProp, defaultValue ?? options[0]?.value ?? '', onValueChange)
  const index = Math.max(0, options.findIndex((o) => o.value === value))
  const current = options[index]
  return (
    <IconAction
      label={current ? `Sorted ${current.label}` : 'Sort'}
      className={cx('sl-sort-cycle', className)}
      data-value={current?.value}
      onClick={(event) => {
        onClick?.(event)
        if (event.defaultPrevented || !options.length) return
        setValue(options[(index + 1) % options.length].value)
      }}
      {...props}
    >
      <Icon name="sort" />
    </IconAction>
  )
}
