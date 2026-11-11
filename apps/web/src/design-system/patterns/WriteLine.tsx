import * as React from 'react'
import { cx, useControllableState } from '../lib/react-utils'

export interface WriteLineProps
  extends Omit<React.ComponentPropsWithRef<'input'>, 'value' | 'defaultValue' | 'onChange' | 'type'> {
  value?: string
  defaultValue?: string
  onValueChange?: (value: string) => void
  /* Called with the trimmed text on Enter; the line then clears. Empty
     text does not send. */
  onSend?: (text: string) => void
}

/* One line to write (to a task, or a reply in a thread). Enter sends and
   clears the line, Escape leaves the field (and goes on to the part around
   it), empty text does not send. The placeholder stays on one line and
   ends in an ellipsis. */
export function WriteLine({
  value: valueProp,
  defaultValue = '',
  onValueChange,
  onSend,
  placeholder = 'Write a reply',
  className,
  onKeyDown,
  'aria-label': ariaLabel,
  ...props
}: WriteLineProps) {
  const [value, setValue] = useControllableState(valueProp, defaultValue, onValueChange)
  return (
    <input
      type="text"
      className={cx('sl-write-line', className)}
      aria-label={ariaLabel ?? placeholder}
      placeholder={placeholder}
      autoComplete="off"
      value={value}
      onChange={(event) => setValue(event.target.value)}
      onKeyDown={(event) => {
        onKeyDown?.(event)
        if (event.defaultPrevented || event.nativeEvent.isComposing) return
        if (event.key === 'Escape') {
          event.currentTarget.blur()
          return
        }
        if (event.key !== 'Enter') return
        /* Enter never submits a form around the line. */
        event.preventDefault()
        const text = value.trim()
        if (!text) return
        onSend?.(text)
        setValue('')
      }}
      {...props}
    />
  )
}
