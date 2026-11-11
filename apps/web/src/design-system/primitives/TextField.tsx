import * as React from 'react'
import { cx, useControllableState, useSafeId } from '../lib/react-utils'

export interface TextFieldProps extends Omit<React.ComponentPropsWithRef<'input'>, 'value' | 'defaultValue' | 'size'> {
  value?: string
  defaultValue?: string
  /* Every change of the text, controlled or not. */
  onValueChange?: (value: string) => void
  /* A label above the field; pressing it focuses the field. Without one,
     name the field with aria-label. */
  label?: React.ReactNode
}

/* One line of text input in the sunk tone with a 1 px inset hairline (one
   ink step darker while focused). Controlled (`value`, `onValueChange`)
   or not (`defaultValue`). The class name goes to the wrapper; the ref
   and the other props (name, type, autoComplete, aria-*) go to the input.
   On a touch screen the text takes the section size, so the browser does
   not zoom into the field. */
export function TextField({
  ref,
  value: valueProp,
  defaultValue = '',
  onValueChange,
  label,
  className,
  id,
  type = 'text',
  onChange,
  ...props
}: TextFieldProps) {
  const [value, setValue] = useControllableState(valueProp, defaultValue, onValueChange)
  const ownId = useSafeId('sl-text-field')
  const inputId = id ?? ownId
  return (
    <div className={cx('sl-text-field', className)}>
      {label !== undefined ? (
        <label htmlFor={inputId} className="sl-text-field-label">
          {label}
        </label>
      ) : null}
      <input
        ref={ref}
        id={inputId}
        type={type}
        className="sl-text-field-input"
        value={value}
        onChange={(event) => {
          onChange?.(event)
          setValue(event.target.value)
        }}
        {...props}
      />
    </div>
  )
}
