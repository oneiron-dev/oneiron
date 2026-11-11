import * as React from 'react'
import { soundPress } from '../lib/press'
import { cx } from '../lib/react-utils'

export interface PrimaryButtonProps extends React.ComponentPropsWithRef<'button'> {}

/* The one filled box on a screen. Every other action is a Verb. */
export function PrimaryButton({ className, type = 'button', onClick, ...props }: PrimaryButtonProps) {
  return (
    <button
      type={type}
      className={cx('sl-primary-button', className)}
      onClick={(event) => {
        onClick?.(event)
        soundPress(event)
      }}
      {...props}
    />
  )
}
