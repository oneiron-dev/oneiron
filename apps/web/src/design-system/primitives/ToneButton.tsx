import * as React from 'react'
import { soundPress } from '../lib/press'
import { cx } from '../lib/react-utils'

export interface ToneButtonProps extends React.ComponentPropsWithRef<'button'> {
  /* A mark at the left of the word: a sign-in provider's own mark. */
  mark?: React.ReactNode
}

/* A full-width button in the chip tone, its word at the say size: a
   choice among equals, such as a sign-in provider. It is not the filled
   box; a screen still has one PrimaryButton. */
export function ToneButton({ mark, className, type = 'button', onClick, children, ...props }: ToneButtonProps) {
  return (
    <button
      type={type}
      className={cx('sl-tone-button', className)}
      onClick={(event) => {
        onClick?.(event)
        soundPress(event)
      }}
      {...props}
    >
      {mark !== undefined ? (
        <span className="sl-tone-button-mark" aria-hidden="true">
          {mark}
        </span>
      ) : null}
      <span className="sl-tone-button-word">{children}</span>
    </button>
  )
}
