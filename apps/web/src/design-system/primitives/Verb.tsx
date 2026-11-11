import * as React from 'react'
import { soundPress } from '../lib/press'
import { cx } from '../lib/react-utils'

export interface VerbProps extends React.ComponentPropsWithRef<'button'> {
  /* `consent` arms the safelight red on hover and focus only: the verb
     commits something that needs the person's consent. */
  tone?: 'plain' | 'consent'
}

/* A plain serif word that acts: the word says what happens. */
export function Verb({ className, tone = 'plain', type = 'button', onClick, ...props }: VerbProps) {
  return (
    <button
      type={type}
      className={cx('sl-verb', className)}
      data-tone={tone}
      onClick={(event) => {
        onClick?.(event)
        soundPress(event)
      }}
      {...props}
    />
  )
}
