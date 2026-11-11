import * as React from 'react'
import { cx } from '../lib/react-utils'

/* A rounded square (85 wide, corners of radius 10) centred in a 120 box,
   with a round opening of radius 22 at its centre; turned 45 degrees when
   drawn. The even-odd rule cuts the opening, so no mask and no id. */
const MARK_PATH =
  'M27.5 17.5H92.5A10 10 0 0 1 102.5 27.5V92.5A10 10 0 0 1 92.5 102.5H27.5A10 10 0 0 1 17.5 92.5V27.5A10 10 0 0 1 27.5 17.5Z' +
  'M60 38A22 22 0 1 0 60 82A22 22 0 1 0 60 38Z'

export interface BrandMarkProps extends Omit<React.ComponentPropsWithRef<'span'>, 'children'> {
  /* The mark's width and height in CSS pixels. */
  size?: number
  /* The name `oneiron` beside the mark. */
  word?: boolean
}

/* The Oneiron mark: a rounded square turned 45 degrees with a round
   opening, in the colour of its context (currentColor). With `word` the
   name stands beside it. It never animates. */
export function BrandMark({ size = 24, word = false, className, ...props }: BrandMarkProps) {
  return (
    <span
      className={cx('sl-brand-mark', className)}
      data-word={word ? '' : undefined}
      role={word ? undefined : 'img'}
      aria-label={word ? undefined : 'Oneiron'}
      {...props}
    >
      <svg className="sl-brand-mark-symbol" viewBox="0 0 120 120" width={size} height={size} aria-hidden="true" focusable="false">
        <path transform="rotate(45 60 60)" fillRule="evenodd" d={MARK_PATH} />
      </svg>
      {word ? <span className="sl-brand-mark-word">oneiron</span> : null}
    </span>
  )
}
