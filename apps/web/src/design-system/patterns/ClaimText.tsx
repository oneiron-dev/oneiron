import * as React from 'react'
import { cx } from '../lib/react-utils'
import { claimInk } from './claim-ink'

export interface ClaimTextProps extends React.ComponentPropsWithRef<'span'> {
  /* How sure the memory is, 0 to 1. */
  confidence: number
}

/* A claim printed on the ink ladder by its confidence: the surer, the
   darker the print (ink-1 at 0.9 and up, down to ink-4 below 0.4). */
export function ClaimText({ confidence, className, ...props }: ClaimTextProps) {
  return <span className={cx('sl-claim-text', className)} data-ink={claimInk(confidence)} {...props} />
}
