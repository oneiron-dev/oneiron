import * as React from 'react'
import { cx } from '../lib/react-utils'

export interface SafelightRootProps extends React.ComponentPropsWithRef<'div'> {}

/* Wraps a screen: carries the tokens (.sl-root), the base type, the focus
   ring and the selection colour. The colour scheme follows the app's theme
   switch through the class on <html>. */
export function SafelightRoot({ className, ...props }: SafelightRootProps) {
  return <div className={cx('sl-root', className)} {...props} />
}
