import * as React from 'react'
import { Icon } from '../primitives/Icon'
import { Unfold } from '../primitives/Unfold'
import { cx } from '../lib/react-utils'

export interface OutsideLineProps extends Omit<React.ComponentPropsWithRef<'div'>, 'onChange'> {
  /* The folded line, in the outside hue: `Guests see what you send here`. */
  summary: React.ReactNode
  open?: boolean
  defaultOpen?: boolean
  onOpenChange?: (open: boolean) => void
}

/* One folded line above a write box in a shared place. It unfolds the
   guests present, grouped by the vault they come from
   (OutsideLine.Group, OutsideLine.Guest). It stays: nothing dismisses it. */
function OutsideLineRoot({ summary, open, defaultOpen, onOpenChange, className, children, ...props }: OutsideLineProps) {
  return (
    <Unfold open={open} defaultOpen={defaultOpen} onOpenChange={onOpenChange} className={cx('sl-outside-line', className)} {...props}>
      <Unfold.Trigger className="sl-outside-line-head">
        <Icon name="chevron" size={12} className="sl-fold-chevron" />
        <span>{summary}</span>
      </Unfold.Trigger>
      <Unfold.Content>
        <div className="sl-outside-line-panel">{children}</div>
      </Unfold.Content>
    </Unfold>
  )
}

export interface OutsideLineGroupProps extends React.ComponentPropsWithRef<'div'> {
  /* The vault the guests come from. */
  origin: React.ReactNode
}

function OutsideLineGroup({ origin, className, children, ...props }: OutsideLineGroupProps) {
  return (
    <div role="group" className={cx('sl-outside-line-group', className)} {...props}>
      <span className="sl-outside-line-origin">{origin}</span>
      {children}
    </div>
  )
}

export interface OutsideLineGuestProps extends React.ComponentPropsWithRef<'span'> {
  /* The guest's mark: a Glyph with its ring. */
  glyph: React.ReactNode
}

/* One guest: the mark and the name, nothing more. */
function OutsideLineGuest({ glyph, className, children, ...props }: OutsideLineGuestProps) {
  return (
    <span className={cx('sl-outside-line-guest', className)} {...props}>
      {glyph}
      <span>{children}</span>
    </span>
  )
}

/* Compound parts: OutsideLine, .Group, .Guest. */
export const OutsideLine = Object.assign(OutsideLineRoot, { Group: OutsideLineGroup, Guest: OutsideLineGuest })
