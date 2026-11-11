import * as React from 'react'
import { PickDiamond } from '../marks/PickDiamond'
import { Figure } from '../primitives/Figure'
import { Verb } from '../primitives/Verb'
import { cx } from '../lib/react-utils'
import { MessageRow } from './MessageRow'

export type SettledState = 'answered' | 'approved' | 'allowed once' | 'denied' | 'expired'

export interface SettledCardProps extends React.ComponentPropsWithRef<'div'> {
  /* The asker's mark: a Glyph. */
  asker?: React.ReactNode
  /* The question or the request, one serif line. */
  question: React.ReactNode
  /* The pick that settled it, shown with a filled diamond. */
  pick?: React.ReactNode
  state: SettledState
  /* When it settled (or lapsed), as a figure. */
  time?: string
  dateTime?: string
  /* Shows `retry` on an expired card. */
  onRetry?: () => void
}

/* A question or approval that has been answered and stays in the thread:
   the question line, then the pick with a filled diamond, the state word
   and the time. An expired card offers `retry`; SettledCard.Missed says
   what did not happen, SettledCard.Detail unfolds what the request does. */
function SettledCardRoot({
  asker,
  question,
  pick,
  state,
  time,
  dateTime,
  onRetry,
  className,
  children,
  ...props
}: SettledCardProps) {
  const expired = state === 'expired'
  return (
    <div className={cx('sl-settled', className)} data-state={state} {...props}>
      <p className="sl-settled-question">
        {asker ? <span className="sl-settled-asker">{asker}</span> : null}
        <span>{question}</span>
      </p>
      <div className="sl-settled-answer">
        {pick !== undefined && !expired ? (
          <span className="sl-settled-pick">
            <PickDiamond chosen />
            {pick}
          </span>
        ) : null}
        <span className="sl-settled-word">{state}</span>
        {time ? (
          <Figure as="time" dateTime={dateTime}>
            {time}
          </Figure>
        ) : null}
        {expired && onRetry ? (
          <Verb className="sl-settled-retry" onClick={onRetry}>
            retry
          </Verb>
        ) : null}
      </div>
      {children}
    </div>
  )
}

export interface SettledCardMissedProps extends React.ComponentPropsWithRef<'p'> {}

/* On an expired card: what did not happen, in one line. */
function SettledCardMissed({ className, ...props }: SettledCardMissedProps) {
  return <p className={cx('sl-settled-missed', className)} {...props} />
}

export interface SettledCardDetailProps extends Omit<React.ComponentPropsWithRef<'div'>, 'onChange'> {
  /* The folded line; `what this does` by default. */
  summary?: React.ReactNode
  open?: boolean
  defaultOpen?: boolean
  onOpenChange?: (open: boolean) => void
  /* Shows `view full request` at the end of the detail. */
  onViewRequest?: () => void
}

/* A fold under the card: what the request does, then `view full request`. */
function SettledCardDetail({
  summary = 'what this does',
  open,
  defaultOpen,
  onOpenChange,
  onViewRequest,
  className,
  children,
  ...props
}: SettledCardDetailProps) {
  return (
    <MessageRow.Fold
      summary={summary}
      open={open}
      defaultOpen={defaultOpen}
      onOpenChange={onOpenChange}
      className={cx('sl-settled-detail', className)}
      {...props}
    >
      {children}
      {onViewRequest ? (
        <Verb className="sl-settled-view" onClick={onViewRequest}>
          view full request
        </Verb>
      ) : null}
    </MessageRow.Fold>
  )
}

/* Compound parts: SettledCard, .Missed, .Detail. */
export const SettledCard = Object.assign(SettledCardRoot, { Missed: SettledCardMissed, Detail: SettledCardDetail })
