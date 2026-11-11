import * as React from 'react'
import { Icon } from '../primitives/Icon'
import { IconAction } from '../primitives/IconAction'
import { StatusDot, type StatusDotState } from '../marks/StatusDot'
import { cx } from '../lib/react-utils'

export interface ConnectionRowProps extends React.ComponentPropsWithRef<'div'> {
  name: React.ReactNode
  /* Where they come from, under the name: `from Acme's vault`. */
  origin?: React.ReactNode
  /* What the link allows, in about six words. */
  scope: React.ReactNode
  status: StatusDotState
  /* Accessible name of the status dot. */
  statusLabel?: string
  /* A critical class, as a small word at the right: `boundary`, `legal`. */
  tag?: React.ReactNode
  /* IconActions shown on hover and focus (re-scope, disconnect, promote). */
  verbs?: React.ReactNode
  /* A request to connect: accept and reject replace the verbs. */
  onAccept?: () => void
  onReject?: () => void
  acceptLabel?: string
  rejectLabel?: string
}

/* One link to another vault: the name, the scope, a status dot, the class,
   and the verbs on hover. Children run across the full row under it (a
   receipt line, re-scope picks). */
export function ConnectionRow({
  name,
  origin,
  scope,
  status,
  statusLabel,
  tag,
  verbs,
  onAccept,
  onReject,
  acceptLabel = 'Allow',
  rejectLabel = 'Reject',
  className,
  children,
  ...props
}: ConnectionRowProps) {
  const request = !!(onAccept || onReject)
  return (
    <div className={cx('sl-connection-row', className)} data-request={request ? '' : undefined} {...props}>
      <div className="sl-connection-row-grid">
        <span className="sl-connection-name-cell">
          <span className="sl-connection-name">{name}</span>
          {origin ? <span className="sl-connection-origin">{origin}</span> : null}
        </span>
        <span className="sl-connection-scope">{scope}</span>
        <StatusDot state={status} label={statusLabel} />
        <span className="sl-connection-tag">{tag}</span>
        <span className="sl-connection-verbs">
          {request ? (
            <>
              {onAccept ? (
                <IconAction label={acceptLabel} size="sm" onClick={onAccept}>
                  <Icon name="check" />
                </IconAction>
              ) : null}
              {onReject ? (
                <IconAction label={rejectLabel} size="sm" tone="consent" onClick={onReject}>
                  <Icon name="x" />
                </IconAction>
              ) : null}
            </>
          ) : (
            verbs
          )}
        </span>
        {children ? <div className="sl-connection-detail">{children}</div> : null}
      </div>
    </div>
  )
}
