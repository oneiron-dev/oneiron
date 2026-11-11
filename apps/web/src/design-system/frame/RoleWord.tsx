import * as React from 'react'
import { Popover, type PopoverContentProps } from '../overlays/Popover'
import { cx } from '../lib/react-utils'

export interface RoleWordProps extends Omit<React.ComponentPropsWithRef<'button'>, 'children'> {
  /* The role's name, shown as the word. */
  name: string
  /* What the role may do, in one line: the read-only popover says it. */
  job?: React.ReactNode
  /* With it the word opens its children (a RolePicker); without it the
     word opens a read-only card of what the role may do. */
  canChange?: boolean
  open?: boolean
  defaultOpen?: boolean
  onOpenChange?: (open: boolean) => void
  side?: PopoverContentProps['side']
  align?: PopoverContentProps['align']
  /* The RolePicker (with canChange), or more read-only lines after the job. */
  children?: React.ReactNode
}

/* A person's role as a plain word that opens a popover: the role picker
   for someone who may change it, or what the role may do for everyone
   else. */
export function RoleWord({
  name,
  job,
  canChange = false,
  open,
  defaultOpen,
  onOpenChange,
  side = 'bottom',
  align = 'end',
  className,
  children,
  ...props
}: RoleWordProps) {
  return (
    <Popover open={open} defaultOpen={defaultOpen} onOpenChange={onOpenChange}>
      <Popover.Trigger className={cx('sl-role-word', className)} data-can-change={canChange ? '' : undefined} {...props}>
        {name}
        {canChange ? (
          <svg className="sl-role-word-chevron" viewBox="0 0 10 10" aria-hidden="true" focusable="false">
            <path d="M2 3.5 L5 6.5 L8 3.5" />
          </svg>
        ) : null}
      </Popover.Trigger>
      <Popover.Content
        side={side}
        align={align}
        aria-label={canChange ? `role of this person: ${name}` : name}
        className={cx('sl-role-pop', canChange ? null : 'sl-role-card')}
      >
        {canChange ? (
          children
        ) : (
          <>
            <p className="sl-role-card-name">{name}</p>
            {job !== undefined ? <p className="sl-role-card-job">{job}</p> : null}
            {children}
          </>
        )}
      </Popover.Content>
    </Popover>
  )
}
