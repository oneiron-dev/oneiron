import * as React from 'react'
import { Slot, cx, useControllableState, useSafeId } from '../lib/react-utils'

interface UnfoldContextValue {
  open: boolean
  setOpen: (open: boolean) => void
  contentId: string
}

const UnfoldContext = React.createContext<UnfoldContextValue | null>(null)

function useUnfoldContext(part: string): UnfoldContextValue {
  const ctx = React.useContext(UnfoldContext)
  if (!ctx) throw new Error(`${part} must be inside Unfold`)
  return ctx
}

export interface UnfoldProps extends React.ComponentPropsWithRef<'div'> {
  open?: boolean
  defaultOpen?: boolean
  onOpenChange?: (open: boolean) => void
}

/* Opens and closes in place: the row grows with its detail and its
   neighbours hold. */
function UnfoldRoot({ open: openProp, defaultOpen = false, onOpenChange, className, ...props }: UnfoldProps) {
  const [open, setOpen] = useControllableState(openProp, defaultOpen, onOpenChange)
  const contentId = useSafeId('sl-unfold')
  const ctx = React.useMemo(() => ({ open, setOpen, contentId }), [open, setOpen, contentId])
  return (
    <UnfoldContext.Provider value={ctx}>
      <div className={cx('sl-unfold-root', className)} data-state={open ? 'open' : 'closed'} {...props} />
    </UnfoldContext.Provider>
  )
}

export interface UnfoldTriggerProps extends React.ComponentPropsWithRef<'button'> {
  /* Render the single child element as the trigger (a Verb, a row). */
  asChild?: boolean
}

function UnfoldTrigger({ asChild, type = 'button', className, onClick, children, ...props }: UnfoldTriggerProps) {
  const ctx = useUnfoldContext('Unfold.Trigger')
  const triggerProps = {
    'aria-expanded': ctx.open,
    'aria-controls': ctx.contentId,
    'data-state': ctx.open ? 'open' : 'closed',
    onClick: (event: React.MouseEvent<HTMLButtonElement>) => {
      onClick?.(event)
      if (!event.defaultPrevented) ctx.setOpen(!ctx.open)
    },
    ...props,
  }
  if (asChild) return <Slot {...triggerProps} className={className}>{children}</Slot>
  return (
    <button type={type} className={cx('sl-unfold-trigger', className)} {...triggerProps}>
      {children}
    </button>
  )
}

export interface UnfoldContentProps extends React.ComponentPropsWithRef<'div'> {}

/* The detail. Rows animate 0fr to 1fr and back on the same curve; closed
   content is inert. */
function UnfoldContent({ className, children, ...props }: UnfoldContentProps) {
  const ctx = useUnfoldContext('Unfold.Content')
  return (
    <div
      id={ctx.contentId}
      className={cx('sl-unfold', className)}
      data-state={ctx.open ? 'open' : 'closed'}
      {...props}
    >
      <div className="sl-unfold-inner" inert={!ctx.open} aria-hidden={!ctx.open}>
        {children}
      </div>
    </div>
  )
}

/* Compound parts: Unfold, Unfold.Trigger, Unfold.Content. */
export const Unfold = Object.assign(UnfoldRoot, { Trigger: UnfoldTrigger, Content: UnfoldContent })
