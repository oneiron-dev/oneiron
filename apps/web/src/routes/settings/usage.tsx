import { createFileRoute } from '@tanstack/react-router'
import { BillingPage } from './billing'

/* /settings/usage: the meters live on billing (spec §3, one page); this
   path is the chip menu's `usage` door and lands on the same sheet. */
export const Route = createFileRoute('/settings/usage')({
  component: BillingPage,
})
