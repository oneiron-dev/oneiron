import { createFileRoute, redirect } from '@tanstack/react-router'

/* /settings opens on you: account (spec §1 · the normal-person default) */
export const Route = createFileRoute('/settings/')({
  beforeLoad: () => {
    throw redirect({ to: '/settings/account' as never })
  },
})
