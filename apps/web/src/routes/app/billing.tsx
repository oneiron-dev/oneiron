import { createFileRoute, redirect } from '@tanstack/react-router'

/* /app/billing moved into the settings area (ruling 8): this path only redirects */
export const Route = createFileRoute('/app/billing')({
  beforeLoad: () => {
    throw redirect({ href: '/settings/billing' })
  },
})
