import { createFileRoute, redirect } from '@tanstack/react-router'

/* /app/packs moved into the settings area (ruling 8): this path only redirects */
export const Route = createFileRoute('/app/packs')({
  beforeLoad: () => {
    throw redirect({ href: '/settings/packs' })
  },
})
