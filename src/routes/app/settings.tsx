import { createFileRoute, redirect } from '@tanstack/react-router'

/* /app/settings moved into the settings area (ruling 8): this path only
   redirects. #account and the rest land on the same door. */
export const Route = createFileRoute('/app/settings')({
  beforeLoad: () => {
    throw redirect({ href: '/settings/account' })
  },
})
