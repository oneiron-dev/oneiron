import { createRouter } from '@tanstack/react-router'
import { routeTree } from './routeTree.gen'
import { DefaultCatchBoundary } from './components/DefaultCatchBoundary'
import { NotFound } from './components/NotFound'
import { createFixtureRuntime } from './runtime/app-runtime'

export function getRouter() {
  const router = createRouter({
    routeTree,
    context: {
      runtime: createFixtureRuntime(import.meta.env.MODE === 'desktop' ? 'desktop' : 'web'),
    },
    defaultPreload: 'intent',
    defaultErrorComponent: DefaultCatchBoundary,
    defaultNotFoundComponent: () => <NotFound />,
    scrollRestoration: true,
  })
  return router
}
