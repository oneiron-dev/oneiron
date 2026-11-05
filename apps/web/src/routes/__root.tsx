/// <reference types="vite/client" />
import { HeadContent, Scripts, createRootRouteWithContext } from '@tanstack/react-router'
import type { AppRouterContext } from '~/runtime/app-runtime'
import * as React from 'react'
import { DefaultCatchBoundary } from '~/components/DefaultCatchBoundary'
import { NotFound } from '~/components/NotFound'
import appCss from '~/styles/app.css?url'
import safelightCss from '~/styles/safelight.css?url'
import desktopChromeCss from '~/styles/desktop-chrome.css?url'
import { seo } from '~/utils/seo'

export const Route = createRootRouteWithContext<AppRouterContext>()({
  head: () => ({
    meta: [
      { charSet: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      /* the browser chrome follows the room (system-follow; a forced
         room via html.light/.dark keeps the system's tint, harmless) */
      { name: 'theme-color', content: '#EBE7DF', media: '(prefers-color-scheme: light)' },
      { name: 'theme-color', content: '#131110', media: '(prefers-color-scheme: dark)' },
      ...seo({
        title: 'oneiron',
        description: 'Memory that shows its work.',
      }),
    ],
    links: [
      { rel: 'stylesheet', href: appCss },
      { rel: 'stylesheet', href: safelightCss },
      { rel: 'stylesheet', href: desktopChromeCss },
      {
        rel: 'preload',
        href: '/fonts/ServerMono-Regular.woff2',
        as: 'font',
        type: 'font/woff2',
        crossOrigin: 'anonymous',
      },
      { rel: 'icon', href: '/favicon.ico' },
    ],
    scripts: [
      /* the fold, the pack folds and the reading room restore before first
         paint · no flash. it mutates <html>, hence suppressHydrationWarning
         below. */
      { src: '/prepaint.js' },
      /* the tuner's math + restore (dev instrument, owner 08-15 eve) */
      { src: '/tune.js' },
      /* cuelume · the house sound (every call site is guarded) */
      { src: '/cuelume.js' },
      /* agentation · visual feedback toolbar (dev tool, vendored bundle) */
      { src: '/agentation.js', defer: true },
    ],
  }),
  errorComponent: DefaultCatchBoundary,
  notFoundComponent: () => <NotFound />,
  shellComponent: RootDocument,
})

function RootDocument({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <HeadContent />
      </head>
      <body className="app">
        <div className="desktop-drag-region" data-tauri-drag-region="" aria-hidden="true" />
        {children}
        <Scripts />
      </body>
    </html>
  )
}
