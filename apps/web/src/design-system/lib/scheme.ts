import * as React from 'react'

export type Scheme = 'light' | 'dark'

/* The scheme in force: a class on <html> forces one (the app's theme switch
   writes html.light or html.dark), otherwise the system preference decides. */
export function resolveScheme(): Scheme {
  const c = document.documentElement.classList
  if (c.contains('light')) return 'light'
  if (c.contains('dark')) return 'dark'
  return matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

function subscribe(onChange: () => void) {
  const media = matchMedia('(prefers-color-scheme: dark)')
  media.addEventListener('change', onChange)
  const observer = new MutationObserver(onChange)
  observer.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
  return () => {
    media.removeEventListener('change', onChange)
    observer.disconnect()
  }
}

/* The resolved scheme, kept current. null during server rendering and the
   hydration pass, so painters wait for the client. */
export function useResolvedScheme(): Scheme | null {
  return React.useSyncExternalStore(subscribe, resolveScheme, () => null)
}
