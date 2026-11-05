export const APP_ROUTE_KEY = 'oneiron-app-route'
export const DEFAULT_APP_ROUTE = '/app/inbox'

type RouteStorage = Pick<Storage, 'getItem' | 'setItem'>

function sessionStore(): RouteStorage | undefined {
  try {
    return typeof window === 'undefined' ? undefined : window.sessionStorage
  } catch {
    return undefined
  }
}

/* Real app screens only. In particular, settings/billing/packs are legacy
   redirects back into Settings and must never become its return address. */
const APP_SCREENS = new Set([
  '/app/inbox', '/app/vault', '/app/agents', '/app/pipeline', '/app/today',
  '/app/orgs', '/app/notes', '/app/briefs', '/app/tasks', '/app/threads',
  '/app/lens/supplier-watch', '/app/recall',
])

export function validAppRoute(value: unknown): string | null {
  if (typeof value !== 'string' || value.length > 4096) return null
  try {
    /* Reject malformed encoding and control/backslash URL ambiguities before
       interpreting any component. Do not repair or resolve arbitrary URLs. */
    if (/[\u0000-\u0020\u007f\\]/.test(value) || /[\u0000-\u001f\u007f\\]/.test(decodeURIComponent(value))) return null
  } catch {
    return null
  }
  const [path] = value.split(/[?#]/)
  const pathname = path.endsWith('/') ? path.slice(0, -1) : path
  if (!APP_SCREENS.has(pathname)) return null

  /* Keep only state that the destination actually reads. Unknown keys (such
     as next/redirect) are not a navigation contract and are never retained. */
  const hashAt = value.indexOf('#')
  const beforeHash = hashAt < 0 ? value : value.slice(0, hashAt)
  const fragment = hashAt < 0 ? '' : value.slice(hashAt + 1)
  const queryAt = beforeHash.indexOf('?')
  const search = new URLSearchParams(queryAt < 0 ? '' : beforeHash.slice(queryAt + 1))
  const kept = new URLSearchParams()
  if (pathname === '/app/recall' && search.get('q')) kept.set('q', search.get('q')!)
  if (pathname === '/app/agents') {
    const room = search.get('with')
    if (room && ['eiri', 'tory', 'antevon', 'house', 'new'].includes(room)) kept.set('with', room)
  }
  if (pathname === '/app/today') {
    const at = search.get('at')
    if (at && /^(?:[01]?\d|2[0-3]):[0-5]\d$/.test(at)) kept.set('at', at)
  }
  if (['/app/inbox', '/app/tasks', '/app/notes'].includes(pathname) && search.has('empty')) {
    kept.set('empty', '')
  }
  const query = kept.toString()
  const hash = /^[a-zA-Z][a-zA-Z0-9_-]*$/.test(fragment) ? `#${fragment}` : ''
  return `${pathname}${query ? `?${query}` : ''}${hash}`
}

export function lastAppRoute(storage = sessionStore()): string {
  try {
    return validAppRoute(storage?.getItem(APP_ROUTE_KEY)) ?? DEFAULT_APP_ROUTE
  } catch {
    return DEFAULT_APP_ROUTE
  }
}

export function rememberAppRoute(value: string, storage = sessionStore()): void {
  const route = validAppRoute(value)
  if (!route) return
  try {
    storage?.setItem(APP_ROUTE_KEY, route)
  } catch {
    /* unavailable storage must not block navigation */
  }
}
