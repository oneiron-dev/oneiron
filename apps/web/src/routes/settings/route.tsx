import { Link, Outlet, createFileRoute, useLocation, useNavigate } from '@tanstack/react-router'
import * as React from 'react'
import { Ground } from '~/components/safelight/Ground'
import { Palette, ShortcutSheet } from '~/components/safelight/Palette'
import { useCommandKey, useCuePress, useGlobalKeys, useHoldKey, useSound, useTheme } from '~/components/safelight/hooks'
import { DEFAULT_APP_ROUTE, lastAppRoute } from '~/runtime/settings-nav'
import chassisCss from '~/styles/chassis.css?url'
import settingsCss from '~/styles/settings-area.css?url'
import { EscLayers, VAULT_NAME, type EscLayer } from './-shared'

export const Route = createFileRoute('/settings')({
  head: () => ({
    links: [
      { rel: 'stylesheet', href: chassisCss },
      { rel: 'stylesheet', href: settingsCss },
    ],
  }),
  component: SettingsLayout,
})

/* ── the settings area (ruling 8, the Linear model): its own left nav on
   the desk, one page per section on the sheet. the app chassis is
   mirrored (grain, plate, the agent line stays mounted so a live run
   never vanishes); the rail is not here. ── */
const NAV: { label: string; rows: { to: string; name: string }[] }[] = [
  {
    label: 'you',
    rows: [
      { to: '/settings/account', name: 'account' },
      { to: '/settings/appearance', name: 'appearance' },
    ],
  },
  {
    label: `vault · ${VAULT_NAME}`,
    rows: [
      { to: '/settings/vault', name: 'vault' },
      { to: '/settings/members', name: 'members' },
      { to: '/settings/billing', name: 'billing' },
      { to: '/settings/connectors', name: 'connectors' },
      { to: '/settings/grants', name: 'grants' },
      { to: '/settings/packs', name: 'packs' },
      { to: '/settings/export', name: 'export' },
      { to: '/settings/forget', name: 'forget' },
    ],
  },
]

function BackArrow() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M10 3.5 5.5 8l4.5 4.5" />
    </svg>
  )
}

function SettingsLayout() {
  const cycleTheme = useTheme()
  const toggleMute = useSound()
  const navigate = useNavigate()
  const pathname = useLocation({ select: (l) => l.pathname })
  const navRef = React.useRef<HTMLElement>(null)
  const layers = React.useRef(new Set<EscLayer>())

  const [returnTo, setReturnTo] = React.useState(DEFAULT_APP_ROUTE)
  React.useEffect(() => setReturnTo(lastAppRoute()), [])
  const [pal, setPal] = React.useState(false)
  const togglePal = React.useCallback(() => setPal((v) => !v), [])
  const openPal = React.useCallback(() => setPal(true), [])
  const closePal = React.useCallback(() => setPal(false), [])
  const keysShown = useHoldKey('Meta', 600)

  React.useEffect(() => {
    addEventListener('oneiron:palette', openPal)
    return () => removeEventListener('oneiron:palette', openPal)
  }, [openPal])
  const back = React.useCallback(() => {
    navigate({ href: lastAppRoute() })
  }, [navigate])

  useCuePress()
  useCommandKey('k', togglePal)
  /* Same search card and keys as the app; no tuner or rail here. */
  useGlobalKeys({ t: cycleTheme, m: toggleMute, '/': openPal })

  /* the esc ladder (spec §2): text field → blur, keep the text; something
     open → close it; nothing open → back to app. the agent line closes
     its own panel first. */
  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape' || e.defaultPrevented || e.isComposing || e.repeat || e.metaKey || e.ctrlKey || e.altKey) return
      /* Use the open state, not only the DOM: the palette may already be
         closing in another listener on this same key event. */
      if (pal) return
      const el = document.activeElement as HTMLElement | null
      if (el && (/^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName) || el.isContentEditable)) {
        el.blur()
        return
      }
      /* the agent line and the palette own their own Escape */
      if (document.querySelector('.gsheet.on, .amenu:not([hidden]), .hmenu:not([hidden]), .palette:not([hidden])'))
        return
      /* the newest open layer closes first */
      let top: EscLayer | null = null
      for (const layer of layers.current) {
        if (layer.isOpen() && (!top || layer.order() > top.order())) top = layer
      }
      if (top) {
        top.close()
        return
      }
      back()
    }
    addEventListener('keydown', onKey)
    return () => removeEventListener('keydown', onKey)
  }, [back, pal])

  /* keyboard in the snav: ↑/↓ walk the rows (labels are not rows), → into
     the page's first control; ← from the page returns to the snav */
  const onNavKey = (e: React.KeyboardEvent) => {
    if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return
    const rows = Array.from(navRef.current?.querySelectorAll<HTMLElement>('a[data-row]') ?? [])
    const i = rows.indexOf(document.activeElement as HTMLElement)
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault()
      const n = e.key === 'ArrowDown' ? Math.min(rows.length - 1, i + 1) : Math.max(0, i - 1)
      rows[n]?.focus()
    } else if (e.key === 'ArrowRight') {
      e.preventDefault()
      const first = document.querySelector<HTMLElement>(
        '#pane .pane-body a[href], #pane .pane-body button:not([disabled]), #pane .pane-body input, #pane .pane-body [tabindex="0"]',
      )
      first?.focus()
    }
  }
  const onPaneKey = (e: React.KeyboardEvent) => {
    if (e.key !== 'ArrowLeft' || e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return
    const t = e.target as HTMLElement
    if (/^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName) || t.isContentEditable) return
    if (t.closest('table, [role="group"]')) return
    e.preventDefault()
    const active = navRef.current?.querySelector<HTMLElement>('a[aria-current="page"]') ?? navRef.current?.querySelector<HTMLElement>('a[data-row]')
    active?.focus()
  }

  return (
    <EscLayers.Provider value={layers}>
      <div className="grain" aria-hidden="true"></div>
      <div className="desk-plate" aria-hidden="true"></div>
      <div className="app-frame settings-frame">
        <nav className="snav" aria-label="settings" ref={navRef} onKeyDown={onNavKey}>
          <a
            className="back"
            data-row
            href={returnTo}
            title="back to where you were · esc"
            onClick={(e) => {
              if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
              e.preventDefault()
              back()
            }}
          >
            <BackArrow />
            <span>back to app</span>
          </a>
          {NAV.map((g) => (
            <div className="group" key={g.label}>
              <span className="label">{g.label}</span>
              {g.rows.map((r) => {
                /* /settings/usage is the meters' alias: it lights billing */
                const on =
                  pathname.startsWith(r.to) ||
                  (r.name === 'billing' && pathname.startsWith('/settings/usage')) ||
                  (r.name === 'account' && (pathname === '/settings' || pathname === '/settings/'))
                return (
                  <Link
                    key={r.to}
                    to={r.to as never}
                    activeProps={{}}
                    data-row
                    className={on ? 'active' : undefined}
                    aria-current={on ? 'page' : undefined}
                  >
                    {r.name}
                  </Link>
                )
              })}
            </div>
          ))}
        </nav>
        <div className="sheet-slot" onKeyDown={onPaneKey}>
          <Outlet />
        </div>
      </div>
      <Ground />
      <Palette open={pal} onClose={closePal} />
      <ShortcutSheet shown={keysShown && !pal} includeRail={false} />
    </EscLayers.Provider>
  )
}
