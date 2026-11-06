import { Outlet, createFileRoute, useLocation } from '@tanstack/react-router'
import * as React from 'react'
import { Tuner } from '~/components/dev/Tuner'
import { Ground } from '~/components/safelight/Ground'
import { Palette, ShortcutSheet } from '~/components/safelight/Palette'
import { Rail } from '~/components/safelight/Rail'
import {
  useCommandKey,
  useCuePress,
  useGlobalKeys,
  useHoldKey,
  useSound,
  useTheme,
} from '~/components/safelight/hooks'
import { rememberAppRoute } from '~/runtime/settings-nav'
import chassisCss from '~/styles/chassis.css?url'

export const Route = createFileRoute('/app')({
  head: () => ({
    links: [{ rel: 'stylesheet', href: chassisCss }],
  }),
  component: AppLayout,
})

/* The chassis: the chrome and the rail live bare on the film-black desk,
   the route's pane is the one elevated sheet, and the bottom strip is the
   agent line. */
function AppLayout() {
  const href = useLocation({ select: (l) => l.href })
  React.useEffect(() => rememberAppRoute(href), [href])
  const cycleTheme = useTheme()
  const toggleMute = useSound()
  const [tune, setTune] = React.useState(false)
  const toggleTune = React.useCallback(() => setTune((v) => !v), [])
  const closeTune = React.useCallback(() => setTune(false), [])
  /* ⌘K: the command palette (owner 08-18); holding ⌘ alone shows the keys */
  const [pal, setPal] = React.useState(false)
  const togglePal = React.useCallback(() => setPal((v) => !v), [])
  const openPal = React.useCallback(() => setPal(true), [])
  const closePal = React.useCallback(() => setPal(false), [])
  const keysShown = useHoldKey('Meta', 600)

  /* search is no longer a page you walk to (owner 08-18): the rail's
     search icon knocks with `oneiron:palette` and the same card opens */
  React.useEffect(() => {
    addEventListener('oneiron:palette', openPal)
    return () => removeEventListener('oneiron:palette', openPal)
  }, [openPal])

  useCuePress()
  useCommandKey('k', togglePal)
  /* t / m: theme + sound (their real homes are the settings page);
     ` opens the tuner (dev instrument); / opens the palette, where the
     search and the ask are one field */
  useGlobalKeys({ t: cycleTheme, m: toggleMute, '`': toggleTune, '/': openPal })

  return (
    <>
      <div className="grain" aria-hidden="true"></div>
      <div className="desk-plate" aria-hidden="true"></div>
      <div className="app-frame">
        <Rail />
        <Outlet />
      </div>
      <Ground />
      <Tuner open={tune} onClose={closeTune} />
      <Palette open={pal} onClose={closePal} onTuner={toggleTune} />
      <ShortcutSheet shown={keysShown && !pal} />
    </>
  )
}
