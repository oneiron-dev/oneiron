import { Outlet, createFileRoute, useNavigate } from '@tanstack/react-router'
import * as React from 'react'
import { Tuner } from '~/components/dev/Tuner'
import { Ground } from '~/components/safelight/Ground'
import { Rail } from '~/components/safelight/Rail'
import { useCuePress, useGlobalKeys, useSound, useTheme } from '~/components/safelight/hooks'
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
  const cycleTheme = useTheme()
  const toggleMute = useSound()
  const navigate = useNavigate()
  /* the rail owns search: / is the door to recall from anywhere */
  const goRecall = React.useCallback(() => {
    if (location.pathname !== '/app/recall') navigate({ to: '/app/recall' })
  }, [navigate])
  const [tune, setTune] = React.useState(false)
  const toggleTune = React.useCallback(() => setTune((v) => !v), [])
  const closeTune = React.useCallback(() => setTune(false), [])

  useCuePress()
  /* t / m: theme + sound (their real homes are the settings page);
     ` opens the tuner (dev instrument) */
  useGlobalKeys({ t: cycleTheme, m: toggleMute, '`': toggleTune, '/': goRecall })

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
    </>
  )
}
