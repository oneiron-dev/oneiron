import { Outlet, createFileRoute } from '@tanstack/react-router'
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

  useCuePress()
  /* t / m: theme + sound (their real homes are the settings page) */
  useGlobalKeys({ t: cycleTheme, m: toggleMute })

  return (
    <>
      <div className="grain" aria-hidden="true"></div>
      <div className="app-frame">
        <Rail />
        <Outlet />
      </div>
      <Ground />
    </>
  )
}
