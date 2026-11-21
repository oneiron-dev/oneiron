import * as React from 'react'
import { cx } from '../lib/react-utils'
import { pagePictures, readScene } from '../lib/scene'
import {
  DEFAULT_THEME,
  SCENE_STAND_IN_COLOUR,
  deriveThemeTones,
  themeProperties,
  type Theme,
  type ThemeSeed,
} from '../lib/theme'
import { RootThemeContext, flatThemeTones, type RootTheme } from './root-theme'

export interface SafelightRootProps extends React.ComponentPropsWithRef<'div'> {
  /* A flat colour or a scene; deep sea by default. */
  theme?: Theme
}

interface SceneSeeds {
  day: string
  night: string
  daySeed: ThemeSeed
  nightSeed: ThemeSeed
}

/* A scene's two seeds, read from its pictures in the browser; null on the
   server, while the pictures load, for a flat theme, and for a scene with
   a picture from another host (it keeps the stand-in). */
function useSceneSeeds(theme: Theme): SceneSeeds | null {
  const pictures = pagePictures(theme)
  const day = pictures?.day ?? null
  const night = pictures?.night ?? null
  const [seeds, setSeeds] = React.useState<SceneSeeds | null>(null)
  React.useEffect(() => {
    if (!day || !night) return
    let alive = true
    Promise.all([readScene(day), readScene(night)])
      .then(([d, n]) => {
        if (alive) setSeeds({ day, night, daySeed: d.seed, nightSeed: n.seed })
      })
      .catch(() => {
        /* without its pictures the scene keeps the flat stand-in */
      })
    return () => {
      alive = false
    }
  }, [day, night])
  return seeds && seeds.day === day && seeds.night === night ? seeds : null
}

/* Wraps a screen: carries the tokens (.sl-root), the base type, the focus
   ring and the selection colour, and the theme's tones as custom
   properties: the window ground in both modes and, at night, the sheet's
   tones turned toward the theme's hue. The colour scheme follows the app's
   theme switch through the class on <html>. A flat theme's tones are in
   the server's markup; a scene's come once its pictures are read, and
   until then the ground is one flat tone. */
export function SafelightRoot({ theme = DEFAULT_THEME, className, style, ...props }: SafelightRootProps) {
  const scene = useSceneSeeds(theme)
  const value = React.useMemo<RootTheme>(() => {
    if (scene) {
      return {
        theme,
        day: deriveThemeTones(scene.daySeed, 'day', 'scene'),
        night: deriveThemeTones(scene.nightSeed, 'night', 'scene'),
        sceneRead: true,
      }
    }
    return {
      theme,
      ...flatThemeTones(theme.kind === 'flat' ? theme.colour : SCENE_STAND_IN_COLOUR),
      sceneRead: false,
    }
  }, [theme, scene])
  const properties = themeProperties(value.day, value.night)
  return (
    <RootThemeContext.Provider value={value}>
      <div
        className={cx('sl-root', className)}
        data-sl-theme={theme.id}
        style={{ ...properties, ...style } as React.CSSProperties}
        {...props}
      />
    </RootThemeContext.Provider>
  )
}
