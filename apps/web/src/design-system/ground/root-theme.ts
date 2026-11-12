import * as React from 'react'
import {
  DEFAULT_THEME,
  SCENE_STAND_IN_COLOUR,
  deriveThemeTones,
  themeSeedFromColour,
  type Theme,
  type ThemeTones,
} from '../lib/theme'

/* What a SafelightRoot tells the parts inside it about its theme: the
   theme, the tones in force by day and at night, and whether a scene's
   pictures have been read (until then its window ground is one flat tone). */
export interface RootTheme {
  theme: Theme
  day: ThemeTones
  night: ThemeTones
  sceneRead: boolean
}

/* The tones of one flat colour, by day and at night. */
export function flatThemeTones(colour: string): Pick<RootTheme, 'day' | 'night'> {
  const seed = themeSeedFromColour(colour)
  return { day: deriveThemeTones(seed, 'day', 'flat'), night: deriveThemeTones(seed, 'night', 'flat') }
}

export const RootThemeContext = React.createContext<RootTheme>({
  theme: DEFAULT_THEME,
  ...flatThemeTones(SCENE_STAND_IN_COLOUR),
  sceneRead: false,
})

/* The theme of the nearest SafelightRoot. */
export function useRootTheme(): RootTheme {
  return React.useContext(RootThemeContext)
}
