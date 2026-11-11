import { SafelightRoot, THEMES, WindowGround, type Theme } from '~/design-system'
import { Section, Specimen } from './-gallery-frame'

/* Themes in the gallery: the built-in flat themes, and one scene made from
   art the app already has (the field, its day and its night picture). */

export const FIELD_SCENE: Theme = {
  id: 'field',
  label: 'field',
  kind: 'scene',
  day: '/art/field-day.png',
  night: '/art/field-night.png',
}

export const GALLERY_THEMES: Theme[] = [...THEMES, FIELD_SCENE]

/* Each theme's window ground on a small stage, its name in the ground ink. */
export function WindowGroundSection() {
  return (
    <Section title="WindowGround">
      {GALLERY_THEMES.map((theme) => (
        <Specimen key={theme.id} name={theme.kind === 'scene' ? `${theme.label}: a scene, printed` : `${theme.label}: flat`}>
          <SafelightRoot theme={theme} className="lib-ground-stage" data-specimen={`ground-${theme.id}`}>
            <WindowGround />
            <span className="lib-ground-word">{theme.label}</span>
          </SafelightRoot>
        </Specimen>
      ))}
    </Section>
  )
}
