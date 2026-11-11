import * as React from 'react'
import { Glyph, Portrait, useResolvedScheme, type PortraitFaceSize } from '~/design-system'
import type { Resident } from './-identity'

/* Faces in the gallery's places: a resident with a picture shows it (the
   night picture in the dark scheme), one without shows its printed glyph,
   and a person shows the initial on a disc. */

export interface Person {
  name: 'Owen' | 'Yuki'
  initial: string
  guest?: boolean
}

export const OWEN: Person = { name: 'Owen', initial: 'o' }
export const YUKI: Person = { name: 'Yuki', initial: 'y', guest: true }

/* Glyph sizes for a face size the glyph does not have. */
const GLYPH_SIZE: Record<PortraitFaceSize, 16 | 18 | 20 | 24 | 32> = { 16: 16, 18: 18, 20: 20, 22: 20, 24: 24, 28: 24, 32: 32 }

export function Face({ who, size }: { who: Resident | Person; size: PortraitFaceSize }) {
  const scheme = useResolvedScheme()
  if ('initial' in who) return <Portrait initial={who.initial} label={who.name} size={size} guest={who.guest} />
  if (who.picture) return <Portrait src={scheme === 'dark' ? who.picture.night : who.picture.day} label={who.name} size={size} />
  return <Glyph glyph={who.glyph} label={who.name} size={GLYPH_SIZE[size]} />
}
