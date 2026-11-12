import type { GlyphName } from '~/design-system'

/* Gallery fixtures: each resident's glyph and own colour. Identity colours
   are data a caller supplies, so they live here and not in the tokens. The
   night value is the resident's ink on the dark ground; the day value is
   the same hue darkened to hold on the white wells. */

export interface Resident {
  name: string
  glyph: GlyphName
  ink: string
  /* The face as a picture, by day and at night; a resident without one
     shows its glyph. */
  picture?: { day: string; night: string }
}

const picture = (id: string) => ({ day: `/art/faces/${id}-A-day.png`, night: `/art/faces/${id}-A-night.png` })

export const EIRI: Resident = { name: 'Eiri', glyph: 'wing', ink: 'light-dark(#3D7499, #6FA3C7)', picture: picture('eiri') }
export const TORY: Resident = { name: 'Tory', glyph: 'owl', ink: 'light-dark(#A2475A, #BE687A)', picture: picture('tory') }
export const ANTEVON: Resident = { name: 'Antevon', glyph: 'laurel', ink: 'light-dark(#5F559A, #857BB8)', picture: picture('antevon') }
export const METRYON: Resident = { name: 'Metryon', glyph: 'ruler', ink: 'light-dark(#55697A, #93A6B5)' }

export const RESIDENTS: Resident[] = [EIRI, TORY, ANTEVON, METRYON]
