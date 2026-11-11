import type { GlyphName } from '~/design-system'

/* Gallery fixtures: each resident's glyph and own colour. Identity colours
   are data a caller supplies, so they live here and not in the tokens. The
   night value is the resident's ink on the dark ground; the day value is
   the same hue darkened to hold on the white wells. */

export interface Resident {
  name: string
  glyph: GlyphName
  ink: string
}

export const EIRI: Resident = { name: 'Eiri', glyph: 'wing', ink: 'light-dark(#3D7499, #6FA3C7)' }
export const TORY: Resident = { name: 'Tory', glyph: 'owl', ink: 'light-dark(#A2475A, #BE687A)' }
export const ANTEVON: Resident = { name: 'Antevon', glyph: 'laurel', ink: 'light-dark(#5F559A, #857BB8)' }
export const METRYON: Resident = { name: 'Metryon', glyph: 'ruler', ink: 'light-dark(#55697A, #93A6B5)' }

export const RESIDENTS: Resident[] = [EIRI, TORY, ANTEVON, METRYON]
