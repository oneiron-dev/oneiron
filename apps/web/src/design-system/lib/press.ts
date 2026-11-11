import type * as React from 'react'
import { cue, markCued } from '~/components/safelight/hooks'

/* Action buttons sound the press cue. The event is marked so a document
   level press listener elsewhere in the app does not ring it twice. */
export function soundPress(event: React.MouseEvent<HTMLElement>) {
  markCued(event)
  cue('press')
}
