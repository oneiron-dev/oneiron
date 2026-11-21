import * as React from 'react'
import { StatusDot } from '../marks/StatusDot'
import { Figure } from '../primitives/Figure'
import { flatThemeTones } from '../ground/root-theme'
import { soundPress } from '../lib/press'
import { cx } from '../lib/react-utils'
import { pagePicture } from '../lib/scene'
import { useResolvedScheme } from '../lib/scheme'
import { SCENE_STAND_IN_COLOUR, type Theme } from '../lib/theme'

export interface VaultRowProps extends Omit<React.ComponentPropsWithRef<'button'>, 'name'> {
  /* The vault's theme: its picture is the scene in the current mode, or
     the flat tone. */
  theme: Theme
  name: React.ReactNode
  /* Where it runs, in one line: `this Mac and two of your machines`. */
  runs: React.ReactNode
  /* How many things wait on the person there: a ring and the count. */
  waiting?: number
}

/* One vault in a list: its theme's picture, its name, where it runs, and
   at the right a ring with a count when something waits. A button; the
   caller's onPointerEnter and onPointerLeave (and onFocus, onBlur) let it
   show the vault's theme behind the list. */
export function VaultRow({ theme, name, runs, waiting = 0, className, type = 'button', onClick, ...props }: VaultRowProps) {
  const scheme = useResolvedScheme()
  const scene = pagePicture(theme, scheme)
  const flat = flatThemeTones(theme.kind === 'flat' ? theme.colour : SCENE_STAND_IN_COLOUR)
  const picture: React.CSSProperties = scene
    ? { backgroundImage: `url(${JSON.stringify(scene)})` }
    : { backgroundColor: `light-dark(${flat.day.flat}, ${flat.night.flat})` }
  return (
    <button
      type={type}
      className={cx('sl-vault-row', className)}
      onClick={(event) => {
        onClick?.(event)
        soundPress(event)
      }}
      {...props}
    >
      <span className="sl-vault-row-picture" data-kind={theme.kind} style={picture} aria-hidden="true" />
      <span className="sl-vault-row-words">
        <span className="sl-vault-row-name">{name}</span>
        <span className="sl-vault-row-runs">{runs}</span>
      </span>
      {waiting > 0 ? (
        <span className="sl-vault-row-waiting">
          <StatusDot state="waiting" label={`${waiting} waiting on you`} />
          <Figure aria-hidden="true">{waiting}</Figure>
        </span>
      ) : null}
    </button>
  )
}
