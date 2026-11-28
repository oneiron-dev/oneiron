import * as React from 'react'
import { BrandMark } from '../marks/BrandMark'
import { cx } from '../lib/react-utils'
import { pagePicture } from '../lib/scene'
import { useResolvedScheme } from '../lib/scheme'
import { useRootTheme } from './root-theme'

export interface SceneSheetProps extends React.ComponentPropsWithRef<'section'> {
  /* The sheet's width in CSS pixels; never wider than the screen less its
     margin. */
  width?: number
  /* The brand line at the top of the sheet: the mark and the word. */
  brand?: boolean
  brandAlign?: 'center' | 'start'
}

/* A screen outside a vault (sign in, the person's vaults): the theme's
   scene in full, cover-fit (a flat theme is its ground tone), and one
   sheet centred on it both ways in the island tone, with no shadow. It
   fills its nearest positioned ancestor and scrolls when the sheet is
   taller than the screen. The ref, the class name and the other props go
   to the sheet. */
export function SceneSheet({ width = 410, brand = false, brandAlign = 'center', className, style, children, ...props }: SceneSheetProps) {
  const { theme } = useRootTheme()
  const scheme = useResolvedScheme()
  const picture = pagePicture(theme, scheme)
  return (
    <div
      className="sl-scene-sheet-stage"
      data-kind={theme.kind}
      style={picture ? { backgroundImage: `url(${JSON.stringify(picture)})` } : undefined}
    >
      <section className={cx('sl-scene-sheet', className)} style={{ width, ...style }} {...props}>
        {brand ? (
          <div className="sl-scene-sheet-brand" data-align={brandAlign}>
            <BrandMark word size={24} />
          </div>
        ) : null}
        {children}
      </section>
    </div>
  )
}
