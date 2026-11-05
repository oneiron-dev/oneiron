import * as React from 'react'
import { isTauri } from '@tauri-apps/api/core'
import { cue, markCued } from '~/components/safelight/hooks'
import {
  readAppIconAppearance,
  supportsAppIconAppearance,
  writeAppIconAppearance,
  type AppIconAppearance,
} from '~/runtime/app-icon'

/** The Dock preference is independent of the desk's light/dark CSS theme. */
export function AppIconAppearanceRow() {
  const [available, setAvailable] = React.useState(false)
  const [preference, setPreference] = React.useState<AppIconAppearance | null>(null)
  const [busy, setBusy] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)

  React.useEffect(() => {
    if (!supportsAppIconAppearance(document.documentElement.dataset.windowChrome, isTauri())) return
    setAvailable(true)
    let active = true
    readAppIconAppearance()
      .then((value) => { if (active) setPreference(value) })
      .catch(() => { if (active) setError('Could not read the app icon preference.') })
      .finally(() => { if (active) setBusy(false) })
    return () => { active = false }
  }, [])

  const pick = (next: AppIconAppearance) => async (event: React.MouseEvent) => {
    markCued(event)
    if (busy || next === preference) return
    setBusy(true)
    setError(null)
    try {
      setPreference(await writeAppIconAppearance(next))
      cue('toggle')
    } catch {
      setError('Could not save or apply the app icon. Try again.')
      cue('error')
    } finally {
      setBusy(false)
    }
  }

  // Do not show an inert native setting in a browser or on another platform.
  if (!available) return null

  return (
    <>
      <div className="srow">
        <span className="key">app icon</span>
        <span className="acts" role="group" aria-label="app icon" aria-busy={busy}>
          <button className={preference === 'light' ? 'act on' : 'act'} aria-pressed={preference === 'light'} disabled={busy} title="paper icon in the Dock" onClick={pick('light')}>
            <span className="glyph" aria-hidden="true">○</span> light
          </button>
          <button className={preference === 'system' ? 'act on' : 'act'} aria-pressed={preference === 'system'} disabled={busy} title="follow macOS icon appearance" onClick={pick('system')}>
            <span className="glyph" aria-hidden="true">◐</span> system
          </button>
          <button className={preference === 'dark' ? 'act on' : 'act'} aria-pressed={preference === 'dark'} disabled={busy} title="dark icon in the Dock" onClick={pick('dark')}>
            <span className="glyph" aria-hidden="true">●</span> dark
          </button>
        </span>
      </div>
      <p className="note">Changes the Dock icon while Oneiron is running. System follows macOS.</p>
      {error && <p className="note" role="alert">{error}</p>}
    </>
  )
}
