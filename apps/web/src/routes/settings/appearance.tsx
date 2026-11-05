import * as React from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { applyTheme, cue, markCued, readTheme, useSound, type Theme } from '~/components/safelight/hooks'
import { PaneHead, Sheet } from './-shared'
import { AppIconAppearanceRow } from '~/components/desktop/AppIconAppearance'
import { RECALL_SCENES, recallSceneAssets, useRecallScene, type RecallScene } from '~/runtime/recall-scene'

export const Route = createFileRoute('/settings/appearance')({
  component: AppearancePage,
})

/* ── appearance: theme + sound live HERE (rules 2, 25, 37). the pressed
   act is the receipt; it settles at once. ── */
const SCENE_LABELS: Record<RecallScene, string> = {
  none: 'None',
  'tidal-margin': 'Tidal margin',
  'high-weather': 'High weather',
}

function AppearancePage() {
  const [scene, setScene] = useRecallScene()
  const sceneAssets = recallSceneAssets(scene)
  const [sceneSaved, setSceneSaved] = React.useState(true)
  const pickScene = (next: RecallScene) => (e: React.MouseEvent) => {
    markCued(e)
    if (next === scene) return
    setSceneSaved(setScene(next))
    cue('toggle')
  }

  /* the theme is a class on <html> (readTheme/applyTheme); read on mount,
     and follow the `t` key so the row never lies */
  const [theme, setTheme] = React.useState<Theme>('system')
  React.useEffect(() => {
    setTheme(readTheme())
    const mo = new MutationObserver(() => setTheme(readTheme()))
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
    return () => mo.disconnect()
  }, [])
  const pickTheme = (next: Theme) => (e: React.MouseEvent) => {
    markCued(e)
    if (next !== readTheme()) {
      applyTheme(next)
      setTheme(next)
    }
    cue('toggle')
  }

  /* sound: useSound() gives the toggle; the row mirrors localStorage */
  const toggleSound = useSound()
  const [sound, setSound] = React.useState(true)
  const readSound = () => {
    try {
      return localStorage.getItem('oneiron-mock-sound') !== 'off'
    } catch {
      return true
    }
  }
  React.useEffect(() => {
    setSound(readSound())
    /* the m key toggles sound from the layout; read again after it
       lands so the row never lies (the theme row has its observer) */
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'm') setTimeout(() => setSound(readSound()), 0)
    }
    addEventListener('keydown', onKey)
    return () => removeEventListener('keydown', onKey)
  }, [])
  const pickSound = (want: boolean) => (e: React.MouseEvent) => {
    markCued(e)
    if (readSound() !== want) {
      toggleSound()
      if (readSound() !== want) toggleSound()
    }
    setSound(want)
    if (!want) cue('press')
  }

  return (
    <Sheet page="appearance">
      <PaneHead title="appearance" hint="How the desk looks and sounds. This follows you, not the vault." />
      <div className="srow">
        <span className="key">theme</span>
        <span className="acts" role="group" aria-label="theme">
          <button className={theme === 'light' ? 'act on' : 'act'} aria-pressed={theme === 'light'} title="the reading room" onClick={pickTheme('light')}>
            <span className="glyph" aria-hidden="true">○</span> light
          </button>
          <button className={theme === 'system' ? 'act on' : 'act'} aria-pressed={theme === 'system'} title="follow the system" onClick={pickTheme('system')}>
            <span className="glyph" aria-hidden="true">◐</span> system
          </button>
          <button className={theme === 'dark' ? 'act on' : 'act'} aria-pressed={theme === 'dark'} title="the film black desk" onClick={pickTheme('dark')}>
            <span className="glyph" aria-hidden="true">●</span> dark
          </button>
        </span>
      </div>
      <div className="srow">
        <span className="key">sound</span>
        <span className="acts" role="group" aria-label="sound">
          <button className={sound ? 'act on' : 'act'} aria-pressed={sound} title="cues on acts, folds and the theme" onClick={pickSound(true)}>
            on
          </button>
          <button className={!sound ? 'act on' : 'act'} aria-pressed={!sound} title="every cue is a no-op" onClick={pickSound(false)}>
            off
          </button>
        </span>
      </div>
      <div className="srow recall-scene-row">
        <span className="key" id="recall-scene-label">Recall scene</span>
        <div className="recall-scene-control">
          <div className="acts" role="group" aria-labelledby="recall-scene-label" aria-describedby="recall-scene-note">
            {RECALL_SCENES.map((choice) => (
              <button
                key={choice}
                type="button"
                className={scene === choice ? 'act on' : 'act'}
                aria-pressed={scene === choice}
                onClick={pickScene(choice)}
              >
                {SCENE_LABELS[choice]}
              </button>
            ))}
          </div>
          <div className="recall-scene-detail">
            <span className="recall-scene-preview" aria-hidden="true">
              {sceneAssets && <>
                <span className="art-day" style={{ backgroundImage: `url("${sceneAssets.day}")` }} />
                <span className="art-night" style={{ backgroundImage: `url("${sceneAssets.night}")` }} />
              </>}
            </span>
            <span id="recall-scene-note">Only before a question in Recall. Follows the theme.</span>
          </div>
          <span className="recall-scene-status" role="status">
            {!sceneSaved && 'For this session only. This device could not save the choice.'}
          </span>
        </div>
      </div>
      <AppIconAppearanceRow />
    </Sheet>
  )
}
