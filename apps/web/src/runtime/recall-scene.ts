import { useSyncExternalStore } from 'react'

export const RECALL_SCENE_KEY = 'oneiron-recall-scene'
export const RECALL_SCENES = ['none', 'tidal-margin', 'high-weather'] as const
export type RecallScene = (typeof RECALL_SCENES)[number]
type SceneStorage = Pick<Storage, 'getItem' | 'setItem'>

export function validateRecallScene(value: unknown): RecallScene {
  return RECALL_SCENES.find((scene) => scene === value) ?? 'none'
}

export function recallSceneAssets(scene: RecallScene) {
  const valid = validateRecallScene(scene)
  return valid === 'none' ? null : {
    day: `/art/scene-${valid}-day.webp`,
    night: `/art/scene-${valid}-night.webp`,
  }
}

/* The store owns only this optional UI preference. Reads are lazy: SSR
   never touches browser storage. Failed writes keep the in-session choice. */
export function createRecallScenePreference(getStorage: () => SceneStorage | null) {
  let current: RecallScene | undefined
  const listeners = new Set<() => void>()
  const read = (): RecallScene => {
    try {
      return validateRecallScene(getStorage()?.getItem(RECALL_SCENE_KEY))
    } catch {
      return 'none'
    }
  }
  const notify = () => listeners.forEach((listener) => listener())
  return {
    getSnapshot: () => current ??= read(),
    getServerSnapshot: (): RecallScene => 'none',
    subscribe(listener: () => void) {
      listeners.add(listener)
      return () => { listeners.delete(listener) }
    },
    restore() {
      current = read()
      notify()
    },
    setScene(next: RecallScene): boolean {
      current = validateRecallScene(next)
      let persisted = false
      try {
        const storage = getStorage()
        if (storage) {
          storage.setItem(RECALL_SCENE_KEY, current)
          persisted = true
        }
      } catch {
        /* private mode / quota: the controlled choice still updates */
      }
      notify()
      return persisted
    },
  }
}

const preference = createRecallScenePreference(() =>
  typeof window === 'undefined' ? null : window.localStorage,
)

function subscribe(listener: () => void) {
  const unsubscribe = preference.subscribe(listener)
  const onStorage = (event: StorageEvent) => {
    if (event.key === RECALL_SCENE_KEY || event.key === null) preference.restore()
  }
  window.addEventListener('storage', onStorage)
  return () => {
    unsubscribe()
    window.removeEventListener('storage', onStorage)
  }
}

export function useRecallScene() {
  const scene = useSyncExternalStore(subscribe, preference.getSnapshot, preference.getServerSnapshot)
  return [scene, preference.setScene] as const
}
