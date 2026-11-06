import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { RECALL_SCENE_KEY, createRecallScenePreference, recallSceneAssets } from '../src/runtime/recall-scene'

describe('Recall scene preference', () => {
  it('defaults to None for absent, invalid or inaccessible storage', () => {
    for (const stored of [null, '', 'rain-garden', 'Tidal margin', '../custom.webp']) {
      const store = createRecallScenePreference(() => ({
        getItem: () => stored,
        setItem: () => {},
      }))
      assert.equal(store.getSnapshot(), 'none')
    }
    assert.equal(createRecallScenePreference(() => null).getSnapshot(), 'none')
    assert.equal(createRecallScenePreference(() => { throw new Error('blocked') }).getSnapshot(), 'none')
  })
})

describe('Recall scene changes', () => {
  it('persists choices under its own key, restores them, and notifies immediately', () => {
    const data = new Map<string, string>()
    const storage = { getItem: (key: string) => data.get(key) ?? null, setItem: (key: string, value: string) => { data.set(key, value) } }
    const store = createRecallScenePreference(() => storage)
    const seen: string[] = []
    const unsubscribe = store.subscribe(() => seen.push(store.getSnapshot()))
    assert.equal(store.setScene('tidal-margin'), true)
    assert.deepEqual([...data], [[RECALL_SCENE_KEY, 'tidal-margin']])
    assert.equal(createRecallScenePreference(() => storage).getSnapshot(), 'tidal-margin')
    store.setScene('high-weather')
    assert.equal(store.getSnapshot(), 'high-weather')
    store.setScene('none')
    assert.deepEqual(seen, ['tidal-margin', 'high-weather', 'none'])
    unsubscribe()
    store.setScene('tidal-margin')
    assert.equal(seen.length, 3)
  })

  it('keeps the controlled choice for the session when writes or storage access fail', () => {
    for (const getStorage of [
      () => null,
      () => { throw new Error('blocked access') },
      () => ({ getItem: () => 'none', setItem: () => { throw new Error('quota') } }),
    ]) {
      const store = createRecallScenePreference(getStorage)
      assert.equal(store.getSnapshot(), 'none')
      assert.equal(store.setScene('high-weather'), false)
      assert.equal(store.getSnapshot(), 'high-weather')
      store.setScene('none')
      assert.equal(store.getSnapshot(), 'none')
    }
  })

  it('validates restore and write values; server rendering always defaults to None', () => {
    let stored = 'tidal-margin'
    const store = createRecallScenePreference(() => ({ getItem: () => stored, setItem: (_, value) => { stored = value } }))
    assert.equal(store.getServerSnapshot(), 'none')
    assert.equal(store.getSnapshot(), 'tidal-margin')
    stored = 'high-weather'
    store.restore()
    assert.equal(store.getSnapshot(), 'high-weather')
    stored = 'https://example.com/remote.webp'
    store.restore()
    assert.equal(store.getSnapshot(), 'none')
    store.setScene('rain-garden' as never)
    assert.equal(stored, 'none')
  })

  it('maps only the two authored day/night pairs; None loads no art', () => {
    assert.equal(recallSceneAssets('none'), null)
    assert.equal(recallSceneAssets('rain-garden' as never), null)
    for (const scene of ['tidal-margin', 'high-weather'] as const) {
      assert.deepEqual(recallSceneAssets(scene), {
        day: `/art/scene-${scene}-day.webp`,
        night: `/art/scene-${scene}-night.webp`,
      })
    }
  })
})
