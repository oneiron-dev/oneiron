import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { runInNewContext } from 'node:vm'

const marker = readFileSync(new URL('../src-tauri/src/macos-chrome.js', import.meta.url), 'utf8')

describe('macOS document-start chrome marker', () => {
  it('sets only the visual marker when the document already exists', () => {
    const document = { documentElement: { dataset: {} as Record<string, string> } }
    runInNewContext(marker, { document })
    assert.deepEqual(document.documentElement.dataset, { windowChrome: 'macos' })
  })

  it('waits for the root and disconnects its one-time observer', () => {
    const document: { documentElement: { dataset: Record<string, string> } | null } = {
      documentElement: null,
    }
    let notify = () => {}
    let disconnected = false
    runInNewContext(marker, {
      document,
      MutationObserver: class {
        constructor(callback: () => void) { notify = callback }
        observe(target: unknown) { assert.equal(target, document) }
        disconnect() { disconnected = true }
      },
    })
    assert.equal(disconnected, false)
    document.documentElement = { dataset: {} }
    notify()
    assert.equal(document.documentElement.dataset.windowChrome, 'macos')
    assert.equal(disconnected, true)
  })

  it('limits renderer window commands to the macOS main window', () => {
    const capability = JSON.parse(readFileSync(
      new URL('../src-tauri/capabilities/macos-chrome.json', import.meta.url), 'utf8',
    ))
    assert.deepEqual(capability.platforms, ['macOS'])
    assert.deepEqual(capability.windows, ['main'])
    assert.deepEqual(capability.permissions, [
      'core:window:allow-start-dragging',
      'core:window:allow-internal-toggle-maximize',
    ])
    const base = JSON.parse(readFileSync(
      new URL('../src-tauri/capabilities/main.json', import.meta.url), 'utf8',
    ))
    assert.deepEqual(base.permissions, [])
  })
})
