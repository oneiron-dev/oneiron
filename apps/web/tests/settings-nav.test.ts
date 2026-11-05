import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { createMemoryHistory, createRootRoute, createRouter, RouterContextProvider } from '@tanstack/react-router'
import { Palette, ShortcutSheet } from '../src/components/safelight/Palette'
import { APP_ROUTE_KEY, DEFAULT_APP_ROUTE, lastAppRoute, rememberAppRoute, validAppRoute } from '../src/runtime/settings-nav'

function memoryStore(initial?: string) {
  const values = new Map<string, string>(initial === undefined ? [] : [[APP_ROUTE_KEY, initial]])
  return {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { values.set(key, value) },
  }
}

describe('Settings return navigation', () => {
  it('remembers the last real app screen, never a settings redirect or route injection', () => {
    const storage = memoryStore()
    rememberAppRoute('/app/pipeline', storage)
    assert.equal(lastAppRoute(storage), '/app/pipeline')
    for (const invalid of [
      '/app/settings', '/app/settings?from=tasks', '/app/billing', '/app/packs',
      '/application', '/app', '/app/', '/app/missing', '/app/inbox/extra',
      'https://example.com/app/inbox', '//example.com/app/inbox', 'javascript:alert(1)',
      '/app/../settings/account', '/app/%2e%2e/settings/account', '/app//inbox',
      '/app/inbox\\evil', '/app/inbox%2f..%2fsettings', ' /app/inbox',
      '/app/inbox\n', '/app/inbox?bad=%', '/app/inbox#%0aevil',
    ]) {
      assert.equal(validAppRoute(invalid), null, invalid)
      rememberAppRoute(invalid, storage)
      assert.equal(lastAppRoute(storage), '/app/pipeline', invalid)
      assert.equal(lastAppRoute(memoryStore(invalid)), DEFAULT_APP_ROUTE, invalid)
    }
    for (const malformed of [null, undefined, 42, {}, [' /app/inbox']]) {
      assert.equal(validAppRoute(malformed), null)
    }
  })

  it('preserves supported page state and safe anchors without carrying arbitrary navigation parameters', () => {
    const cases = [
      ['/app/recall?q=Hokuei%20pilot#pane', '/app/recall?q=Hokuei+pilot#pane'],
      ['/app/recall?q=Pilot?when#pane', '/app/recall?q=Pilot%3Fwhen#pane'],
      ['/app/vault#pane#other', '/app/vault'],
      ['/app/recall?q=%E6%9D%B1%E4%BA%AC&redirect=https%3A%2F%2Fevil.test', '/app/recall?q=%E6%9D%B1%E4%BA%AC'],
      ['/app/agents?with=tory#pane', '/app/agents?with=tory#pane'],
      ['/app/agents?with=unknown', '/app/agents'],
      ['/app/today?at=9%3A30', '/app/today?at=9%3A30'],
      ['/app/today?at=29%3A99', '/app/today'],
      ['/app/tasks?empty#tasks-why', '/app/tasks?empty=#tasks-why'],
      ['/app/notes?empty=1', '/app/notes?empty='],
      ['/app/inbox?empty=0', '/app/inbox?empty='],
      ['/app/pipeline/?next=%2Fsettings%2Faccount#pane', '/app/pipeline#pane'],
      ['/app/vault?with=tory#//evil.test', '/app/vault'],
      ['/app/threads#javascript:alert(1)', '/app/threads'],
      ['/app/briefs#heading-name', '/app/briefs#heading-name'],
      ['/app/orgs?empty#pane', '/app/orgs#pane'],
    ]
    for (const [input, expected] of cases) {
      const storage = memoryStore()
      rememberAppRoute(input, storage)
      assert.equal(lastAppRoute(storage), expected, input)
      assert.equal(validAppRoute(expected), expected, `stable: ${expected}`)
    }
  })

  it('falls back safely when storage is missing, malformed or blocked', () => {
    assert.equal(lastAppRoute(memoryStore()), DEFAULT_APP_ROUTE)
    assert.equal(lastAppRoute(memoryStore('')), DEFAULT_APP_ROUTE)
    const blocked = {
      getItem: () => { throw new Error('blocked read') },
      setItem: () => { throw new Error('blocked write') },
    }
    assert.equal(lastAppRoute(blocked), DEFAULT_APP_ROUTE)
    assert.doesNotThrow(() => rememberAppRoute('/app/tasks', blocked))
    assert.equal(validAppRoute(`/app/recall?q=${'a'.repeat(4096)}`), null)

    const original = Object.getOwnPropertyDescriptor(globalThis, 'window')
    try {
      Reflect.deleteProperty(globalThis, 'window')
      assert.equal(lastAppRoute(), DEFAULT_APP_ROUTE)
      assert.doesNotThrow(() => rememberAppRoute('/app/tasks'))
      Object.defineProperty(globalThis, 'window', {
        configurable: true,
        value: { get sessionStorage() { throw new Error('blocked storage access') } },
      })
      assert.equal(lastAppRoute(), DEFAULT_APP_ROUTE)
      assert.doesNotThrow(() => rememberAppRoute('/app/tasks'))
      const storage = memoryStore()
      Object.defineProperty(globalThis, 'window', { configurable: true, value: { sessionStorage: storage } })
      rememberAppRoute('/app/tasks')
      assert.equal(lastAppRoute(), '/app/tasks')
    } finally {
      if (original) Object.defineProperty(globalThis, 'window', original)
      else Reflect.deleteProperty(globalThis, 'window')
    }
  })

})

describe('Settings palette compatibility', () => {
  it('omits the tuner only when the layout does not supply one', () => {
    const router = createRouter({ routeTree: createRootRoute(), history: createMemoryHistory() })
    const render = (onTuner?: () => void) => renderToStaticMarkup(
      React.createElement(RouterContextProvider, {
        router,
        children: React.createElement(Palette, { open: true, onClose: () => {}, onTuner }),
      }),
    )
    assert.doesNotMatch(render(), /class="ptitle">tuner</)
    assert.match(render(() => {}), /class="ptitle">tuner</)
    assert.match(render(), /role="combobox"/)
  })

  it('keeps the app shortcut sheet unchanged and omits the rail shortcut in Settings', () => {
    const render = (includeRail?: boolean) => renderToStaticMarkup(
      React.createElement(ShortcutSheet, { shown: true, includeRail }),
    )
    assert.match(render(), /fold the rail/)
    assert.doesNotMatch(render(false), /fold the rail/)
    assert.match(render(false), /search or ask/)
    assert.match(render(false), /⌘K/)
  })
})
