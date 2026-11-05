import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createFixtureRuntime } from '../src/runtime/app-runtime'

describe('fixture application runtime', () => {
  it('keeps host identity separate from data and engine status', () => {
    const web = createFixtureRuntime('web')
    const desktop = createFixtureRuntime('desktop')
    assert.equal(web.surface, 'web')
    assert.equal(desktop.surface, 'desktop')
    for (const runtime of [web, desktop]) {
      assert.equal(runtime.dataSource, 'fixtures')
      assert.deepEqual(runtime.engine, { status: 'not-configured' })
    }
  })

  it('cannot turn fixture activity into a live connection by mutating context', () => {
    const runtime = createFixtureRuntime('desktop')
    assert.equal(Reflect.set(runtime, 'dataSource', 'engine'), false)
    assert.equal(Reflect.set(runtime.engine, 'status', 'connected'), false)
    assert.equal(runtime.dataSource, 'fixtures')
    assert.equal(runtime.engine.status, 'not-configured')
  })

  it('creates isolated context values without browser or native globals', () => {
    const first = createFixtureRuntime('web')
    const second = createFixtureRuntime('web')
    assert.notEqual(first, second)
    assert.notEqual(first.engine, second.engine)
    assert.deepEqual(first, second)
  })
})
