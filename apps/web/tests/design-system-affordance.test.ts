import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { affordance, findAffordance, gateOf, paramsContain, parseVerbParams, readAffordances } from '../src/design-system/lib/affordance'
import { adopt, element, h } from './support/stand-in-dom'

const verb = (name: string, params?: Record<string, string | number | boolean | null>, gate?: 'auto' | 'proposed' | 'person') =>
  affordance({ verb: name, params, gate }) as unknown as Record<string, string>

describe('affordance()', () => {
  test('the attributes: the verb, the params as JSON, the gate (auto by default)', () => {
    assert.deepEqual(affordance({ verb: 'vault.rooms.speak', params: { room: 'acme-forecast' } }), {
      'data-verb': 'vault.rooms.speak',
      'data-verb-gate': 'auto',
      'data-verb-params': '{"room":"acme-forecast"}',
    })
    assert.deepEqual(affordance({ verb: 'app.pane.close', gate: 'person' }), { 'data-verb': 'app.pane.close', 'data-verb-gate': 'person' })
  })

  test('params read back: plain values only; anything else reads as none', () => {
    assert.deepEqual(parseVerbParams('{"room":"acme","count":3,"open":true,"none":null,"list":[1]}'), { room: 'acme', count: 3, open: true, none: null })
    assert.deepEqual(parseVerbParams('[1,2]'), {})
    assert.deepEqual(parseVerbParams('not json'), {})
    assert.deepEqual(parseVerbParams(null), {})
    assert.equal(gateOf('proposed'), 'proposed')
    assert.equal(gateOf('anything'), 'auto')
    assert.equal(paramsContain({ room: 'acme', count: 3 }, { room: 'acme' }), true)
    assert.equal(paramsContain({ room: 'acme' }, { room: 'hokuei' }), false)
  })
})

describe('readAffordances', () => {
  function screen() {
    const form = h(
      'form',
      { role: 'region', 'aria-label': 'invite' },
      element('input', { type: 'text', 'aria-label': 'Name', ...verb('app.draft.set', { field: 'invite' }) }, { value: 'Yuki' }, []),
      element('input', { type: 'password', 'aria-label': 'Passphrase', ...verb('app.draft.set', { field: 'passphrase' }) }, { value: 'hunter' }, []),
      h('button', { ...verb('vault.rooms.invite', { room: 'acme-forecast' }, 'proposed') }, 'invite'),
      h('button', { disabled: '', ...verb('vault.rooms.leave', { room: 'acme-forecast' }, 'person') }, 'leave'),
    )
    const menu = h(
      'div',
      { role: 'menu', 'aria-label': 'room' },
      h('button', { role: 'menuitemcheckbox', 'aria-checked': 'true', ...verb('app.pin.set', { pin: 'q4' }) }, 'Q4 view'),
      h('button', { 'aria-pressed': 'false', 'aria-expanded': 'true', ...verb('app.pane.open', { pane: 'outline' }) }, 'outline'),
      h('a', { href: '/app/inbox', 'aria-current': 'page', ...verb('app.place.go', { place: 'inbox' }) }, 'inbox'),
    )
    const hidden = h('div', { 'data-agent-hidden': '' }, h('button', { ...verb('vault.erase') }, 'erase'))
    const secret = h('div', { 'data-agent-secret': '' }, element('textarea', { 'aria-label': 'Note to self', ...verb('app.draft.set', { field: 'note' }) }, { value: 'private words' }, []))
    const root = h('main', {}, form, menu, hidden, secret)
    adopt(root)
    return root as unknown as Element
  }

  test('in document order, with each control’s name, role, verb, params and gate', () => {
    const list = readAffordances(screen())
    assert.deepEqual(
      list.map((a) => [a.name, a.role, a.verb, a.gate]),
      [
        ['Name', 'textbox', 'app.draft.set', 'auto'],
        ['Passphrase', 'textbox', 'app.draft.set', 'auto'],
        ['invite', 'button', 'vault.rooms.invite', 'proposed'],
        ['leave', 'button', 'vault.rooms.leave', 'person'],
        ['Q4 view', 'menuitemcheckbox', 'app.pin.set', 'auto'],
        ['outline', 'button', 'app.pane.open', 'auto'],
        ['inbox', 'link', 'app.place.go', 'auto'],
        ['Note to self', 'textbox', 'app.draft.set', 'auto'],
      ],
    )
    assert.deepEqual(list[2].params, { room: 'acme-forecast' })
  })

  test('each control’s state', () => {
    const list = readAffordances(screen())
    assert.deepEqual(list[0].state, { value: 'Yuki' })
    assert.deepEqual(list[3].state, { disabled: true })
    assert.deepEqual(list[4].state, { checked: true })
    assert.deepEqual(list[5].state, { checked: false, expanded: true })
    assert.deepEqual(list[6].state, { current: 'page' })
  })

  test('the named regions around a control, outermost first', () => {
    const list = readAffordances(screen())
    assert.deepEqual(list[2].region, ['invite'])
    assert.deepEqual(list[4].region, ['room'])
  })

  test('data-agent-hidden leaves a subtree out; data-agent-secret and a password leave the value out', () => {
    const list = readAffordances(screen())
    assert.equal(list.some((a) => a.verb === 'vault.erase'), false)
    assert.equal(list[1].state.value, undefined)
    assert.equal(list[7].state.value, undefined)
  })

  test('a root inside a hidden subtree lists nothing', () => {
    const inner = h('div', {}, h('button', { ...verb('app.pane.close') }, 'close'))
    h('section', { 'data-agent-hidden': '' }, inner)
    assert.deepEqual(readAffordances(inner as unknown as Element), [])
    assert.deepEqual(readAffordances(null), [])
  })

  test('findAffordance by verb and params', () => {
    const root = screen()
    assert.equal(findAffordance(root, { verb: 'app.draft.set', params: { field: 'passphrase' } })?.name, 'Passphrase')
    assert.equal(findAffordance(root, { verb: 'app.pane.open' })?.name, 'outline')
    assert.equal(findAffordance(root, { verb: 'app.pane.open', params: { pane: 'tasks' } }), null)
  })
})
