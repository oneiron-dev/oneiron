import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { setActMode, type RoleAct } from '../src/design-system/frame/role-acts'

const acts: RoleAct[] = [
  { name: 'erase the vault', mode: 'always-ask' },
  { name: 'add a member', mode: 'ask-when-unsure' },
]

describe('setActMode', () => {
  test('changes the named act only', () => {
    assert.deepEqual(setActMode(acts, 'add a member', 'just-go'), [
      { name: 'erase the vault', mode: 'always-ask' },
      { name: 'add a member', mode: 'just-go' },
    ])
  })

  test('an unknown act changes nothing, and the input is never changed', () => {
    const out = setActMode(acts, 'transfer ownership', 'just-go')
    assert.deepEqual(out, acts)
    assert.notEqual(out, acts)
    assert.equal(acts[1].mode, 'ask-when-unsure')
  })
})
