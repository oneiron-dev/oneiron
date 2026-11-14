import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { accessibleName, accessibleRole, isTextField } from '../src/design-system/lib/accessible-name'
import { adopt, asElement, element, h } from './support/stand-in-dom'

describe('accessibleName, by source', () => {
  test('aria-labelledby: the named elements, each by its label or its text, in order', () => {
    const tree = h('div', {}, h('span', { id: 'an-room' }, 'acme-forecast'), h('span', { id: 'an-verb', 'aria-label': 'pin' }, 'ignored'), h('button', { 'aria-labelledby': 'an-verb an-room', 'aria-label': 'not this' }, 'nor this'))
    adopt(tree)
    assert.equal(accessibleName(asElement(tree.children[2])), 'pin acme-forecast')
  })

  test('aria-labelledby that names nothing falls through to aria-label', () => {
    const tree = h('button', { 'aria-labelledby': 'an-missing', 'aria-label': 'Close' })
    adopt(tree)
    assert.equal(accessibleName(asElement(tree)), 'Close')
  })

  test('aria-label', () => {
    assert.equal(accessibleName(asElement(h('button', { 'aria-label': '  Reply   in the thread ' }, h('svg', { 'aria-hidden': 'true' })))), 'Reply in the thread')
  })

  test('the label element of a field, or the label it sits in', () => {
    const label = h('label', { for: 'an-email' }, 'Email address')
    const field = element('input', { id: 'an-email', type: 'email' }, { labels: [label], value: '' }, [])
    assert.equal(accessibleName(asElement(field)), 'Email address')
    const inside = element('input', { type: 'text' }, { value: '' }, [])
    h('label', {}, 'Vault name ', inside)
    assert.equal(accessibleName(asElement(inside)), 'Vault name')
  })

  test('the text of a control whose role names it from content', () => {
    const button = h('button', {}, h('span', { 'aria-hidden': 'true' }, 'o'), 'send ', h('img', { alt: 'now' }), h('span', { role: 'tooltip', popover: 'manual' }, 'tooltip words'))
    assert.equal(accessibleName(asElement(button)), 'send now')
    assert.equal(accessibleName(asElement(h('div', {}, 'a plain block'))), '')
  })

  test('title last', () => {
    assert.equal(accessibleName(asElement(h('button', { title: 'More' }))), 'More')
    assert.equal(accessibleName(asElement(h('button', { title: 'More' }, 'more actions'))), 'more actions')
  })

  test('a text field with nothing else is named by its placeholder', () => {
    assert.equal(accessibleName(asElement(element('input', { placeholder: 'Write to acme-forecast' }, { value: '' }, []))), 'Write to acme-forecast')
    assert.equal(accessibleName(asElement(h('div', { role: 'textbox', 'aria-placeholder': 'Write a note' }))), 'Write a note')
  })
})

describe('accessibleRole', () => {
  test('the declared role wins; else the tag’s', () => {
    assert.equal(accessibleRole(asElement(h('button', { role: 'tab menuitem' }))), 'tab')
    assert.equal(accessibleRole(asElement(h('button'))), 'button')
    assert.equal(accessibleRole(asElement(h('a', { href: '/app' }))), 'link')
    assert.equal(accessibleRole(asElement(h('a'))), '')
    assert.equal(accessibleRole(asElement(h('input', { type: 'checkbox' }))), 'checkbox')
    assert.equal(accessibleRole(asElement(h('input', {}))), 'textbox')
    assert.equal(accessibleRole(asElement(h('select', {}))), 'combobox')
    assert.equal(accessibleRole(asElement(h('section', {}))), 'region')
  })

  test('text fields', () => {
    assert.equal(isTextField(asElement(h('textarea'))), true)
    assert.equal(isTextField(asElement(h('input', { type: 'search' }))), true)
    assert.equal(isTextField(asElement(h('input', { type: 'range' }))), false)
    assert.equal(isTextField(asElement(h('div', { contenteditable: 'true' }))), true)
  })
})
