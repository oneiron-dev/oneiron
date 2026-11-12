import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { ICON_NAMES, Icon } from '../src/design-system/primitives/Icon'

type SvgElement = React.ReactElement<{ dangerouslySetInnerHTML?: { __html: string } }>

describe('Icon', () => {
  /* React DOM writes innerHTML again whenever the markup object differs
     from the last render's. A control that renders between pointer down
     and pointer up (an InfoMark hides its note on pointer down) would then
     lose the path the press started on, and the click with it. */
  test('the markup object is the same object on every render, for every icon', () => {
    for (const name of ICON_NAMES) {
      const first = Icon({ name }) as SvgElement
      const second = Icon({ name, size: 20 }) as SvgElement
      assert.ok(first.props.dangerouslySetInnerHTML, `${name} draws its paths`)
      assert.equal(first.props.dangerouslySetInnerHTML, second.props.dangerouslySetInnerHTML, `${name} keeps its markup object`)
    }
  })

  test('each icon keeps its own paths', () => {
    const info = renderToStaticMarkup(<Icon name="info" />)
    const check = renderToStaticMarkup(<Icon name="check" />)
    assert.match(info, /<circle cx="12" cy="12" r="9.5"\/>/)
    assert.match(check, /<path d="M20 6 9 17l-5-5"\/>/)
    assert.notEqual(info, check)
  })
})
