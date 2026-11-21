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

  test('the house is a house: walls, a roof and a door, no hash', () => {
    const house = renderToStaticMarkup(<Icon name="house" />)
    assert.doesNotMatch(house, /h11/)
    assert.match(house, /M15 21v-8a1 1 0 0 0-1-1h-4a1 1 0 0 0-1 1v8/)
  })

  test('day, night and follows the system are drawn in the same style', () => {
    for (const name of ['sun', 'moon', 'halfCircle'] as const) {
      assert.ok(ICON_NAMES.includes(name), `${name} is an icon`)
      const svg = renderToStaticMarkup(<Icon name={name} />)
      assert.match(svg, /viewBox="0 0 24 24"/)
      assert.match(svg, /stroke-width="1.5"/)
      assert.match(svg, /stroke-linecap="round"/)
      assert.match(svg, /stroke-linejoin="round"/)
    }
    /* Only the system's half is filled. */
    assert.match(renderToStaticMarkup(<Icon name="halfCircle" />), /<path d="M12 3a9 9 0 0 1 0 18z" fill="currentColor"\/>/)
    assert.doesNotMatch(renderToStaticMarkup(<Icon name="sun" />), /fill="currentColor"/)
  })
})
