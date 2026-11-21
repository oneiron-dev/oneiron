import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { Glyph } from '../src/design-system/marks/Glyph'

const css = (path: string) => readFileSync(new URL(`../src/design-system/${path}`, import.meta.url), 'utf8')

describe('Glyph at 28 px', () => {
  test('a 28 px glyph is 28 px square, as a seal and as a person', () => {
    assert.match(renderToStaticMarkup(<Glyph glyph="wing" label="Eiri" size={28} />), /data-size="28"/)
    assert.match(renderToStaticMarkup(<Glyph initial="o" label="Owen" size={28} />), /data-size="28"/)
    assert.match(css('marks/Glyph.css'), /\.sl-glyph\[data-size="28"\] \{\s*width: 28px;\s*height: 28px;\s*\}/)
  })

  test('the microsidebar’s 40 px square holds a 28 px face', () => {
    assert.match(css('frame/MicroSidebar.css'), /\.sl-micro-item-mark:has\(> \.sl-glyph\[data-size="28"\]\) \{\s*width: 28px;\s*height: 28px;\s*\}/)
  })
})
