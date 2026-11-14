import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { FileRow, listHasSizes } from '../src/design-system/patterns/FileRow'

describe('FileRow: who is optional, a size at the right', () => {
  test('a row with no author keeps an empty who column', () => {
    const html = renderToStaticMarkup(<FileRow kind="sheet" kindLabel="sheet" name="Acme store sales" time="16:40" />)
    assert.match(html, /<span class="sl-file-author"><\/span>/)
  })

  test('a row with a size ends with the size as a figure, after the time', () => {
    const html = renderToStaticMarkup(<FileRow kind="sheet" kindLabel="sheet" name="Acme store sales" time="16:40" size="1.2 MB" />)
    assert.match(html, /data-sizes=""/)
    const time = html.indexOf('sl-file-time')
    const size = html.indexOf('sl-file-size')
    assert.ok(time > 0 && size > time, 'the size follows the time')
    assert.match(html, /class="sl-figure sl-file-size"[^>]*>1\.2 MB<\/span><\/button>$/)
  })

  test('without a size the row is as before', () => {
    const html = renderToStaticMarkup(<FileRow kind="sheet" kindLabel="sheet" name="Acme store sales" author="Metryon" time="16:40" />)
    assert.doesNotMatch(html, /data-sizes|sl-file-size/)
  })

  test('a list shows the size column when a row has a size; every row keeps the column', () => {
    const rows = [
      <FileRow key="a" kind="sheet" kindLabel="sheet" name="Acme store sales" time="16:40" size="1.2 MB" />,
      <FileRow key="b" kind="note" kindLabel="note" name="week 44 dips" time="03:10" />,
    ]
    assert.equal(listHasSizes(rows), true)
    assert.equal(listHasSizes(<FileRow kind="note" name="week 44 dips" />), false)
    const html = renderToStaticMarkup(<FileRow.List whoHead="">{rows}</FileRow.List>)
    assert.match(html, /<div class="sl-file-list" data-sizes="">/)
    assert.match(html, /<span class="sl-file-list-size">size<\/span>/)
    assert.equal((html.match(/data-layout="list" data-sizes=""/g) ?? []).length, 2)
  })
})
