import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { FileRow } from '../src/design-system/patterns/FileRow'
import { PINNED_LIST_NOTE, PinnedList } from '../src/design-system/patterns/PinnedList'

describe('FileRow in a list', () => {
  test('one head row: made by, changed; each row kind, name, pin mark, who, time', () => {
    const html = renderToStaticMarkup(
      <FileRow.List>
        <FileRow kind="chart" name="Q4 view" pinned portrait={<span className="who">M</span>} author="Metryon" time="14:31" />
        <FileRow kind="table" name="Acme store sales" portrait={<span className="who">T</span>} author="Tory" time="09:40" />
      </FileRow.List>,
    )
    assert.match(html, /<div class="sl-file-list-head" aria-hidden="true"><span><\/span><span><\/span><span><\/span><span>made by<\/span><span class="sl-file-list-time">changed<\/span><\/div>/)
    assert.equal((html.match(/data-layout="list"/g) ?? []).length, 2)
    assert.equal((html.match(/aria-label="pinned in this room"/g) ?? []).length, 1)
    const row = html.slice(html.indexOf('Q4 view'))
    assert.ok(row.indexOf('sl-file-pin') < row.indexOf('class="who"'))
    assert.ok(row.indexOf('class="who"') < row.indexOf('14:31'))
  })

  test('outside a list a row keeps its seal and its four columns', () => {
    const html = renderToStaticMarkup(<FileRow kind="note" name="week 44 dips" maker="agent" author="Tory" time="03:10" />)
    assert.doesNotMatch(html, /data-layout|sl-file-pin/)
    assert.match(html, /sl-seal/)
  })
})

describe('PinnedList', () => {
  test('the sentence, then pinned by, then the pins; a pinned message carries its writer as the mark', () => {
    const html = renderToStaticMarkup(
      <PinnedList>
        <FileRow kind="chart" name="Q4 view" portrait={<span>M</span>} author="Metryon" time="14:31" />
        <FileRow mark={<span className="writer">y</span>} name="Can we have the Q4 view by Friday?" portrait={<span>O</span>} author="Owen" time="13:52" />
      </PinnedList>,
    )
    assert.ok(html.includes(PINNED_LIST_NOTE))
    assert.ok(html.indexOf(PINNED_LIST_NOTE) < html.indexOf('pinned by'))
    assert.match(html, /<span>pinned by<\/span><span class="sl-file-list-time"><\/span>/)
    assert.match(html, /<span class="sl-file-mark"><span class="writer">y<\/span><\/span>/)
  })
})
