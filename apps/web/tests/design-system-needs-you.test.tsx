import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { NEEDS_YOU_UNDO_MS, NeedsYou, type NeedsYouAnswerRecord } from '../src/design-system/patterns/NeedsYou'
import { formatAnswerTime } from '../src/design-system/patterns/answer-time'
import { pushPendingUndo } from '../src/design-system/lib/pending-undo'

/* The opening tag of the first element carrying `attribute`. */
function tagWith(html: string, attribute: string): string {
  const at = html.indexOf(attribute)
  assert.ok(at >= 0, `no element with ${attribute}`)
  const start = html.lastIndexOf('<', at)
  return html.slice(start, html.indexOf('>', at) + 1)
}

const ANSWERED: NeedsYouAnswerRecord = { value: 'promo', word: 'promo weeks', mark: 'pick', time: '09:14' }

function block(props: { answers?: 'chips' | 'plain'; answer?: NeedsYouAnswerRecord; aside?: boolean } = {}) {
  return renderToStaticMarkup(
    <NeedsYou answers={props.answers}>
      <NeedsYou.Group room="acme-forecast">
        <NeedsYou.Ask
          id="promo"
          asker={<span className="asker">M</span>}
          question="Should the fit treat weeks 44 to 46 as promo weeks?"
          note="Sales dip in weeks 44 to 46 every year."
          defaultAnswer={props.answer}
          defaultSetAside={props.aside}
        >
          <NeedsYou.Picks>
            <NeedsYou.Pick value="promo">promo weeks</NeedsYou.Pick>
            <NeedsYou.Pick value="normal">normal weeks</NeedsYou.Pick>
            <NeedsYou.OwnAnswer />
          </NeedsYou.Picks>
        </NeedsYou.Ask>
      </NeedsYou.Group>
      <NeedsYou.Group room="the house">
        <NeedsYou.Ask id="extracts" question="Pull three paid registry extracts?">
          <NeedsYou.YesNo figure="¥2,400" />
        </NeedsYou.Ask>
      </NeedsYou.Group>
    </NeedsYou>,
  )
}

describe('NeedsYou, the ruled shape', () => {
  test('one block, the measure for an information mark, chips by default', () => {
    const root = tagWith(block(), 'class="sl-needs-you"')
    assert.match(root, /data-ground="well"/)
    assert.match(root, /data-answers="chips"/)
    assert.match(root, /data-info-block=""/)
    assert.match(tagWith(block({ answers: 'plain' }), 'class="sl-needs-you"'), /data-answers="plain"/)
  })

  test('each group is named by its room, with the hash symbol', () => {
    const html = block()
    assert.match(html, /<p id="[^"]+" class="sl-needs-you-group-label"># acme-forecast<\/p>/)
    assert.match(html, /<p id="[^"]+" class="sl-needs-you-group-label"># the house<\/p>/)
    assert.match(tagWith(html, 'class="sl-needs-you-group"'), /role="group"/)
  })

  test('an open ask: portrait, the ask, then later and the information mark; the answers under it', () => {
    const html = block()
    const row = html.slice(html.indexOf('data-needs-you-id="promo"'), html.indexOf('data-needs-you-id="extracts"'))
    const order = ['class="asker"', 'class="sl-needs-you-question"', 'aria-label="Later"', 'aria-label="About this"', 'class="sl-needs-you-answers"'].map((m) =>
      row.indexOf(m),
    )
    assert.ok(order.every((at) => at >= 0), `parts present: ${order}`)
    assert.deepEqual([...order].sort((a, b) => a - b), order)
    assert.match(tagWith(html, 'data-needs-you-id="promo"'), /data-state="open"/)
    /* Picks, then the pencil for an own answer. */
    assert.match(row, /data-kind="pick"[^>]*>.*promo weeks/)
    assert.match(tagWith(row, 'data-kind="own"'), /aria-label="Your own answer"/)
  })

  test('an ask without a note shows no information mark', () => {
    const html = block()
    const row = html.slice(html.indexOf('data-needs-you-id="extracts"'))
    assert.doesNotMatch(row, /aria-label="About this"/)
  })

  test('yes or no: a check carrying the figure and a cross, named Approve and Do not', () => {
    const html = block()
    assert.match(tagWith(html, 'data-kind="yes"'), /aria-label="Approve, ¥2,400"/)
    assert.match(tagWith(html, 'data-kind="no"'), /aria-label="Do not"/)
    assert.match(html, /<span class="sl-figure" data-size="figure">¥2,400<\/span>/)
  })

  test('answered: one record line in the block, with the answer’s mark, word and time, no undo once it stands', () => {
    const html = block({ answer: ANSWERED })
    assert.match(tagWith(html, 'data-needs-you-id="promo"'), /data-state="answered"/)
    const record = html.slice(html.indexOf('class="sl-needs-you-record"'), html.indexOf('data-needs-you-id="extracts"'))
    const order = ['class="asker"', 'class="sl-needs-you-record-ask"', 'data-mark="pick"', 'class="sl-needs-you-record-word">promo weeks', '09:14'].map((m) =>
      record.indexOf(m),
    )
    assert.ok(order.every((at) => at >= 0), `record parts present: ${order}`)
    assert.deepEqual([...order].sort((a, b) => a - b), order)
    assert.doesNotMatch(record, /sl-needs-you-undo/)
    assert.doesNotMatch(record, /sl-needs-you-answers/)
    /* The other group is untouched. */
    assert.match(tagWith(html, 'data-needs-you-id="extracts"'), /data-state="open"/)
  })

  test('set aside: the ask, set aside, answer now', () => {
    const html = block({ aside: true })
    assert.match(tagWith(html, 'data-needs-you-id="promo"'), /data-state="aside"/)
    const line = html.slice(html.indexOf('class="sl-needs-you-aside"'), html.indexOf('data-needs-you-id="extracts"'))
    assert.match(line, /class="sl-needs-you-record-ask">Should the fit/)
    assert.match(line, /<span class="sl-needs-you-aside-state">set aside<\/span>/)
    assert.match(line, />answer now<\/button>/)
  })
})

describe('the undo window', () => {
  test('an answer can be undone for 5 seconds', () => {
    assert.equal(NEEDS_YOU_UNDO_MS, 5000)
  })

  test('Escape undoes the newest answer still in its window; a released window is skipped', () => {
    const listeners = new Set<(event: KeyboardEvent) => void>()
    const original = (globalThis as { document?: unknown }).document
    ;(globalThis as { document?: unknown }).document = {
      addEventListener: (_: string, fn: (event: KeyboardEvent) => void) => listeners.add(fn),
      removeEventListener: (_: string, fn: (event: KeyboardEvent) => void) => listeners.delete(fn),
    }
    try {
      const undone: string[] = []
      const releaseFirst = pushPendingUndo(() => undone.push('first'))
      const releaseSecond = pushPendingUndo(() => undone.push('second'))
      const escape = () => {
        let prevented = false
        const event = { key: 'Escape', defaultPrevented: false, preventDefault: () => (prevented = true) } as unknown as KeyboardEvent
        for (const fn of [...listeners]) fn(event)
        return prevented
      }
      assert.equal(listeners.size, 1)
      assert.equal(escape(), true)
      assert.deepEqual(undone, ['second'])
      releaseSecond()
      assert.equal(escape(), true)
      assert.deepEqual(undone, ['second', 'first'])
      releaseFirst()
      /* Every window closed: the listener is gone and Escape is left alone. */
      assert.equal(listeners.size, 0)
    } finally {
      ;(globalThis as { document?: unknown }).document = original
    }
  })

  test('the record’s time is hours and minutes on the 24-hour clock', () => {
    assert.equal(formatAnswerTime(new Date(2026, 10, 12, 9, 4)), '09:04')
    assert.equal(formatAnswerTime(new Date(2026, 10, 12, 17, 30)), '17:30')
  })
})
