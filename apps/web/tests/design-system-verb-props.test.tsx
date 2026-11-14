import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { affordance } from '../src/design-system/lib/affordance'
import { RoomHead } from '../src/design-system/frame/RoomHead'
import { Tabs } from '../src/design-system/primitives/Tabs'
import { Composer } from '../src/design-system/patterns/Composer'
import { SplitPane } from '../src/design-system/patterns/SplitPane'
import { NeedsYou } from '../src/design-system/patterns/NeedsYou'
import { ComposedCard } from '../src/design-system/patterns/ComposedCard'

/* The opening tag of the element that declares `verb`. */
function declaring(html: string, verb: string): string {
  const at = html.indexOf(`data-verb="${verb}"`)
  assert.ok(at >= 0, `nothing declares ${verb}`)
  const start = html.lastIndexOf('<', at)
  return html.slice(start, html.indexOf('>', at) + 1)
}

describe('a part’s inner controls declare the verbs the caller gives', () => {
  test('RoomHead: the fixed tabs, the tasks and the add action', () => {
    const html = renderToStaticMarkup(
      <Tabs value="talk">
        <RoomHead
          title="acme-forecast"
          pins="head"
          tasks={['done', 'working']}
          affordances={{
            talk: affordance({ verb: 'app.view.set', params: { view: 'talk' } }),
            files: affordance({ verb: 'app.view.set', params: { view: 'files' } }),
            tasks: affordance({ verb: 'app.pane.open', params: { pane: 'tasks' } }),
            addPin: affordance({ verb: 'vault.rooms.pins.add', gate: 'proposed' }),
          }}
        />
      </Tabs>,
    )
    assert.match(declaring(html, 'app.view.set'), /role="tab"/)
    assert.match(declaring(html, 'app.pane.open'), /class="sl-room-head-tasks"/)
    assert.match(declaring(html, 'vault.rooms.pins.add'), /sl-tabs-add/)
    assert.match(declaring(html, 'vault.rooms.pins.add'), /data-verb-gate="proposed"/)
  })

  test('RoomHead with no tabs: the outline action', () => {
    const html = renderToStaticMarkup(<RoomHead title="acme-forecast" pins="none" affordances={{ outline: affordance({ verb: 'app.pane.open', params: { pane: 'outline' } }) }} />)
    assert.match(declaring(html, 'app.pane.open'), /sl-room-head-outline/)
  })

  test('Composer: the field, the button by its mode, dictation', () => {
    const verbs = {
      field: affordance({ verb: 'app.draft.set' }),
      send: affordance({ verb: 'vault.rooms.speak' }),
      voice: affordance({ verb: 'app.voice.start' }),
      dictate: affordance({ verb: 'app.dictation.start' }),
    }
    const empty = renderToStaticMarkup(<Composer onVoice={() => {}} onDictate={() => {}} affordances={verbs} />)
    assert.match(declaring(empty, 'app.draft.set'), /^<textarea/)
    assert.match(declaring(empty, 'app.voice.start'), /data-mode="talk"/)
    assert.doesNotMatch(empty, /vault\.rooms\.speak/)
    assert.match(declaring(empty, 'app.dictation.start'), /sl-composer-dictate/)
    const text = renderToStaticMarkup(<Composer defaultValue="Keep the promo weeks." onVoice={() => {}} affordances={verbs} />)
    assert.match(declaring(text, 'vault.rooms.speak'), /data-mode="send"/)
  })

  test('SplitPane.Head and SplitPane.Thing: close, and the write box', () => {
    const head = renderToStaticMarkup(<SplitPane.Head title="Tasks" onClose={() => {}} affordances={{ close: affordance({ verb: 'app.pane.close', params: { pane: 'tasks' } }) }} />)
    assert.match(declaring(head, 'app.pane.close'), /sl-split-head-close/)
    const thing = renderToStaticMarkup(
      <SplitPane>
        <SplitPane.Pane />
        <SplitPane.Thing
          title="Which stores are in?"
          onClose={() => {}}
          affordances={{ close: affordance({ verb: 'app.pane.close' }), field: affordance({ verb: 'app.draft.set' }), send: affordance({ verb: 'vault.threads.reply' }) }}
        />
      </SplitPane>,
    )
    assert.match(declaring(thing, 'app.pane.close'), /sl-split-head-close/)
    assert.match(declaring(thing, 'app.draft.set'), /^<input/)
    assert.match(declaring(thing, 'vault.threads.reply'), /sl-composer-send/)
  })

  test('NeedsYou.YesNo: the check and the cross', () => {
    const html = renderToStaticMarkup(
      <NeedsYou aria-label="asks">
        <NeedsYou.Ask id="extracts" question="Pull paid registry extracts at ¥800 each?">
          <NeedsYou.YesNo affordances={{ yes: affordance({ verb: 'vault.asks.answer', params: { answer: 'yes' }, gate: 'person' }), no: affordance({ verb: 'vault.asks.answer', params: { answer: 'no' }, gate: 'person' }) }} />
        </NeedsYou.Ask>
      </NeedsYou>,
    )
    assert.match(declaring(html, 'vault.asks.answer'), /data-kind="yes"/)
    assert.match(html, /data-kind="no"[^>]*data-verb="vault.asks.answer"|data-verb="vault.asks.answer"[^>]*data-verb-params="\{&quot;answer&quot;:&quot;no&quot;\}"/)
  })

  test('ComposedCard.Foot: more and the action', () => {
    const html = renderToStaticMarkup(
      <ComposedCard.Foot
        more="show 10 more"
        action="use this list"
        affordances={{ more: affordance({ verb: 'app.card.more' }), action: affordance({ verb: 'vault.lists.use', gate: 'proposed' }) }}
      />,
    )
    assert.match(declaring(html, 'app.card.more'), /sl-composed-foot-more/)
    assert.match(declaring(html, 'vault.lists.use'), /sl-composed-foot-action/)
  })
})
