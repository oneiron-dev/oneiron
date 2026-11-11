import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { RoomHead, type RoomPins } from '../src/design-system/frame/RoomHead'
import { Tabs } from '../src/design-system/primitives/Tabs'

function head(pins: RoomPins) {
  return renderToStaticMarkup(
    <Tabs defaultValue="talk">
      <RoomHead
        title="acme-forecast"
        pins={pins}
        filesCount={6}
        tasks={['done', 'working', 'ahead']}
        tasksNeedYou
        crew={<span className="crew">crew</span>}
      >
        <Tabs.Pin value="q4" icon="chart" pinnedBy="Metryon">
          Q4 view
        </Tabs.Pin>
        <Tabs.Pin value="brief" icon="note" pinnedBy="Antevon">
          The brief
        </Tabs.Pin>
        <Tabs.Pin onGo={() => {}} pinnedBy="Owen">
          Can we have the Q4 view by Friday?
        </Tabs.Pin>
      </RoomHead>
    </Tabs>,
  )
}

const order = (html: string, marks: string[]) => {
  const at = marks.map((m) => html.indexOf(m))
  assert.ok(at.every((i) => i >= 0), `all present: ${marks.filter((_, k) => at[k] < 0)}`)
  assert.deepEqual([...at].sort((a, b) => a - b), at)
}

describe('RoomHead', () => {
  test('head: the name, talk, files with its count, the divider, the pins, add, then the tasks and the crew', () => {
    const html = head('head')
    order(html, ['acme-forecast', '>talk<', '>files<', 'sl-tabs-divider', 'Q4 view', 'The brief', 'Can we have the Q4 view by Friday?', 'sl-tabs-add', 'sl-room-head-tasks', 'class="crew"'])
    assert.match(html, /aria-label="3 tasks in this room, something waits on you"/)
    assert.match(html, /data-value="pinned"/)
  })

  test('tab: three fixed tabs, the pins counted on pinned, none on the line', () => {
    const html = head('tab')
    order(html, ['>talk<', '>files<', '>pinned<'])
    assert.match(html, />pinned<span class="sl-figure" data-size="figure">3<\/span>/)
    assert.doesNotMatch(html, /Q4 view|sl-tabs-add|sl-tabs-divider/)
    assert.match(html, /sl-room-head-tasks/)
  })

  test('none: no tabs, no tasks; the outline action at the right after the crew', () => {
    const html = head('none')
    assert.doesNotMatch(html, /role="tablist"|sl-room-head-tasks/)
    order(html, ['acme-forecast', 'class="crew"', 'aria-label="Outline of this room"'])
  })
})
