import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { MicroSidebar } from '../src/design-system/frame/MicroSidebar'
import { AppFrameContext, useMicroSidebarPeek, type AppFrameContextValue, type MicroSidebarPeek } from '../src/design-system/frame/app-frame-context'
import * as library from '../src/design-system'

/* A frame that records what its items report. */
function recordingFrame(peekId: string | null, log: string[]): AppFrameContextValue {
  return {
    sidebarShown: false,
    hasSidebar: true,
    setSidebarOpen: () => {},
    peekId,
    itemPointerEnter: (id) => log.push(`enter ${id}`),
    itemPointerLeave: (id) => log.push(`leave ${id}`),
    itemPointerDown: (id) => log.push(`down ${id}`),
    itemKeyDown: (id, event) => log.push(`key ${id} ${event.key}`),
  }
}

/* Renders a caller's item that reads the hook, and hands back what it read. */
function readPeek(frame: AppFrameContextValue | null, id: string | undefined): MicroSidebarPeek {
  let read: MicroSidebarPeek | null = null
  function OwnItem() {
    read = useMicroSidebarPeek(id)
    return <div {...read.itemProps} />
  }
  renderToStaticMarkup(frame ? <AppFrameContext.Provider value={frame}><OwnItem /></AppFrameContext.Provider> : <OwnItem />)
  assert.ok(read)
  return read
}

describe('a microsidebar item of the caller’s own', () => {
  test('the library exports the hook, not the frame’s context', () => {
    assert.equal(typeof library.useMicroSidebarPeek, 'function')
    assert.equal('AppFrameContext' in library, false)
  })

  test('inside a frame the item reports its pointer and keys and knows when its sidebar peeks', () => {
    const log: string[] = []
    const peek = readPeek(recordingFrame('eiri', log), 'eiri')
    assert.equal(peek.peeking, true)
    assert.equal(peek.itemProps['data-micro-sidebar-id'], 'eiri')
    const pointer = {} as React.PointerEvent<HTMLElement>
    peek.itemProps.onPointerEnter?.(pointer)
    peek.itemProps.onPointerDown?.(pointer)
    peek.itemProps.onPointerLeave?.(pointer)
    peek.onControlKeyDown({ key: 'ArrowRight', defaultPrevented: false } as React.KeyboardEvent<HTMLElement>)
    peek.onControlKeyDown({ key: 'ArrowRight', defaultPrevented: true } as React.KeyboardEvent<HTMLElement>)
    assert.deepEqual(log, ['enter eiri', 'down eiri', 'leave eiri', 'key eiri ArrowRight'])
    assert.equal(readPeek(recordingFrame('activity', []), 'eiri').peeking, false)
  })

  test('outside a frame it does nothing', () => {
    const peek = readPeek(null, 'eiri')
    assert.equal(peek.peeking, false)
    assert.equal(peek.itemProps.onPointerEnter, undefined)
  })
})

describe('MicroSidebar.Item', () => {
  test('the tooltip carries a caption, the quiet second line', () => {
    const html = renderToStaticMarkup(
      <MicroSidebar aria-label="places">
        <MicroSidebar.Item id="eiri" icon={<span />} label="eiri" caption="your companion" />
      </MicroSidebar>,
    )
    assert.match(html, /<span class="sl-tooltip-label">eiri<\/span>/)
    assert.match(html, /class="sl-tooltip-caption">your companion<\/span>/)
  })
})
