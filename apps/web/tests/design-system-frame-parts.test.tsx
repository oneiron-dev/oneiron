import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { AppFrame } from '../src/design-system/frame/AppFrame'
import { AppFramePeekContext } from '../src/design-system/frame/app-frame-context'
import { MicroSidebar } from '../src/design-system/frame/MicroSidebar'
import { Sidebar } from '../src/design-system/frame/Sidebar'
import { VaultSwitch } from '../src/design-system/frame/VaultSwitch'
import { Icon } from '../src/design-system/primitives/Icon'
import { IconAction } from '../src/design-system/primitives/IconAction'

/* The opening tag of the first element carrying `attribute`. */
function tagWith(html: string, attribute: string): string {
  const at = html.indexOf(attribute)
  assert.ok(at >= 0, `no element with ${attribute}`)
  const start = html.lastIndexOf('<', at)
  return html.slice(start, html.indexOf('>', at) + 1)
}

const VAULTS = [
  { id: 'antevon', name: 'antevon' },
  { id: 'owen', name: 'owen' },
]

function HomeHeadParts() {
  return (
    <>
      <VaultSwitch vaults={VAULTS} currentId="antevon" />
      <IconAction label="Search">
        <Icon name="search" />
      </IconAction>
      <AppFrame.Fold />
    </>
  )
}

function frame(sidebarOpen: boolean) {
  return renderToStaticMarkup(
    <AppFrame
      microSidebar={
        <MicroSidebar>
          <MicroSidebar.VaultMark name="antevon" current />
        </MicroSidebar>
      }
      sidebar={
        <Sidebar aria-label="Home">
          <Sidebar.Head>
            <HomeHeadParts />
          </Sidebar.Head>
          <Sidebar.Group id="top">
            <Sidebar.Row id="eiri" label="eiri" />
          </Sidebar.Group>
        </Sidebar>
      }
      sidebarOpen={sidebarOpen}
    >
      <p>work</p>
    </AppFrame>,
  )
}

describe('MicroSidebar.VaultMark', () => {
  test('is a button named by the vault, the home item, current while Home shows', () => {
    const html = renderToStaticMarkup(
      <MicroSidebar>
        <MicroSidebar.VaultMark name="antevon" current />
      </MicroSidebar>,
    )
    const item = tagWith(html, 'data-micro-sidebar-id=')
    assert.match(item, /data-micro-sidebar-id="home"/)
    const button = tagWith(html, 'aria-label="antevon"')
    assert.match(button, /^<button/)
    assert.match(button, /type="button"/)
    assert.match(button, /aria-current="page"/)
    assert.match(button, /data-vault-mark=""/)
    /* The mark is the initial, hidden from assistive tech behind the name. */
    assert.match(html, /<span class="sl-micro-vault-mark">A<\/span>/)
    assert.match(tagWith(html, 'class="sl-micro-item-mark"'), /aria-hidden="true"/)
  })

  test('first in the strip; not current elsewhere; a picture replaces the initial', () => {
    const html = renderToStaticMarkup(
      <MicroSidebar>
        <MicroSidebar.VaultMark name="hokuei" picture="/art/mark.png" />
        <MicroSidebar.Item id="activity" icon={<Icon name="activity" />} label="activity" />
      </MicroSidebar>,
    )
    assert.ok(html.indexOf('aria-label="hokuei"') < html.indexOf('aria-label="activity"'))
    assert.doesNotMatch(tagWith(html, 'aria-label="hokuei"'), /aria-current/)
    assert.match(html, /<img src="\/art\/mark.png" alt="" draggable="false"\/>/)
    assert.doesNotMatch(html, />H</)
  })

  test('the initial is the first letter of the name, upper case', () => {
    const html = renderToStaticMarkup(
      <MicroSidebar>
        <MicroSidebar.VaultMark name=" éclair" />
      </MicroSidebar>,
    )
    assert.match(html, /<span class="sl-micro-vault-mark">É<\/span>/)
  })
})

describe('Sidebar.Head', () => {
  test('the vault switch at the left, then search and the fold action', () => {
    const html = frame(true)
    const head = html.slice(html.indexOf('class="sl-sidebar-head"'), html.indexOf('class="sl-sidebar-groups"'))
    const vault = tagWith(head, 'aria-haspopup="menu"')
    assert.match(vault, /^<button/)
    assert.match(vault, /class="[^"]*\bsl-vault-switch\b[^"]*"/)
    assert.match(vault, /aria-expanded="false"/)
    assert.match(head, /<span class="sl-vault-switch-name">antevon<\/span>/)
    const order = ['sl-vault-switch', 'aria-label="Search"', 'aria-label="Fold the sidebar"'].map((m) => head.indexOf(m))
    assert.ok(order.every((at) => at >= 0), `head parts present: ${order}`)
    assert.deepEqual([...order].sort((a, b) => a - b), order)
    assert.match(tagWith(head, 'aria-label="Fold the sidebar"'), /type="button"/)
  })

  test('is the first line of the sidebar, before the groups', () => {
    const html = frame(true)
    assert.ok(html.indexOf('class="sl-sidebar-head"') < html.indexOf('class="sl-sidebar-groups"'))
    assert.match(tagWith(html, 'class="sl-sidebar"'), /aria-label="Home"/)
  })

  test('the frame draws the window ground, the strip and the sheet', () => {
    const html = frame(true)
    const order = ['class="sl-window-ground"', 'class="sl-app-frame-micro"', 'class="sl-app-frame-sheet"', 'class="sl-app-frame-side"', 'class="sl-app-frame-work"'].map((m) => html.indexOf(m))
    assert.ok(order.every((at) => at >= 0), `frame parts present: ${order}`)
    assert.deepEqual([...order].sort((a, b) => a - b), order)
    assert.match(tagWith(html, 'class="sl-app-frame"'), /data-sidebar="open"/)
  })

  test('folded, the fold action opens the sidebar', () => {
    const html = frame(false)
    assert.match(tagWith(html, 'class="sl-app-frame"'), /data-sidebar="folded"/)
    assert.match(html, /aria-label="Open the sidebar"/)
  })

  test('in the peek the fold action stays and keeps the sidebar open', () => {
    const html = renderToStaticMarkup(
      <AppFrame microSidebar={<MicroSidebar />} sidebar={<p>sidebar</p>} sidebarOpen={false}>
        <AppFramePeekContext.Provider value={true}>
          <AppFrame.Fold />
        </AppFramePeekContext.Provider>
      </AppFrame>,
    )
    assert.match(tagWith(html, 'aria-label="Keep the sidebar open"'), /class="sl-icon-action sl-app-frame-fold"/)
  })

  test('the strip carries no fold control', () => {
    const html = frame(false)
    const strip = html.slice(html.indexOf('class="sl-app-frame-micro"'), html.indexOf('class="sl-app-frame-sheet"'))
    assert.doesNotMatch(strip, /sl-app-frame-fold/)
  })
})
