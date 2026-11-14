import { createFileRoute } from '@tanstack/react-router'
import * as React from 'react'
import designSystemCss from '~/design-system/design-system.css?url'
import {
  Field,
  Icon,
  IconAction,
  Island,
  Menu,
  PickDiamond,
  PrimaryButton,
  SafelightRoot,
  TextField,
  Verb,
  affordance,
  readAffordances,
  type Affordance,
  type AffordanceGate,
  type AffordanceState,
} from '~/design-system'
import galleryCss from './-gallery.css?url'

export const Route = createFileRoute('/library/verbs')({
  head: () => ({
    meta: [{ title: 'Safelight library: verbs' }],
    links: [
      { rel: 'stylesheet', href: designSystemCss },
      { rel: 'stylesheet', href: galleryCss },
    ],
  }),
  component: VerbsPage,
})

/* What a gate means for the person, in words. */
const GATE_WORD: Record<AffordanceGate, string> = {
  auto: 'free',
  proposed: 'asks you',
  person: 'only you',
}

const ROOM = 'acme-forecast'
const ROLES = ['member', 'guest'] as const

/* A control's state in words: its text, checked, open, off. */
function stateWords(state: AffordanceState, secret: boolean): string {
  const words: string[] = []
  if (state.value !== undefined) words.push(state.value ? `“${state.value}”` : 'empty')
  else if (secret) words.push('value left out')
  if (state.checked !== undefined) words.push(state.checked === 'mixed' ? 'part chosen' : state.checked ? 'chosen' : 'not chosen')
  if (state.expanded !== undefined) words.push(state.expanded ? 'open' : 'closed')
  if (state.disabled) words.push('off')
  if (state.current) words.push('here')
  return words.join(', ')
}

/* The declared verbs under a region, read again whenever its controls
   change (a value, a pick, a menu that opens). */
function useAffordances(region: React.RefObject<HTMLElement | null>): Affordance[] {
  const [list, setList] = React.useState<Affordance[]>([])
  React.useEffect(() => {
    const root = region.current
    if (!root) return
    let frame = 0
    const read = () => {
      cancelAnimationFrame(frame)
      frame = requestAnimationFrame(() => setList(readAffordances(root)))
    }
    read()
    const observer = new MutationObserver(read)
    observer.observe(root, { subtree: true, childList: true, attributes: true, characterData: true })
    root.addEventListener('input', read)
    root.addEventListener('toggle', read, true)
    return () => {
      cancelAnimationFrame(frame)
      observer.disconnect()
      root.removeEventListener('input', read)
      root.removeEventListener('toggle', read, true)
    }
  }, [region])
  return list
}

/* A screen whose controls declare the verbs they run, and beside it the
   list readAffordances returns for that screen: the same verbs an agent
   acting for the person would call. */
function VerbsPage() {
  const screenRef = React.useRef<HTMLDivElement | null>(null)
  const [name, setName] = React.useState('Yuki')
  const [role, setRole] = React.useState<(typeof ROLES)[number]>('guest')
  const [log, setLog] = React.useState('')
  const list = useAffordances(screenRef)

  return (
    <SafelightRoot className="lib">
      <Field />
      <header className="lib-head">
        <h1 className="lib-title">Verbs</h1>
        <a className="lib-head-link" href="/library">
          the library
        </a>
      </header>
      <Island className="lib-island">
        <div className="lib-verbs">
          <div ref={screenRef} className="lib-verbs-screen" role="region" aria-label="invite to # acme-forecast" data-specimen="verbs-screen">
            <div className="lib-verbs-head">
              <h2 className="lib-section-head">Invite to # {ROOM}</h2>
              <Menu>
                <Menu.Trigger asChild>
                  <IconAction label="More" {...affordance({ verb: 'app.menu.open', params: { menu: 'room' } })} data-specimen="verbs-more">
                    <Icon name="more" />
                  </IconAction>
                </Menu.Trigger>
                <Menu.Content align="end" aria-label="the room">
                  <Menu.Item icon={<Icon name="pin" />} onClick={() => setLog('pinned to the room')} {...affordance({ verb: 'vault.rooms.pins.add', params: { room: ROOM }, gate: 'proposed' })}>
                    pin to the room
                  </Menu.Item>
                  <Menu.Item icon={<Icon name="link" />} onClick={() => setLog('copied the link')} {...affordance({ verb: 'app.link.copy', params: { room: ROOM } })}>
                    copy the link
                  </Menu.Item>
                  <Menu.Item icon={<Icon name="signOut" />} onClick={() => setLog('left the room')} {...affordance({ verb: 'vault.rooms.leave', params: { room: ROOM }, gate: 'person' })}>
                    leave the room
                  </Menu.Item>
                </Menu.Content>
              </Menu>
            </div>
            <form
              className="lib-verbs-form"
              onSubmit={(event) => {
                event.preventDefault()
                setLog(`invited ${name} as a ${role}`)
              }}
            >
              <TextField label="Name" value={name} onValueChange={setName} autoComplete="off" {...affordance({ verb: 'app.draft.set', params: { field: 'name' } })} />
              <div className="lib-picks" role="group" aria-label="role">
                {ROLES.map((r) => (
                  <button
                    key={r}
                    type="button"
                    className="lib-pick"
                    aria-pressed={role === r}
                    onClick={() => setRole(r)}
                    {...affordance({ verb: 'app.draft.set', params: { field: 'role', role: r } })}
                  >
                    <PickDiamond chosen={role === r} />
                    {r}
                  </button>
                ))}
              </div>
              <div data-agent-secret="">
                <TextField label="A note to them" defaultValue="Welcome to the Q4 view." autoComplete="off" {...affordance({ verb: 'app.draft.set', params: { field: 'note' } })} />
              </div>
              <div className="lib-verbs-actions">
                <PrimaryButton type="submit" disabled={!name.trim()} {...affordance({ verb: 'vault.rooms.invite', params: { room: ROOM }, gate: 'proposed' })}>
                  invite
                </PrimaryButton>
                <Verb onClick={() => setName('')} {...affordance({ verb: 'app.draft.clear', params: { field: 'name' } })}>
                  clear
                </Verb>
              </div>
            </form>
            <p className="lib-readout" data-specimen="verbs-log">
              {log || 'Nothing done yet.'}
            </p>
          </div>

          <section className="lib-verbs-list" aria-labelledby="lib-verbs-list-head" data-specimen="verbs-list">
            <h2 id="lib-verbs-list-head" className="lib-section-head">
              What can be done here
            </h2>
            <table className="lib-verbs-table">
              <thead>
                <tr>
                  <th scope="col">name</th>
                  <th scope="col">verb</th>
                  <th scope="col">state</th>
                  <th scope="col">gate</th>
                </tr>
              </thead>
              <tbody>
                {list.map((a, i) => (
                  <tr key={i}>
                    <td>{a.name || 'no name'}</td>
                    <td className="lib-verbs-verb">{a.verb}</td>
                    <td>{stateWords(a.state, !!a.ref.closest('[data-agent-secret]'))}</td>
                    <td>{GATE_WORD[a.gate]}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        </div>
      </Island>
    </SafelightRoot>
  )
}
