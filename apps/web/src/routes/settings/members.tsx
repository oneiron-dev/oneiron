import * as React from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { cue, markCued } from '~/components/safelight/hooks'
import { CLOCK, Empty, Fold, LedgerHead, PaneHead, Sheet, TODAY, useEscLayer, useLedger, type Col } from './-shared'

export const Route = createFileRoute('/settings/members')({
  component: MembersPage,
})

/* ── members: who reaches this vault, and how far ── */
type Role = 'owner' | 'member' | 'guest'
type Member = {
  id: string
  seal: string
  name: string
  cls?: string
  role: Role
  reach: string
  reachTip: string
  seen: string
  seenKey: string
  settled?: string
  gone?: boolean
}
const MEMBERS: Member[] = [
  {
    id: 'o',
    seal: 'o',
    name: 'Owen',
    role: 'owner',
    reach: 'everything',
    reachTip: 'every world, plus grants, export and forget',
    seen: `today ${CLOCK}`,
    seenKey: `${TODAY} ${CLOCK}`,
  },
  {
    id: 'y',
    seal: 'y',
    name: 'Yuki',
    role: 'member',
    reach: 'base · clients',
    reachTip: 'worlds base and clients · writes land, sends still ask',
    seen: 'today 11:04',
    seenKey: `${TODAY} 11:04`,
  },
  {
    id: 'm',
    seal: 'm',
    name: 'Mika Tanaka',
    cls: 'seal-class',
    role: 'guest',
    reach: 'clients/hokuei · read',
    reachTip: 'one org, read only · the pass expires 2026-09-30, then she is a contact again',
    seen: '08-12 10:41',
    seenKey: '2026-08-12 10:41',
  },
]
const ROLE_RANK: Record<Role, number> = { owner: 0, member: 1, guest: 2 }

const COLS: Col<Member>[] = [
  { id: 'who', header: 'who', accessor: (m) => m.name, size: 176 },
  { id: 'role', header: 'role', accessor: (m) => ROLE_RANK[m.role], size: 88 },
  { id: 'reach', header: 'reach', accessor: (m) => m.reach },
  { id: 'seen', header: 'last here', accessor: (m) => m.seenKey, size: 112 },
  { id: 'acts', header: '', size: 220 },
]

function MembersPage() {
  const [members, setMembers] = React.useState<Member[]>(MEMBERS)
  const patch = (id: string, p: Partial<Member>) =>
    setMembers((ms) => ms.map((m) => (m.id === id ? { ...m, ...p } : m)))

  /* the role chooser sits in the acts cell; esc closes it (before the
     ledger's selection) */
  const [choosing, setChoosing] = React.useState<string | null>(null)
  useEscLayer(!!choosing, () => setChoosing(null))

  /* invite: unfolds under the head an address field + role chips;
     Enter settles: a new row lands, seal = first letter, reach pending */
  const [inviting, setInviting] = React.useState(false)
  const [addr, setAddr] = React.useState('')
  const [invRole, setInvRole] = React.useState<'member' | 'guest'>('member')
  const addrRef = React.useRef<HTMLInputElement>(null)
  useEscLayer(inviting, () => setInviting(false))
  React.useEffect(() => {
    if (inviting) addrRef.current?.focus()
  }, [inviting])

  const ledger = useLedger<Member>({
    rows: members,
    columns: COLS,
    getId: (m) => m.id,
    searchable: (m) => `${m.name} ${m.role} ${m.reach}`,
  })
  const [landed, setLanded] = React.useState<string[]>([])
  const commitInvite = () => {
    const a = addr.trim()
    if (!a) return
    const name = a.split('@')[0]
    const id = `inv-${Date.now()}`
    setMembers((ms) => [
      {
        id,
        seal: name.charAt(0),
        name,
        role: invRole,
        reach: 'pending',
        reachTip: `${invRole} · reach lands when ${name} accepts`,
        seen: '',
        seenKey: '',
        settled: `invited · ${CLOCK}`,
      },
      ...ms,
    ])
    setLanded((l) => [...l, id])
    setAddr('')
    setInviting(false)
    cue('success')
  }

  const pick = (m: Member, next: Role) => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    patch(m.id, { role: next, settled: `${m.role} → ${next} · ${CLOCK} · receipted` })
    setChoosing(null)
    cue('success')
  }
  const remove = (m: Member) => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    patch(m.id, { gone: true, settled: `removed · ${CLOCK} · receipted` })
    setChoosing(null)
    cue('press')
  }

  return (
    <Sheet page="members">
      <PaneHead
        title="members"
        hint="Who reaches this vault, and how far."
        search={{ value: ledger.query, onChange: ledger.setQuery, onKeyDown: ledger.onKeyDown }}
        tools={
          <button
            className="act"
            aria-expanded={inviting}
            aria-controls="invite-fold"
            title="verb: invite · an address and a role; the invite lands as a row"
            onClick={(e) => {
              markCued(e)
              setInviting((o) => !o)
              cue('toggle')
            }}
          >
            invite
          </button>
        }
      />
      <div className={inviting ? 'fold on invite' : 'fold invite'} id="invite-fold" aria-hidden={!inviting}>
        <div className="fold-in">
          <div className="fold-body invite-row">
            <input
              ref={addrRef}
              className="field"
              type="email"
              value={addr}
              placeholder="address"
              aria-label="address to invite"
              tabIndex={inviting ? 0 : -1}
              onChange={(e) => setAddr(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault()
                  commitInvite()
                }
              }}
            />
            <span className="chips" role="group" aria-label="role">
              {(['member', 'guest'] as const).map((r) => (
                <button
                  key={r}
                  type="button"
                  className={invRole === r ? 'chip on' : 'chip'}
                  aria-pressed={invRole === r}
                  tabIndex={inviting ? 0 : -1}
                  onClick={() => {
                    setInvRole(r)
                    cue('toggle')
                  }}
                >
                  {r}
                </button>
              ))}
            </span>
            <button className={addr.trim() ? 'act' : 'act disarmed'} aria-disabled={!addr.trim()} tabIndex={inviting ? 0 : -1} title="Enter also sends it" onClick={commitInvite}>
              send
            </button>
          </div>
        </div>
      </div>

      <div className="ledger-wrap" tabIndex={-1} onKeyDown={ledger.onKeyDown}>
        <table className="ledger m-ledger">
          <LedgerHead columns={COLS} sort={ledger.sort} onSort={ledger.toggleSort} />
          <tbody>
            {ledger.view.length === 0 && <Empty cols={COLS.length} what="No member matches that." />}
            {ledger.view.map((m) => {
              const isSel = ledger.sel === m.id
              const isOpen = ledger.open === m.id
              const others = (['member', 'guest'] as Role[]).filter((r) => r !== m.role)
              const cls = ['row', m.gone ? 'gone' : '', isSel ? 'selected' : '', landed.includes(m.id) ? 'landed' : ''].filter(Boolean).join(' ')
              return (
                <React.Fragment key={m.id}>
                  <tr
                    className={cls}
                    aria-selected={isSel}
                    aria-expanded={isOpen}
                    onClick={(e) => {
                      if ((e.target as HTMLElement).closest('a, button, input')) return
                      ledger.clickRow(m.id, e)
                    }}
                  >
                    <td>
                      <span className="who">
                        <span className={`seal seal-human${m.cls ? ` ${m.cls}` : ''}`} title={`${m.seal} · ${m.name} · ${m.role}`}>
                          {m.seal}
                        </span>
                        <span className={m.role === 'guest' ? 'nm guest' : 'nm'}>{m.name}</span>
                      </span>
                    </td>
                    <td>
                      <span className="role">{m.role}</span>
                    </td>
                    <td>
                      <span className="scope" title={m.reachTip}>
                        {m.reach}
                      </span>
                    </td>
                    <td>
                      <span className="meta-line" title={m.seenKey ? `last here · ${m.seenKey}` : 'not here yet'}>
                        {m.seen}
                      </span>
                    </td>
                    <td>
                      <span className="racts">
                        {m.role === 'owner' ? null : m.settled ? (
                          <span className="settled">{m.settled}</span>
                        ) : choosing === m.id ? (
                          <span className="chooser" role="group" aria-label={`new role for ${m.name}`}>
                            <span className="label">role</span>
                            {others.map((r) => (
                              <a className="act" href="#" key={r} title={`verb: set_role · ${m.name} becomes ${r}`} onClick={pick(m, r)}>
                                {r}
                              </a>
                            ))}
                            <a
                              className="act"
                              href="#"
                              title="keep the role"
                              onClick={(e) => {
                                e.preventDefault()
                                markCued(e)
                                setChoosing(null)
                                cue('toggle')
                              }}
                            >
                              keep
                            </a>
                          </span>
                        ) : (
                          <>
                            <button
                              className="act"
                              aria-expanded={false}
                              title={`verb: set_role · ${m.name} is a ${m.role}`}
                              onClick={(e) => {
                                markCued(e)
                                setChoosing(m.id)
                                cue('toggle')
                              }}
                            >
                              change role
                            </button>
                            <a
                              className="act"
                              href="#"
                              data-danger
                              title={`verb: remove_member · ${m.name} loses reach now; what they did keeps its receipts`}
                              onClick={remove(m)}
                            >
                              remove
                            </a>
                          </>
                        )}
                      </span>
                    </td>
                  </tr>
                  <Fold open={isOpen} cols={COLS.length}>
                    <span className="glance">{m.reachTip}</span>
                    {m.seenKey && <span className="meta-line">last here · {m.seenKey}</span>}
                  </Fold>
                </React.Fragment>
              )
            })}
          </tbody>
        </table>
      </div>
    </Sheet>
  )
}
