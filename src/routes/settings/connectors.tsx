import * as React from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { ChanLine, ChanLinkedin, ChanMail, ChanSlack } from '~/components/safelight/icons'
import { cue, markCued } from '~/components/safelight/hooks'
import { CLOCK, Empty, Fold, LedgerHead, PaneHead, ReceiptLines, Sheet, useEscLayer, useLedger, type Col } from './-shared'

export const Route = createFileRoute('/settings/connectors')({
  component: ConnectorsPage,
})

/* ── connectors: where messages come from and go to. the fixtures are the
   channel presences from threads (slack · LINE · email) plus LinkedIn,
   not connected. scope numbers and budgets live on grants; here, state. ── */
type Conn = {
  id: 'slack' | 'line' | 'email' | 'linkedin'
  chan: string
  glyph: React.ReactNode
  handle: string
  aud: string
  audTitle: string
  state: string
  stateTitle: string
  charter: string
  receipts: [string, string][]
  receiptsN: number
  scope: string
  connected: boolean
  settled?: string
}
const CONNS: Conn[] = [
  {
    id: 'slack',
    chan: 'slack',
    glyph: <ChanSlack />,
    handle: 'as @antevon',
    aud: '#ops · antevon workspace',
    audTitle: 'the antevon workspace · #ops and #pilot-hokuei',
    state: 'connected 07-02',
    stateTitle: 'connected 07-02 · granted by o',
    charter: 'Antevon answers in #ops when someone addresses it. It never opens a thread on its own.',
    receipts: [
      ['14:05', 'Moved the freight terms question into #pilot-hokuei.'],
      ['13:41', 'Answered the timeline question with the September start.'],
    ],
    receiptsN: 41,
    scope: 'scope: channel.read · channel.post · granted by o, 07-02',
    connected: true,
  },
  {
    id: 'line',
    chan: 'LINE',
    glyph: <ChanLine />,
    handle: 'as @antevon',
    aud: 'official account · Hokuei contacts',
    audTitle: 'the Antevon official account · 3 contact threads',
    state: 'connected 06-18 · read only',
    stateTitle: 'connected 06-18 · read only · granted by o',
    charter: 'Mika writes to the account, not to an agent. Replies still leave from your hand.',
    receipts: [
      ['09:15', 'Mika Tanaka: a quote request for Tuesday.'],
      ['08-12', 'Mika Tanaka: confirmed the Thursday call.'],
    ],
    receiptsN: 12,
    scope: 'scope: inbound.read · no send verb granted · granted by o, 06-18',
    connected: true,
  },
  {
    id: 'email',
    chan: 'email',
    glyph: <ChanMail />,
    handle: 'as ops@antevon.jp',
    aud: 'clients',
    audTitle: 'a verified sender on a domain you own · replies return to the same thread',
    state: 'verified 06-30',
    stateTitle: 'verified sender · SPF and DKIM pass · verified 06-30 · granted by o',
    charter: 'Recipients see ops@antevon.jp, signed. Their replies come back into the same thread.',
    receipts: [
      ['11:48', 'Pilot scope summary to Hokuei ops.'],
      ['08-11', 'Thursday call agenda to Mika Tanaka.'],
    ],
    receiptsN: 8,
    scope: 'scope: outbound.email · SPF and DKIM pass · verified 06-30',
    connected: true,
  },
  {
    id: 'linkedin',
    chan: 'LinkedIn',
    glyph: <ChanLinkedin />,
    handle: '',
    aud: '',
    audTitle: '',
    state: 'not connected',
    stateTitle: 'no workspace or account yet',
    charter: 'Once connected, Antevon reads the page and sends only under the outreach grant.',
    receipts: [],
    receiptsN: 0,
    scope: 'no scope yet',
    connected: false,
  },
]

const COLS: Col<Conn>[] = [
  { id: 'chan', header: 'channel', accessor: (c) => c.chan, size: 150 },
  { id: 'as', header: 'as', accessor: (c) => c.handle, size: 150 },
  { id: 'aud', header: 'audience', accessor: (c) => c.aud },
  { id: 'state', header: 'state', accessor: (c) => c.state, size: 190 },
  { id: 'acts', header: '', size: 150 },
]

function ConnectorsPage() {
  const [conns, setConns] = React.useState<Conn[]>(CONNS)
  const patch = (id: Conn['id'], p: Partial<Conn>) => setConns((cs) => cs.map((c) => (c.id === id ? { ...c, ...p } : c)))

  /* LinkedIn: connect a workspace → under-row field → settles connected.
     its fold closes on esc before the ledger's selection does */
  const [connecting, setConnecting] = React.useState(false)
  const [ws, setWs] = React.useState('')
  const wsRef = React.useRef<HTMLInputElement>(null)
  useEscLayer(connecting, () => setConnecting(false))
  const ledger = useLedger<Conn>({
    rows: conns,
    columns: COLS,
    getId: (c) => c.id,
    searchable: (c) => `${c.chan} ${c.handle} ${c.aud} ${c.state}`,
  })

  /* revoke: the row cools; the verbs go quiet; the receipt lands */
  const revoke = (c: Conn) => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    patch(c.id, {
      connected: false,
      settled: 'receipted',
      state: `revoked ${CLOCK}`,
      stateTitle: `revoked by o · ${CLOCK} · the threads it brought stay`,
      receipts: [[CLOCK, 'Revoked by Owen. The reach stops here; the threads stay in the vault.'], ...c.receipts],
    })
    ledger.setSel(c.id)
    ledger.setOpen(c.id)
    cue('press')
  }
  React.useEffect(() => {
    if (connecting) wsRef.current?.focus()
  }, [connecting])
  const commitConnect = () => {
    const w = ws.trim()
    if (!w) return
    patch('linkedin', {
      connected: true,
      handle: `as ${w.startsWith('@') ? w : `@${w}`}`,
      aud: 'the page · its followers',
      audTitle: 'the LinkedIn page and the people who follow it',
      state: `connected ${CLOCK}`,
      stateTitle: `connected ${CLOCK} · granted by o`,
      settled: 'receipted',
      scope: `scope: page.read · granted by o, ${CLOCK}`,
      receipts: [[CLOCK, `Connected ${w}. Reads the page; sends only under the outreach grant.`]],
    })
    setConnecting(false)
    setWs('')
    ledger.setSel('linkedin')
    ledger.setOpen('linkedin')
    cue('success')
  }

  return (
    <Sheet page="connectors">
      <PaneHead
        title="connectors"
        hint="Where messages come from and go to. Revoking stops the reach; threads already in the vault stay."
        search={{ value: ledger.query, onChange: ledger.setQuery, onKeyDown: ledger.onKeyDown }}
      />
      <div className="ledger-wrap" tabIndex={-1} onKeyDown={ledger.onKeyDown}>
        <table className="ledger c-ledger">
          <LedgerHead columns={COLS} sort={ledger.sort} onSort={ledger.toggleSort} />
          <tbody>
            {ledger.view.length === 0 && <Empty cols={COLS.length} what="No connector matches that." />}
            {ledger.view.map((c) => {
              const isSel = ledger.sel === c.id
              const isOpen = ledger.open === c.id
              const gone = !c.connected && !!c.settled
              const cls = ['row', gone ? 'gone' : '', isSel ? 'selected' : ''].filter(Boolean).join(' ')
              const isLinkedinOpen = c.id === 'linkedin' && connecting
              return (
                <React.Fragment key={c.id}>
                  <tr
                    className={cls}
                    aria-selected={isSel}
                    aria-expanded={isOpen}
                    onClick={(e) => {
                      if ((e.target as HTMLElement).closest('a, button, input')) return
                      ledger.clickRow(c.id, e)
                    }}
                  >
                    <td>
                      <span className="who chan">
                        <span className="chan-glyph" aria-hidden="true">
                          {c.glyph}
                        </span>
                        <span className="nm">{c.chan}</span>
                      </span>
                    </td>
                    <td>
                      <span className="scope" title={c.scope}>
                        {c.handle}
                      </span>
                    </td>
                    <td>
                      <span className="aud" title={c.audTitle}>
                        {c.aud}
                      </span>
                    </td>
                    <td>
                      <span className="meta-line" title={c.stateTitle}>
                        {c.state}
                      </span>
                    </td>
                    <td>
                      <span className="racts">
                        {c.settled ? (
                          <span className="settled">{c.settled}</span>
                        ) : c.connected ? (
                          <a
                            className="act"
                            href="#"
                            data-danger
                            title="verb: revoke_connector · the reach stops now; the threads it brought stay"
                            onClick={revoke(c)}
                          >
                            revoke
                          </a>
                        ) : (
                          <button
                            className="act"
                            aria-expanded={isLinkedinOpen}
                            aria-controls="connect-fold"
                            title="verb: connect · a workspace or account; the reach is granted by your click"
                            onClick={(e) => {
                              markCued(e)
                              setConnecting((o) => !o)
                              cue('toggle')
                            }}
                          >
                            connect a workspace
                          </button>
                        )}
                      </span>
                    </td>
                  </tr>
                  {c.id === 'linkedin' && !c.connected && (
                    <Fold open={isLinkedinOpen} cols={COLS.length} id="connect-fold">
                      <div className="invite-row">
                        <input
                          ref={wsRef}
                          className="field"
                          value={ws}
                          placeholder="workspace or account"
                          aria-label="workspace or account"
                          tabIndex={isLinkedinOpen ? 0 : -1}
                          onChange={(e) => setWs(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter') {
                              e.preventDefault()
                              commitConnect()
                            }
                          }}
                        />
                        <button className={ws.trim() ? 'act' : 'act disarmed'} aria-disabled={!ws.trim()} tabIndex={isLinkedinOpen ? 0 : -1} title="Enter also connects it" onClick={commitConnect}>
                          connect
                        </button>
                      </div>
                    </Fold>
                  )}
                  <Fold open={isOpen} cols={COLS.length}>
                    <span className="glance">{c.charter}</span>
                    {c.receipts.length > 0 && <ReceiptLines lines={c.receipts.slice(0, 2)} />}
                    {c.receiptsN > 2 && (
                      <a className="act more" href="/app/threads" title="every receipt, in threads">
                        {c.receiptsN - 2} more
                      </a>
                    )}
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
