import * as React from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { cue, markCued } from '~/components/safelight/hooks'
import { CLOCK, Empty, Fold, LedgerHead, PaneHead, ReceiptLines, Sheet, TODAY, useLedger, type Col } from './-shared'

export const Route = createFileRoute('/settings/grants')({
  component: GrantsPage,
})

/* ── grants: what each agent may do, how much, and until when. the
   load-bearing ledger. new grants are minted on the agents page. ── */
type State = 'live' | 'spent' | 'revoked'
type Grant = {
  id: string
  name: string
  who: React.ReactNode
  scope: string
  scopeTip: string
  budget: string
  expires: string
  receipts: [string, string][]
  state: State
  revocable: boolean
  gone?: string
}
const GRANTS: Grant[] = [
  {
    id: 'eiri',
    name: 'Eiri',
    who: (
      <a className="aname" data-agent="eiri" href="/app/agents" title="Eiri · outbound companion · bound to oleksii · open the agent">
        Eiri
      </a>
    ),
    scope: 'outbound.email · hokuei.co.jp',
    scopeTip: 'send email as antevon, to one domain, nothing else',
    budget: '20 sends a month · 6 used',
    expires: '2026-10-07',
    receipts: [
      ['08-12 16:20', 'Sent the pilot quote to mika@hokuei.co.jp. You approved it in the inbox.'],
      ['08-06 09:41', 'Sent the audit summary. Delivery verified, then receipted.'],
    ],
    state: 'live',
    revocable: true,
  },
  {
    id: 'tory',
    name: 'Tory',
    who: (
      <a className="aname" data-agent="tory" href="/app/agents" title="Tory · research companion · open the agent">
        Tory
      </a>
    ),
    scope: 'read.web · read.world:clients',
    scopeTip: 'public web plus the clients world, read only · it never writes a claim without review',
    budget: '$4 a day · $0.31 today',
    expires: 'open',
    receipts: [
      ['08-13 13:14', 'Read 6 public filings for the supplier rumor. Two proposed claims wait in the inbox.'],
      ['08-11 08:02', 'Read the clients world, 41 claims. Nothing written.'],
    ],
    state: 'live',
    revocable: true,
  },
  {
    id: 'antevon',
    name: 'Antevon',
    who: (
      <a className="aname" data-agent="antevon" href="/app/agents" title="Antevon · the house mind · local model · open the agent">
        Antevon
      </a>
    ),
    scope: 'read.vault · write.summary',
    scopeTip: 'reads the vault, writes summaries only · summaries recompile, they never overwrite a claim',
    budget: 'local model · ¥0',
    expires: 'open',
    receipts: [
      ['08-13 13:44', 'Recompiled 2 summaries whose evidence moved. Nothing left the machine.'],
      ['08-13 03:12', 'Nightly consolidation. One summary retired, its claims kept.'],
    ],
    state: 'live',
    revocable: true,
  },
  {
    id: 'importer',
    name: 'importer',
    who: (
      <span className="who">
        <span className="seal seal-system" title="im · importer · system actor">
          im
        </span>
        <span className="nm">importer</span>
      </span>
    ),
    scope: 'import.mail · fastmail archive',
    scopeTip: 'one pass over one mailbox · credentials discarded after it, so a spent grant cannot be used twice',
    budget: 'one pass · 11,204 messages',
    expires: 'spent 08-05',
    receipts: [['08-05 22:40', '318 sources read. 96 claims proposed, 61 accepted. Learned dates set to the import.']],
    state: 'spent',
    revocable: false,
  },
  {
    id: 'slack',
    name: 'slack connector',
    who: (
      <span className="who">
        <span className="seal seal-system" title="sl · slack connector · system actor">
          sl
        </span>
        <span className="nm">slack connector</span>
      </span>
    ),
    scope: 'read.messages · #ops',
    scopeTip: 'revoked · the scope is dead, the reading it did is not',
    budget: 'was 2 GB·days a month',
    expires: 'revoked 08-11',
    receipts: [
      ['08-11 16:20', 'Revoked by oleksii. The workspace moved to a new plan.'],
      ['', '41 receipts stay. 12 claims it brought in keep their sources and their learned dates.'],
    ],
    state: 'revoked',
    revocable: false,
    gone: 'revoked · 08-11 16:20 · receipted',
  },
]

const COLS: Col<Grant>[] = [
  { id: 'who', header: 'who', accessor: (g) => g.name, size: 176 },
  { id: 'scope', header: 'scope', accessor: (g) => g.scope },
  { id: 'budget', header: 'budget', accessor: (g) => g.budget, size: 176 },
  { id: 'expires', header: 'expires', accessor: (g) => g.expires, size: 112 },
  { id: 'acts', header: '', size: 200 },
]
const STATES: State[] = ['live', 'spent', 'revoked']

function GrantsPage() {
  const [grants, setGrants] = React.useState<Grant[]>(GRANTS)
  const [chip, setChip] = React.useState<State | null>(null)
  const filter = React.useCallback((g: Grant) => !chip || g.state === chip, [chip])
  const ledger = useLedger<Grant>({
    rows: grants,
    columns: COLS,
    getId: (g) => g.id,
    searchable: (g) => `${g.name} ${g.scope} ${g.budget} ${g.expires} ${g.state}`,
    filter,
  })

  const revoke = (g: Grant) => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setGrants((gs) =>
      gs.map((x) =>
        x.id === g.id
          ? {
              ...x,
              state: 'revoked',
              gone: `revoked · ${CLOCK} · receipted`,
              receipts: [[`${TODAY.slice(5)} ${CLOCK}`, 'Revoked by oleksii. The reach ends now; the receipts stay.'], ...x.receipts],
            }
          : x,
      ),
    )
    ledger.setOpen(g.id)
    ledger.setSel(g.id)
    cue('press')
  }

  const live = grants.filter((g) => g.state === 'live').length
  const revoked = grants.filter((g) => g.state === 'revoked').length

  return (
    <Sheet page="grants">
      <PaneHead
        title="grants"
        hint="What each agent may do, how much, and until when. Revoking is not erasing."
        meta={
          <span className="meta-line head-meta">
            {live} live · {revoked} revoked
          </span>
        }
        search={{ value: ledger.query, onChange: ledger.setQuery, onKeyDown: ledger.onKeyDown }}
      />
      <div className="filters">
        <span className="set" role="group" aria-label="state">
          {STATES.map((s) => (
            <button
              key={s}
              type="button"
              className={chip === s ? 'chip on' : 'chip'}
              aria-pressed={chip === s}
              onClick={() => {
                setChip((c) => (c === s ? null : s))
                cue('toggle')
              }}
            >
              {s}
            </button>
          ))}
        </span>
      </div>

      <div className="ledger-wrap" tabIndex={-1} onKeyDown={ledger.onKeyDown}>
        <table className="ledger g-ledger">
          <LedgerHead columns={COLS} sort={ledger.sort} onSort={ledger.toggleSort} />
          <tbody>
            {ledger.view.length === 0 && <Empty cols={COLS.length} what="No grant matches that." />}
            {ledger.view.map((g) => {
              const gone = g.state === 'revoked'
              const isSel = ledger.sel === g.id
              const isOpen = ledger.open === g.id
              const cls = ['row', gone ? 'gone' : '', isSel ? 'selected' : ''].filter(Boolean).join(' ')
              return (
                <React.Fragment key={g.id}>
                  <tr
                    className={cls}
                    data-grant={g.id}
                    aria-selected={isSel}
                    aria-expanded={isOpen}
                    onClick={(e) => {
                      if ((e.target as HTMLElement).closest('a, button')) return
                      ledger.clickRow(g.id, e)
                    }}
                  >
                    <td>{g.who}</td>
                    <td>
                      <span className="scope" title={g.scopeTip}>
                        {g.scope}
                      </span>
                    </td>
                    <td>
                      <span className="meta-line">{g.budget}</span>
                    </td>
                    <td>
                      <span className="meta-line">{g.expires}</span>
                    </td>
                    <td>
                      <span className="racts">
                        {g.gone && <span className="settled">{g.gone}</span>}
                        <button
                          className="act"
                          aria-expanded={isOpen}
                          aria-controls={`g-${g.id}`}
                          title={isOpen ? 'fold the receipts back' : 'verb: open_receipts · what this grant paid for, in place'}
                          onClick={(e) => {
                            markCued(e)
                            ledger.clickRow(g.id, e)
                          }}
                        >
                          receipts
                        </button>
                        {g.revocable && !gone && (
                          <a
                            className="act"
                            href="#"
                            data-danger
                            title="verb: revoke_grant · the reach ends at once; what it already did stays on the record"
                            onClick={revoke(g)}
                          >
                            revoke
                          </a>
                        )}
                      </span>
                    </td>
                  </tr>
                  <Fold open={isOpen} cols={COLS.length} id={`g-${g.id}`}>
                    <ReceiptLines lines={g.receipts} />
                  </Fold>
                </React.Fragment>
              )
            })}
          </tbody>
        </table>
      </div>
      <span className="note">Revoking is not erasing. The reach ends now. What the grant already did keeps its receipts.</span>
    </Sheet>
  )
}
