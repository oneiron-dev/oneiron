import * as React from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { cue, markCued } from '~/components/safelight/hooks'
import { PaneHead, Sheet, TODAY } from './-shared'

export const Route = createFileRoute('/settings/forget')({
  component: ForgetPage,
})

/* ── forget: the ceremony. the act arms only once there is a reason; the
   receipt lands into the ledger below, stamped. red = the armed forget only. ── */
type Erased = { stamp: string; what: string; why: string; seal: string; sealTip: string; sweep: 'due' | string }
const ERASED: Erased[] = [
  {
    stamp: 'ERASED · 2026-08-13 · reason on record',
    what: 'A supplier rumor and the thread under it.',
    why: 'Retracted at source.',
    seal: 'y',
    sealTip: 'y · Yuki · member',
    sweep: 'due',
  },
  {
    stamp: 'ERASED · 2026-08-11 · reason on record',
    what: "Mika Tanaka's home address, and the two claims that carried it.",
    why: 'Asked for by the contact.',
    seal: 'o',
    sealTip: 'o · Owen · owner',
    sweep: 'swept 08-12 03:12',
  },
  {
    stamp: 'ERASED · 2026-07-29 · reason on record',
    what: 'The 2025 payroll import, all 402 rows.',
    why: 'Landed in the wrong vault.',
    seal: 'o',
    sealTip: 'o · Owen · owner',
    sweep: 'swept 07-30 03:12',
  },
]

function ForgetPage() {
  const [reason, setReason] = React.useState('')
  const [erased, setErased] = React.useState<Erased[]>(ERASED)
  const [landed, setLanded] = React.useState(0)
  const armed = reason.trim().length > 0
  const commitForget = () => {
    setErased((rows) => [
      {
        stamp: `ERASED · ${TODAY} · reason on record`,
        what: reason.trim(),
        why: '',
        seal: 'o',
        sealTip: 'o · Owen · owner',
        sweep: 'due',
      },
      ...rows,
    ])
    setLanded((n) => n + 1)
    setReason('')
    cue('success')
  }
  const forget = (e: React.MouseEvent) => {
    e.preventDefault()
    if (!armed) return
    markCued(e)
    commitForget()
  }

  return (
    <Sheet page="forget">
      <PaneHead
        title="forget"
        hint="The record goes. A receipt stays, with your reason."
        meta={<span className="meta-line head-meta">{erased.length} erased</span>}
      />
      <div className="ceremony">
        <span className="two-phase">Forgetting has two phases. The record goes now. The sweep clears the history at 03:12.</span>
        <input
          className="reason"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="what goes away, and why"
          aria-label="reason for the deletion"
          onKeyDown={(e) => {
            if (e.key === 'Enter' && armed) {
              e.preventDefault()
              commitForget()
            }
          }}
        />
        <div className="c-go">
          <a
            className={armed ? 'act' : 'act disarmed'}
            href="#"
            data-danger
            aria-disabled={!armed}
            title={armed ? 'verb: forget · tombstones the record now and queues the history sweep' : 'say why first'}
            onClick={forget}
          >
            forget
          </a>
        </div>
      </div>
      <div className="ledger-wrap">
        <table className="ledger f-ledger" aria-label="deletion receipts">
          <thead>
            <tr>
              <th className="c-stamp"></th>
              <th>record</th>
              <th className="c-seal"></th>
              <th className="c-sweep">sweep</th>
            </tr>
          </thead>
          <tbody>
            {erased.map((r, i) => (
              <tr className={i < landed ? 'row landed' : 'row'} key={`${r.stamp}-${r.what}`}>
                <td>
                  <span className="stamp" title="erased · the record is gone; the fact that it was erased is not">
                    {r.stamp}
                  </span>
                </td>
                <td>
                  <span className="claim">
                    {r.what}
                    {r.why && <span className="why"> {r.why}</span>}
                  </span>
                </td>
                <td>
                  <span className="seal seal-human" title={r.sealTip}>
                    {r.seal}
                  </span>
                </td>
                <td>
                  <span
                    className="meta-line"
                    title={r.sweep === 'due' ? 'the record is gone now · the sweep clears the history at 03:12' : 'the history is swept'}
                  >
                    {r.sweep === 'due' ? 'due 03:12' : r.sweep}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Sheet>
  )
}
