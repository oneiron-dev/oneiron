import * as React from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { cue, markCued } from '~/components/safelight/hooks'
import { Empty, Fold, LedgerHead, PaneHead, Sec, Sheet, useEscLayer, useLedger, type Col } from './-shared'

export const Route = createFileRoute('/settings/billing')({
  component: BillingPage,
})

/* ── billing · a statement on paper: two meters, one plan, one card, five
   invoices. every number is the metered truth and carries a receipt ── */
const CYCLE_RESET = 'Sep 1'

const METERS = [
  {
    key: 'storage',
    name: 'storage',
    reading: '41.2 GB·days',
    of: 'of 100',
    pct: 41.2,
    tip: 'storage · 41.2 of 100 GB·days · resets Sep 1',
  },
  {
    key: 'inference',
    name: 'inference',
    reading: '18,400 credits',
    of: 'of 50,000',
    pct: 36.8,
    tip: 'inference · 18,400 of 50,000 credits · resets Sep 1',
  },
] as const

type PlanKey = 'solo' | 'studio' | 'team'
const PLANS: { key: PlanKey; name: string; price: string; includes: string }[] = [
  { key: 'solo', name: 'Solo', price: '¥2,900 / month', includes: '25 GB·days · 10,000 credits' },
  { key: 'studio', name: 'Studio', price: '¥9,800 / month', includes: '100 GB·days · 50,000 credits' },
  { key: 'team', name: 'Team', price: '¥29,000 / month', includes: '400 GB·days · 200,000 credits' },
]
const CURRENT: PlanKey = 'studio'

type Invoice = {
  id: string
  date: string
  amount: string
  amountN: number
  state: 'paid'
  period: string
  storage: string
  inference: string
  paid: string
  hash: string
  note?: string
}
const INVOICES: Invoice[] = [
  {
    id: 'inv_08a1',
    date: '2026-08-01',
    amount: '¥9,800',
    amountN: 9800,
    state: 'paid',
    period: 'Jul 1 – Jul 31',
    storage: '38.9 GB·days',
    inference: '21,300 credits',
    paid: 'visa · 4242 · 2026-08-01',
    hash: 'rc_3f9a2c',
  },
  {
    id: 'inv_07a1',
    date: '2026-07-01',
    amount: '¥9,800',
    amountN: 9800,
    state: 'paid',
    period: 'Jun 1 – Jun 30',
    storage: '44.6 GB·days',
    inference: '17,050 credits',
    paid: 'visa · 4242 · 2026-07-01',
    hash: 'rc_b71e04',
  },
  {
    id: 'inv_06a1',
    date: '2026-06-01',
    amount: '¥11,240',
    amountN: 11240,
    state: 'paid',
    period: 'May 1 – May 31',
    storage: '112.4 GB·days',
    inference: '26,900 credits',
    paid: 'visa · 4242 · 2026-06-01',
    hash: 'rc_9d0c17',
    note: '¥9,800 plan · ¥1,440 storage over 100 GB·days',
  },
  {
    id: 'inv_05a1',
    date: '2026-05-01',
    amount: '¥9,800',
    amountN: 9800,
    state: 'paid',
    period: 'Apr 1 – Apr 30',
    storage: '61.0 GB·days',
    inference: '12,400 credits',
    paid: 'visa · 4242 · 2026-05-01',
    hash: 'rc_44ab8e',
  },
  {
    id: 'inv_04a1',
    date: '2026-04-01',
    amount: '¥9,800',
    amountN: 9800,
    state: 'paid',
    period: 'Mar 1 – Mar 31',
    storage: '22.7 GB·days',
    inference: '8,150 credits',
    paid: 'visa · 4242 · 2026-04-01',
    hash: 'rc_e12f60',
  },
]

const COLS: Col<Invoice>[] = [
  { id: 'date', header: 'date', accessor: (i) => i.date, size: 128 },
  { id: 'amount', header: 'amount', accessor: (i) => i.amountN, size: 110, align: 'right' },
  { id: 'state', header: 'state', accessor: (i) => i.state, size: 90 },
  { id: 'door', header: '', size: 90, className: 'c-door' },
]

/* ── the two-phase settle: the line lands at once, the receipt a beat
   later. no toast ever — the outcome IS the row ── */
function useTwoPhase() {
  const [phase, setPhase] = React.useState<0 | 1 | 2>(0)
  const timer = React.useRef<ReturnType<typeof setTimeout> | null>(null)
  const start = React.useCallback(() => {
    setPhase(1)
    if (timer.current) clearTimeout(timer.current)
    timer.current = setTimeout(() => setPhase(2), 700)
  }, [])
  const reset = React.useCallback(() => {
    if (timer.current) clearTimeout(timer.current)
    setPhase(0)
  }, [])
  React.useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current)
    },
    [],
  )
  return { phase, start, reset }
}

export function BillingPage() {
  /* plan: change (unfold under the row · glance + act) · end (settles) */
  const [planOpen, setPlanOpen] = React.useState(false)
  const [nextPlan, setNextPlan] = React.useState<PlanKey | null>(null)
  const [ending, setEnding] = React.useState(false)
  const settle = useTwoPhase()

  /* payment: update unfolds two fields; save settles the row */
  const [card, setCard] = React.useState({ last4: '4242', exp: '09/28' })
  const [payOpen, setPayOpen] = React.useState(false)
  const [payLanded, setPayLanded] = React.useState(false)
  const numRef = React.useRef<HTMLInputElement>(null)
  const expRef = React.useRef<HTMLInputElement>(null)

  /* invoices: row click = the under-glance; the receipt is something you
     READ · the context column */
  const [ctx, setCtx] = React.useState<string | null>(null)
  /* the esc ladder closes the newest thing first: column, then the plan
     or card fold, then the ledger's selection */
  useEscLayer(!!ctx, () => setCtx(null))
  useEscLayer(planOpen, () => setPlanOpen(false))
  useEscLayer(payOpen, () => setPayOpen(false))
  const ledger = useLedger<Invoice>({
    rows: INVOICES,
    columns: COLS,
    getId: (i) => i.id,
    searchable: (i) => `${i.date} ${i.amount} ${i.state} ${i.period} ${i.hash} ${i.note ?? ''}`,
  })

  const current = PLANS.find((p) => p.key === CURRENT)!
  const chosen = nextPlan ? PLANS.find((p) => p.key === nextPlan)! : null

  const togglePlan = (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setPlanOpen((o) => !o)
    cue('toggle')
  }
  const choose = (key: PlanKey) => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setNextPlan(key)
    setEnding(false)
    setPlanOpen(false)
    settle.start()
    cue('success')
  }
  const endPlan = (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setEnding(true)
    setNextPlan(null)
    setPlanOpen(false)
    settle.start()
    cue('press')
  }
  const keepPlan = (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setEnding(false)
    setNextPlan(null)
    settle.reset()
    cue('toggle')
  }

  const togglePay = (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setPayOpen((o) => !o)
    cue('toggle')
  }
  React.useEffect(() => {
    if (payOpen) numRef.current?.focus()
  }, [payOpen])
  const saveCard = (e?: React.SyntheticEvent) => {
    e?.preventDefault()
    const digits = (numRef.current?.value ?? '').replace(/\D/g, '')
    const exp = (expRef.current?.value ?? '').trim()
    if (digits.length < 4 || !/^\d{2}\/\d{2}$/.test(exp)) {
      cue('press')
      return
    }
    setCard({ last4: digits.slice(-4), exp })
    setPayOpen(false)
    setPayLanded(true)
    cue('success')
  }

  const inv = ctx ? INVOICES.find((i) => i.id === ctx) ?? null : null

  /* the plan line, at rest or settled */
  const changing = ending || !!chosen
  const planLine = `${current.name} · ${current.price} · ${changing ? 'until' : 'renews'} ${CYCLE_RESET}`
  const receipt = ending
    ? `ends ${CYCLE_RESET} · nothing is deleted`
    : chosen
      ? `${chosen.name} · ${chosen.price} from ${CYCLE_RESET}`
      : null

  return (
    <Sheet
      page="billing"
      ctx={!!inv}
      aside={
        <aside className="context" id="invoice-receipt" hidden={!inv} aria-label="the receipt">
          {inv && (
            <>
              <div className="ctx-head">
                <span className="ctx-crumb">invoice · {inv.date}</span>
                <button
                  className="ctx-close"
                  aria-label="close the receipt"
                  title="close · esc"
                  onClick={() => {
                    setCtx(null)
                    cue('toggle')
                  }}
                >
                  ×
                </button>
              </div>
              <div className="ctx-title">Receipt · {inv.amount}</div>
              <div className="kvs">
                <div className="kv">
                  <span className="k">plan</span>
                  <span className="v">{current.name}</span>
                </div>
                <div className="kv">
                  <span className="k">period</span>
                  <span className="v">{inv.period}</span>
                </div>
                <div className="kv">
                  <span className="k">storage</span>
                  <span className="v">{inv.storage}</span>
                </div>
                <div className="kv">
                  <span className="k">inference</span>
                  <span className="v">{inv.inference}</span>
                </div>
                <div className="kv">
                  <span className="k">paid</span>
                  <span className="v">{inv.paid}</span>
                </div>
                <div className="kv">
                  <span className="k">receipt</span>
                  <span className="v">
                    <a href="#" title="content-addressed" onClick={(e) => e.preventDefault()}>
                      {inv.hash}
                    </a>
                  </span>
                </div>
              </div>
              {inv.note && <span className="ctx-note">{inv.note}</span>}
              <span className="ctx-acts">
                <a className="act" href="#" title={`${inv.id} · pdf`} onClick={(e) => e.preventDefault()}>
                  download
                </a>
                <a className="act" href="#" title="the meter readings this invoice was cut from" onClick={(e) => e.preventDefault()}>
                  the readings
                </a>
              </span>
            </>
          )}
        </aside>
      }
    >
      <PaneHead
        title="billing"
        hint="Storage and inference are metered each cycle. At 80% a note lands in your inbox. Nothing stops in silence."
        search={{ value: ledger.query, onChange: ledger.setQuery, onKeyDown: ledger.onKeyDown, placeholder: 'search invoices' }}
      />

      {/* ── USAGE · two readings, two thin bars, no colour ── */}
      <Sec label="usage" title="Usage">
        <div className="meters">
          {METERS.map((m) => (
            <div className="meter-row" key={m.key} title={m.tip}>
              <div className="m-line">
                <span className="m-name">{m.name}</span>
                <a className="m-read" href="#" title="the readings behind this number" onClick={(e) => e.preventDefault()}>
                  {m.reading}
                </a>
                <span className="m-of">{m.of}</span>
                <span className="m-meta">resets {CYCLE_RESET}</span>
              </div>
              <div className="m-bar" aria-hidden="true">
                <span className="m-fill" style={{ width: `${m.pct}%` }}></span>
              </div>
            </div>
          ))}
        </div>
      </Sec>

      {/* ── PLAN · one serif line + two acts; settles in place ── */}
      <Sec label="plan" title="Plan">
        <div className={planOpen ? 'plan open' : 'plan'}>
          <div className="plan-line">
            <span className={receipt ? 'plan-words cool' : 'plan-words'}>{planLine}</span>
            <span className="plan-acts">
              {receipt ? (
                <a className="act" href="#" title="the plan stays as it is" onClick={keepPlan}>
                  keep {current.name.toLowerCase()}
                </a>
              ) : (
                <>
                  <a className="act" href="#" aria-expanded={planOpen} aria-controls="plan-pick" title="takes effect next cycle" onClick={togglePlan}>
                    change plan
                  </a>
                  <a className="act" href="#" data-danger title="ends Sep 1 · nothing is deleted" onClick={endPlan}>
                    end plan
                  </a>
                </>
              )}
            </span>
          </div>
          {receipt && (
            <span className="receipt">
              {receipt}
              <span className={settle.phase === 2 ? 'landed on' : 'landed'}> · receipt landed</span>
            </span>
          )}
          {/* under the row = glance + act (rule 39 A): the other plans, one line each */}
          <div className="plan-pick" id="plan-pick" aria-hidden={!planOpen}>
            <div className="pp-inner">
              {PLANS.map((p) => (
                <div className="pp-row" key={p.key}>
                  <span className="pp-name">{p.name}</span>
                  <span className="pp-terms">
                    {p.price} · {p.includes}
                  </span>
                  {p.key === CURRENT ? (
                    <span className="meta-line">current</span>
                  ) : (
                    <a
                      className="act"
                      href="#"
                      title={`${p.name} from ${CYCLE_RESET} · ${current.name} until then`}
                      onClick={choose(p.key)}
                      tabIndex={planOpen ? 0 : -1}
                    >
                      choose
                    </a>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </Sec>

      {/* ── PAYMENT · one mono row + update; save settles ── */}
      <Sec label="payment" title="Payment">
        <div className={payOpen ? 'pay open' : 'pay'}>
          <div className="pay-line">
            <a className="pay-card" href="#" title="the card on file · charged on the 1st" onClick={(e) => e.preventDefault()}>
              visa · {card.last4} · exp {card.exp}
            </a>
            {payLanded && !payOpen && (
              <span className="meta-line" title="the change is receipted">
                updated · receipt landed
              </span>
            )}
            <span className="plan-acts">
              <a className="act" href="#" aria-expanded={payOpen} aria-controls="pay-edit" title="charged from the next invoice" onClick={togglePay}>
                {payOpen ? 'close' : 'update'}
              </a>
            </span>
          </div>
          <div className="pay-edit" id="pay-edit" aria-hidden={!payOpen}>
            <form className="pe-inner" onSubmit={saveCard}>
              <input
                ref={numRef}
                className="pay-input"
                inputMode="numeric"
                autoComplete="cc-number"
                placeholder="card number"
                aria-label="card number"
                tabIndex={payOpen ? 0 : -1}
              />
              <input
                ref={expRef}
                className="pay-input pay-exp"
                inputMode="numeric"
                autoComplete="cc-exp"
                placeholder="mm/yy"
                aria-label="expiry"
                tabIndex={payOpen ? 0 : -1}
              />
              <button className="act" type="submit" title="the old card is dropped" tabIndex={payOpen ? 0 : -1}>
                save
              </button>
            </form>
          </div>
        </div>
      </Sec>

      {/* ── INVOICES · the ledger; the glance under the row, the receipt in the column ── */}
      <Sec
        label="invoices"
        title="Invoices"
        meta={
          <span className="meta-line" title="5 invoices · all paid">
            5 · paid
          </span>
        }
      >
        <div className="ledger-wrap" tabIndex={-1} onKeyDown={ledger.onKeyDown}>
          <table className="ledger i-ledger">
            <LedgerHead columns={COLS} sort={ledger.sort} onSort={ledger.toggleSort} />
            <tbody>
              {ledger.view.length === 0 && <Empty cols={COLS.length} what="No invoice matches that." />}
              {ledger.view.map((i) => {
                const isSel = ledger.sel === i.id || ctx === i.id
                const isOpen = ledger.open === i.id
                return (
                  <React.Fragment key={i.id}>
                    <tr
                      className={isSel ? 'row selected' : 'row'}
                      aria-selected={isSel}
                      aria-expanded={isOpen}
                      onClick={(e) => {
                        if ((e.target as HTMLElement).closest('a, button')) return
                        ledger.clickRow(i.id, e)
                      }}
                    >
                      <td>
                        <span className="clk" title={`${i.id} · issued ${i.date}`}>
                          {i.date}
                        </span>
                      </td>
                      <td className="num">
                        <span className="amt" title={i.note ?? `${current.name} · ${i.period}`}>
                          {i.amount}
                        </span>
                      </td>
                      <td>
                        <span className="state" title={`paid · ${i.paid}`}>
                          {i.state}
                        </span>
                      </td>
                      <td className="c-door">
                        <a
                          className="act"
                          href="#"
                          aria-expanded={ctx === i.id}
                          aria-controls="invoice-receipt"
                          title={`receipt ${i.hash} · opens on the right`}
                          onClick={(e) => {
                            e.preventDefault()
                            markCued(e)
                            setCtx((cur) => (cur === i.id ? null : i.id))
                            ledger.setSel(i.id)
                            cue('toggle')
                          }}
                        >
                          receipt
                        </a>
                      </td>
                    </tr>
                    <Fold open={isOpen} cols={COLS.length}>
                      <span className="glance-kvs">
                        <span className="gk">
                          <span className="k">period</span> <span className="v">{i.period}</span>
                        </span>
                        <span className="gk">
                          <span className="k">storage</span> <span className="v">{i.storage}</span>
                        </span>
                        <span className="gk">
                          <span className="k">inference</span> <span className="v">{i.inference}</span>
                        </span>
                      </span>
                    </Fold>
                  </React.Fragment>
                )
              })}
            </tbody>
          </table>
        </div>
      </Sec>

      <span className="foot">Every meter reading carries a receipt.</span>
    </Sheet>
  )
}
