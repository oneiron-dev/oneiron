import * as React from 'react'
import { Link, createFileRoute } from '@tanstack/react-router'
import { ChanLine, ChanLinkedin, ChanMail, ChanSlack, Chevron } from '~/components/safelight/icons'
import { DraftCard, Throbber } from '~/components/safelight/Widgets'
import { cue, markCued, useDocumentEvent } from '~/components/safelight/hooks'
import inboxCss from '~/styles/inbox.css?url'

export const Route = createFileRoute('/app/inbox')({
  head: () => ({
    links: [{ rel: 'stylesheet', href: inboxCss }],
  }),
  component: Inbox,
})

/* ── rows settle in place: the dot fills, the verbs become the record.
   no toast ever — the outcome IS the row (08-14) ── */
type Settled = { ok: boolean; word: string } | null

function dotClass(settled: Settled, rest: string) {
  if (!settled) return `dot ${rest}`
  return `dot ${settled.ok ? 'dot-approved' : 'dot-rejected'}`
}
function dotTitle(settled: Settled, rest: string) {
  if (!settled) return rest
  return settled.ok ? 'approved · yours' : 'rejected · kept, struck'
}
/* one icon: the channel glyph takes the outcome ink */
function chanClass(settled: Settled) {
  if (!settled) return 'w-chan'
  return `w-chan ${settled.ok ? 'chan-ok' : 'chan-no'}`
}
function chanTitle(settled: Settled, rest: string) {
  if (!settled) return rest
  return settled.ok ? `${settled.word} · receipted` : settled.word
}
function claimClass(settled: Settled, base: string) {
  return settled && !settled.ok ? `${base} retracted` : base
}

/* the ROW is the inspect unit: click unfolds it in place, click again
   closes. A commit verb settles it and never toggles it. */
function useBrow() {
  const [open, setOpen] = React.useState(false)
  const [settled, setSettled] = React.useState<Settled>(null)

  const toggle = React.useCallback(() => {
    setOpen((o) => !o)
    cue('toggle')
  }, [])

  const onLineClick = (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest('a')) return
    toggle()
  }

  const onKeyDown = (e: React.KeyboardEvent) => {
    const target = e.target as HTMLElement
    if (
      (e.key === 'Enter' || e.key === ' ') &&
      !target.closest('a') &&
      !/^(INPUT|TEXTAREA)$/.test(target.tagName)
    ) {
      e.preventDefault()
      toggle()
    }
  }

  const act = (ok: boolean, word: string) => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setSettled({ ok, word })
    cue(ok ? 'success' : 'press')
  }

  /* "read" opens the row — the commit verb waits where the draft is visible */
  const openRow = (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    toggle()
  }

  return { open, settled, onLineClick, onKeyDown, act, openRow }
}

/* headings collapse in place (owner 08-14 eve) */
function Bundle({
  label,
  title,
  titleTip,
  meta,
  children,
}: {
  label: string
  title: React.ReactNode
  titleTip?: string
  meta?: React.ReactNode
  children: React.ReactNode
}) {
  const [closed, setClosed] = React.useState(false)
  const toggle = () => {
    setClosed((c) => !c)
    cue('toggle')
  }
  return (
    <section className={closed ? 'bundle closed' : 'bundle'} aria-label={label}>
      <div
        className="head"
        tabIndex={0}
        role="button"
        aria-expanded={!closed}
        onClick={(e) => {
          if ((e.target as HTMLElement).closest('a')) return
          toggle()
        }}
        onKeyDown={(e) => {
          if ((e.key === 'Enter' || e.key === ' ') && !(e.target as HTMLElement).closest('a')) {
            e.preventDefault()
            toggle()
          }
        }}
      >
        <span className="title" title={titleTip}>
          {title}
        </span>
        <span className="fold-hint" aria-hidden="true">
          <Chevron ariaHidden={false} />
        </span>
        {meta}
      </div>
      {children}
    </section>
  )
}

function Inbox() {
  const paneRef = React.useRef<HTMLElement>(null)
  const [dialAll, setDialAll] = React.useState(false)
  const [hintOpen, setHintOpen] = React.useState(false)
  const [summon, setSummon] = React.useState({ left: 0, top: 0, on: false })

  const a1 = useBrow()
  const a2 = useBrow()
  const b1 = useBrow()
  const b2 = useBrow()
  const c1 = useBrow()
  const c2 = useBrow()
  const d1 = useBrow()

  /* the view flip: a filter on what you SEE, never a policy */
  React.useEffect(() => {
    document.body.classList.toggle('dial-all', dialAll)
    return () => document.body.classList.remove('dial-all')
  }, [dialAll])

  /* select anything → summon (mock: shows the verb near the selection) */
  useDocumentEvent('mouseup', () => {
    const pane = paneRef.current
    if (!pane) return
    const sel = getSelection()
    if (sel && !sel.isCollapsed && String(sel).trim().length > 3) {
      const r = sel.getRangeAt(0).getBoundingClientRect()
      const p = pane.getBoundingClientRect()
      setSummon({ left: r.left - p.left, top: r.top - p.top + pane.scrollTop - 34, on: true })
    } else {
      setSummon((s) => ({ ...s, on: false }))
    }
  })

  return (
    <main className="pane" style={{ position: 'relative' }} id="pane" ref={paneRef}>
      {/* select anything → hand it to an agent (OF-248) */}
      <span
        className={summon.on ? 'summon on' : 'summon'}
        id="summon"
        style={{ left: summon.left, top: summon.top }}
      >
        <a className="act" href="#" title="engine-issued handle, read reach only · never a text blob">
          hand to agent
        </a>
      </span>

      {/* the view filter lives quietly in the sheet head (owner 08-14 eve):
          it changes what you SEE, never what happens. auto-accept is a
          policy, and policies live in settings. the (?) explains the UI. */}
      <div className="pane-head">
        <h1>Inbox</h1>
        {/* "5 need you" is dead (owner): the rail's inbox number already
            says it — one place per fact */}
        <span className="pane-tools">
          <button
            className="act"
            title="a view filter only · it changes nothing"
            onClick={() => {
              setDialAll((all) => !all)
              cue('toggle')
            }}
          >
            {dialAll ? 'needs you' : 'show all'}
          </button>
          <button
            className="hint-btn"
            aria-expanded={hintOpen}
            aria-controls="dial-why"
            title="what this screen is"
            onClick={() => {
              setHintOpen((open) => !open)
              cue('toggle')
            }}
          >
            ?
          </button>
        </span>
      </div>
      <div className="dial-why" id="dial-why" hidden={!hintOpen}>
        <span className="why-voice">
          This is the queue of things waiting for your click. By default it shows only those; show
          all also streams what landed on its own. Auto-accept is a policy, and policies live in
          settings.
        </span>
      </div>

      {/* run bundle: nightly consolidation · headline authored by the run,
          so it carries a byline (authorship law) — not live, so no well */}
      <Bundle
        label="Antevon run"
        title="Nightly consolidation"
        meta={
          <span
            className="meta-line"
            title="Antevon · run rx_7b12 · 03:12 · 42 writes · every write receipted"
          >
            2 wait
          </span>
        }
      >
        <div className="sec-voice">
          <span
            className="aname"
            data-agent="antevon"
            title="Antevon · the house mind · the overnight run · 03:12 · the run's receipts"
          >
            Antevon
          </span>
          <span>
            42 claims went in on their own. Two wait for you. The allergy claim has only one source.
            The supplier claim contradicts a claim from May.
          </span>
        </div>
        <div className="brows">
          <div
            className={a1.open ? 'brow open' : 'brow'}
            aria-expanded={a1.open}
            tabIndex={0}
            onKeyDown={a1.onKeyDown}
          >
            <div className="brow-line" onClick={a1.onLineClick}>
              <span
                className={dotClass(a1.settled, 'dot-proposed')}
                title={dotTitle(a1.settled, 'proposed · held for review')}
              ></span>
              <span
                className={claimClass(a1.settled, 'claim conf-3')}
                title="0.52 · held: low-confidence critical, one mention in April"
              >
                May be allergic to shellfish
              </span>
              <span className="rverbs">
                {a1.settled ? (
                  <span className="meta-line">{a1.settled.word} 14:09</span>
                ) : (
                  <>
                    <a
                      className="act"
                      href="#"
                      title="verb: approve_claim"
                      onClick={a1.act(true, 'accepted')}
                    >
                      accept
                    </a>
                    <a
                      className="act"
                      href="#"
                      title="verb: reject_claim"
                      onClick={a1.act(false, 'rejected')}
                    >
                      reject
                    </a>
                  </>
                )}
              </span>
            </div>
            <div className="brow-detail">
              <div className="bd-inner">
                <span className="bd-why">
                  Held: a critical-class claim from one April mention. The floor wants a second
                  source.
                </span>
                <span className="bd-acts">
                  <a className="act" href="#" title="the April mention · LINE thread">
                    source
                  </a>
                  <Link
                    className="act"
                    to="/app/vault"
                    title="claim cl_58aa · confidence, occurred, learned, actor"
                  >
                    open the claim
                  </Link>
                </span>
              </div>
            </div>
          </div>
          <div
            className={a2.open ? 'brow open' : 'brow'}
            aria-expanded={a2.open}
            tabIndex={0}
            onKeyDown={a2.onKeyDown}
          >
            <div className="brow-line" onClick={a2.onLineClick}>
              <span
                className={dotClass(a2.settled, 'dot-proposed')}
                title={dotTitle(a2.settled, 'proposed · held for review')}
              ></span>
              <span
                className={claimClass(a2.settled, 'claim conf-2')}
                title="0.81 · held: it contradicts a standing claim"
              >
                Hokuei may be consolidating suppliers this fiscal year
              </span>
              <span className="rverbs">
                {a2.settled ? (
                  <span className="meta-line">{a2.settled.word} 14:09</span>
                ) : (
                  <>
                    <a className="act" href="#" onClick={a2.act(true, 'accepted')}>
                      accept
                    </a>
                    <a className="act" href="#" onClick={a2.act(false, 'rejected')}>
                      reject
                    </a>
                  </>
                )}
              </span>
            </div>
            <div className="brow-detail">
              <div className="bd-inner">
                <span className="bd-why">
                  Held: it contradicts the standing claim that Hokuei is expanding the supplier base
                  (0.77, May). Accepting supersedes it.
                </span>
                <span className="bd-acts">
                  <Link className="act" to="/app/vault" title="cl_31f0 · the standing claim">
                    the standing claim
                  </Link>
                  <a className="act" href="#" title="scout run rx_8c41 · public filings">
                    source
                  </a>
                  <Link
                    className="act"
                    to="/app/vault"
                    title="claim cl_9d17 · confidence, occurred, learned, actor"
                  >
                    open the claim
                  </Link>
                </span>
              </div>
            </div>
          </div>
        </div>
        <div className="bmore">
          <span className="meta-line" title="40 more claims landed on their own tonight">
            40 more
          </span>
          <a className="act" href="#" title="j/k walk">
            review each
          </a>
          <a className="act" href="#" title="verb: approve_bundle">
            accept all
          </a>
          <a className="act" href="#" title="verb: reject_bundle">
            reject all
          </a>
        </div>
      </Bundle>

      {/* Eiri session: drafts + consent · LIVE, so the headline wears the
          [data-work] well in herald's ink; the byline signs the authorship */}
      <Bundle
        label="Eiri session"
        titleTip="Eiri works the Hokuei outreach · session sn_31a8 · live"
        title={
          <>
            <span className="aname" data-agent="eiri">Eiri</span>: Hokuei outreach
          </>
        }
        meta={
          <span className="meta-line" title="session sn_31a8 · live">
            2 wait · working <Throbber initial="⠧" />
          </span>
        }
      >
        <div className="brows">
          <div
            className={b1.open ? 'brow open' : 'brow'}
            aria-expanded={b1.open}
            tabIndex={0}
            onKeyDown={b1.onKeyDown}
          >
            <div className="brow-line" onClick={b1.onLineClick}>
              <span
                className={chanClass(b1.settled)}
                title={chanTitle(b1.settled, 'LINE · a draft waits on your click')}
              >
                <ChanLine />
              </span>
              <span
                className={claimClass(b1.settled, 'claim conf-1')}
                title="open the row to read and send"
              >
                Reply to Mika Tanaka: the quote for Tuesday
              </span>
              <span className="rverbs">
                {b1.settled ? (
                  <span className="meta-line">{b1.settled.word} 14:09</span>
                ) : (
                  <a
                    className="act"
                    href="#"
                    title="the draft opens here; send sits beside it"
                    onClick={b1.openRow}
                  >
                    read
                  </a>
                )}
              </span>
            </div>
            <div className="brow-detail">
              <div className="bd-inner">
                {/* what it answers (owner): the message being replied to, then
                    the editable draft with send right beside it */}
                <div className="bd-msg">
                  <span className="seal seal-human seal-class" title="Mika Tanaka · 09:15 · LINE">
                    m
                  </span>
                  <span className="bd-msg-text" lang="ja">
                    見積書、火曜までにいただけますか。概算だけでも先にあると助かります。
                  </span>
                </div>
                <DraftCard
                  agent="eiri"
                  name="Eiri"
                  nameTitle="Eiri wrote this draft · edit it in place"
                  lang="ja"
                  rows={2}
                  ariaLabel="the draft to Mika Tanaka"
                  defaultValue="お見積もりの件、承知しました。火曜までに正式版をお送りします。先に概算だけ共有します…"
                  sendTitle="verb: send_message · your click is the consent"
                  onSend={b1.act(true, 'sent')}
                />
                <input
                  className="reply-input"
                  type="text"
                  placeholder="or tell Eiri what to change…"
                  aria-label="reply to Eiri"
                />
                <span className="bd-acts">
                  <a className="act" href="#" title="LINE · Mika Tanaka · the whole thread">
                    the thread
                  </a>
                  <a className="act" href="#" title="LINE OA grant · scoped, budgeted, revocable">
                    the grant
                  </a>
                </span>
              </div>
            </div>
          </div>
          <div
            className={b2.open ? 'brow open' : 'brow'}
            aria-expanded={b2.open}
            tabIndex={0}
            onKeyDown={b2.onKeyDown}
          >
            <div className="brow-line" onClick={b2.onLineClick}>
              <span
                className={chanClass(b2.settled)}
                title={chanTitle(b2.settled, 'LinkedIn · a consent ask waits on you')}
              >
                <ChanLinkedin />
              </span>
              <span
                className={claimClass(b2.settled, 'claim conf-2')}
                title="a new audience for the linkedin grant"
              >
                <span className="aname" data-agent="eiri" title="Eiri · outbound · every send waits for your click">Eiri</span> asks: reach the Hokuei COO through Yuki’s account?
              </span>
              <span className="rverbs">
                {b2.settled ? (
                  <span className="meta-line">{b2.settled.word} 14:09</span>
                ) : (
                  <>
                    <a
                      className="act"
                      href="#"
                      title="mints a scoped, budgeted, revocable grant (OF-050)"
                      onClick={b2.act(true, 'allowed')}
                    >
                      allow once
                    </a>
                    <a className="act" href="#" onClick={b2.act(true, 'granted')}>
                      allow + grant
                    </a>
                    <a className="act" href="#" onClick={b2.act(false, 'denied')}>
                      deny
                    </a>
                  </>
                )}
              </span>
            </div>
            <div className="brow-detail">
              <div className="bd-inner">
                <span className="bd-why">
                  A new audience for the LinkedIn grant, so it asks before it reaches. Every send
                  stays a human click.
                </span>
                <input
                  className="reply-input"
                  type="text"
                  placeholder="or answer Eiri in your words…"
                  aria-label="reply to Eiri"
                />
                <span className="bd-acts">
                  <a
                    className="act"
                    href="#"
                    title="linkedin grant · Yuki's account · scope, budget, expiry"
                  >
                    the grant
                  </a>
                  <a className="act" href="#" title="Hokuei · the org dossier">
                    who they are
                  </a>
                </span>
              </div>
            </div>
          </div>
        </div>
      </Bundle>

      {/* prepared work */}
      <Bundle label="prepared work" title="Prepared for you">
        <div className="brows">
          <div
            className={c1.open ? 'brow open' : 'brow'}
            aria-expanded={c1.open}
            tabIndex={0}
            onKeyDown={c1.onKeyDown}
          >
            <div className="brow-line" onClick={c1.onLineClick}>
              <span className="dot dot-auto" title="prepared · nothing waits on you"></span>
              <span
                className="claim conf-2"
                title="brief · compiled for Thursday 10:00, cites every claim under it"
              >
                Meeting brief: Hokuei pilot call, Thursday 10:00
              </span>
              <span className="rverbs">
                <a className="act" href="#">
                  open brief
                </a>
              </span>
            </div>
            <div className="brow-detail">
              <div className="bd-inner">
                <span className="bd-why">
                  Every load-bearing sentence cites the claims under it, so the brief can be read
                  backwards into the vault.
                </span>
                <span className="bd-acts">
                  <a className="act" href="#" title="Hokuei · the org dossier">
                    the org
                  </a>
                </span>
              </div>
            </div>
          </div>
          <div
            className={c2.open ? 'brow open' : 'brow'}
            aria-expanded={c2.open}
            tabIndex={0}
            onKeyDown={c2.onKeyDown}
          >
            <div className="brow-line" onClick={c2.onLineClick}>
              <span className="dot dot-auto" title="prepared · nothing waits on you"></span>
              <span className="claim conf-3" title="note · the 03:12 run, one line per receipt">
                Night-shift note: 03:12 run, one line per receipt
              </span>
              <span className="rverbs">
                <a className="act" href="#">
                  read
                </a>
              </span>
            </div>
            <div className="brow-detail">
              <div className="bd-inner">
                <span className="bd-why">
                  What the night did, in the order it did it. One line per receipt, nothing
                  summarised away.
                </span>
                <span className="bd-acts">
                  <a className="act" href="#" title="run rx_7b12 · the run's receipts">
                    the receipts
                  </a>
                </span>
              </div>
            </div>
          </div>
        </div>
      </Bundle>

      {/* paused run */}
      <Bundle
        label="paused import"
        title="LinkedIn import"
        meta={
          <span
            className="meta-line"
            title="run rx_9a04 · it stopped itself at 180 writes · nothing landed"
          >
            paused
          </span>
        }
      >
        <div className="brows">
          <div
            className={d1.open ? 'brow open' : 'brow'}
            aria-expanded={d1.open}
            tabIndex={0}
            onKeyDown={d1.onKeyDown}
          >
            <div className="brow-line" onClick={d1.onLineClick}>
              <span
                className={dotClass(d1.settled, 'dot-proposed')}
                title={dotTitle(d1.settled, 'paused · waiting on you')}
              ></span>
              <span
                className={claimClass(d1.settled, 'claim conf-2')}
                title="paused run · the burst guard stopped it, nothing landed"
              >
                The burst guard stopped this import before anything landed
              </span>
              <span className="rverbs">
                {d1.settled ? (
                  <span className="meta-line">{d1.settled.word} 14:09</span>
                ) : (
                  <>
                    <a className="act" href="#">
                      review bundle
                    </a>
                    <a className="act" href="#" title="verb: resume_run">
                      resume
                    </a>
                    <a
                      className="act"
                      href="#"
                      title="verb: cancel_run"
                      onClick={d1.act(false, 'discarded')}
                    >
                      discard
                    </a>
                  </>
                )}
              </span>
            </div>
            <div className="brow-detail">
              <div className="bd-inner">
                <span className="bd-why">
                  Unusual write volume for this source, so the run paused itself. The bundle waits as
                  one decision.
                </span>
                <span className="bd-acts">
                  <a className="act" href="#" title="run rx_9a04 · the run's receipts">
                    the run
                  </a>
                </span>
              </div>
            </div>
          </div>
        </div>
      </Bundle>

      {/* DEFAULT STATE · the digest, in plain words (owner 08-14 eve) */}
      <div className="quiet-line">
        <span className="digest">
          Your agents handled 14 messages across LINE, email and Slack this week. Two drafts waited
          for you; everything else carries a receipt.
        </span>
        <a className="act" href="#">
          open receipts
        </a>
      </div>

      {/* DIAL = REVIEW EVERYTHING · the live stream unfolds. one tight
          line per event: time · channel glyph · seal · what happened. */}
      <section className="wire" aria-label="every surface event">
        <div className="wire-head">
          Everything that crossed a channel today, in order. Reads only; the receipts hold the
          detail.
        </div>
        <div className="thread">
          <div className="w-row">
            <span className="w-time">14:05</span>
            <span className="w-chan" title="slack">
              <ChanSlack />
            </span>
            <span className="seal seal-agent" title="h · herald">
              h
            </span>
            <span className="t-msg conf-3">
              Answered #ops: pilot timeline question, cited the scope note.
            </span>
          </div>
          <div className="w-row">
            <span className="w-time">14:02</span>
            <span className="w-chan" title="linkedin">
              <ChanLinkedin />
            </span>
            <span className="seal seal-human" title="y · Yuki">
              y
            </span>
            <span className="t-msg conf-3">DM to Hokuei COO sent · verifying</span>
          </div>
          <div className="w-row">
            <span className="w-time">11:48</span>
            <span className="w-chan" title="email">
              <ChanMail />
            </span>
            <span className="seal seal-agent" title="h · herald">
              h
            </span>
            <span className="t-msg conf-3">
              Pilot scope summary delivered · verified in thread · receipted
            </span>
          </div>
          <div className="w-row">
            <span className="w-time">09:15</span>
            <span className="w-chan" title="LINE">
              <ChanLine />
            </span>
            <span className="seal seal-human seal-class" title="m · Mika Tanaka">
              m
            </span>
            <span className="t-msg conf-3">
              Inbound from Mika Tanaka · quote request · claim extracted
            </span>
          </div>
        </div>
      </section>
    </main>
  )
}
