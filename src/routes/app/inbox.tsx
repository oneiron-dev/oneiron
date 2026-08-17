import * as React from 'react'
import { Link, createFileRoute } from '@tanstack/react-router'
import { ChanLine, ChanLinkedin, ChanMail, ChanSlack, Chevron } from '~/components/safelight/icons'
import { DraftCard, Throbber } from '~/components/safelight/Widgets'
import { cue, markCued, useDocumentEvent, useEscape } from '~/components/safelight/hooks'
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

/* read-only detail summons the CONTEXT COLUMN (owner 08-15, the Slack
   model): a claim/prepared/wire row selects into the right column. The
   in-place unfold survives ONLY where you act — a draft to edit, a
   consent to answer. */
type CtxKey = 'a1' | 'a2' | 'b1' | 'b2' | 'c1' | 'c2' | 'd1' | 'w1' | 'w2' | 'w3' | 'w4'

/* ── the OPEN LAW, switchable so the owner can FEEL each (08-18, rule 39
   still open). tuner → open law. gesture: click = under the row, `open`
   = the column (reads only). column: every row opens the column, drafts
   too. kind: acts under the row, records in the column (as built 08-15). ── */
type OpenLaw = 'gesture' | 'column' | 'kind'
function readOpenLaw(): OpenLaw {
  try {
    const v = localStorage.getItem('oneiron-open-law')
    return v === 'gesture' || v === 'column' ? v : 'kind'
  } catch {
    return 'kind'
  }
}
function useOpenLaw(): OpenLaw {
  const [law, setLaw] = React.useState<OpenLaw>('kind')
  React.useEffect(() => {
    const read = () => setLaw(readOpenLaw())
    read()
    addEventListener('oneiron:openlaw', read)
    return () => removeEventListener('oneiron:openlaw', read)
  }, [])
  return law
}

/* a row that settles in place but inspects in the column */
function useSettle() {
  const [settled, setSettled] = React.useState<Settled>(null)
  const act = (ok: boolean, word: string) => (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    markCued(e)
    setSettled({ ok, word })
    cue(ok ? 'success' : 'press')
  }
  return { settled, act }
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
  const paneRef = React.useRef<HTMLDivElement>(null)
  const [dialAll, setDialAll] = React.useState(false)
  const [hintOpen, setHintOpen] = React.useState(false)
  const [empty, setEmpty] = React.useState(false)
  React.useEffect(() => {
    setEmpty(new URLSearchParams(location.search).has('empty'))
  }, [])
  const [summon, setSummon] = React.useState({ left: 0, top: 0, on: false })
  const [ctx, setCtx] = React.useState<CtxKey | null>(null)
  const law = useOpenLaw()
  /* gesture law: the row that is unfolded under itself */
  const [glance, setGlance] = React.useState<CtxKey | null>(null)
  React.useEffect(() => {
    setCtx(null)
    setGlance(null)
  }, [law])

  const a1 = useSettle()
  const a2 = useSettle()
  const b1 = useBrow()
  const b2 = useBrow()
  const d1 = useSettle()

  /* a row click: under the law of the day. gesture → unfold under the row;
     column · kind → select into the column; the same row closes it */
  const select = (key: CtxKey) => (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest('a')) return
    if (law === 'gesture') setGlance((cur) => (cur === key ? null : key))
    else setCtx((cur) => (cur === key ? null : key))
    cue('toggle')
  }
  /* an explicit door into the column (the `open` / `read` acts) */
  const openCol = (key: CtxKey) => (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    markCued(e)
    setCtx((cur) => (cur === key ? null : key))
    cue('toggle')
  }
  useEscape(() => {
    if (ctx) setCtx(null)
    else setGlance(null)
  })
  const rowCls = (key: CtxKey, base = 'brow') =>
    `${base}${ctx === key ? ' sel' : ''}${law === 'gesture' && glance === key ? ' open' : ''}`

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

  /* what the column shows, per selected row (fixture) */
  const CTX: Record<CtxKey, {
    crumb: string
    title: string
    by?: React.ReactNode
    body: React.ReactNode
    acts: React.ReactNode
    /* gesture law: is there something to READ beyond the glance? */
    read?: boolean
  }> = {
    a1: {
      crumb: 'nightly consolidation · claim',
      title: 'May be allergic to shellfish',
      body: 'Held: a critical-class claim from one April mention. The floor wants a second source.',
      acts: (
        <>
          <a className="act" href="#" title="the April mention · LINE thread">
            source
          </a>
          <Link className="act" to="/app/vault" title="claim cl_58aa · confidence, occurred, learned, actor">
            open the claim
          </Link>
        </>
      ),
    },
    a2: {
      crumb: 'nightly consolidation · claim',
      title: 'Hokuei may be consolidating suppliers this fiscal year',
      body: 'Held: it contradicts the standing claim that Hokuei is expanding the supplier base (0.77, May). Accepting supersedes it.',
      acts: (
        <>
          <Link className="act" to="/app/vault" title="cl_31f0 · the standing claim">
            the standing claim
          </Link>
          <a className="act" href="#" title="scout run rx_8c41 · public filings">
            source
          </a>
          <Link className="act" to="/app/vault" title="claim cl_9d17 · confidence, occurred, learned, actor">
            open the claim
          </Link>
        </>
      ),
    },
    b1: {
      crumb: 'Eiri · draft · LINE',
      title: 'Reply to Mika Tanaka: the quote for Tuesday',
      by: (
        <span className="aname" data-agent="eiri" title="Eiri wrote this draft">
          Eiri
        </span>
      ),
      body: (
        <>
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
            rows={3}
            ariaLabel="the draft to Mika Tanaka"
            defaultValue="お見積もりの件、承知しました。火曜までに正式版をお送りします。先に概算だけ共有します…"
            sendTitle="verb: send_message · your click is the consent"
            onSend={b1.act(true, 'sent')}
          />
          <input className="reply-input" type="text" placeholder="or tell Eiri what to change…" aria-label="reply to Eiri" />
        </>
      ),
      acts: (
        <>
          <a className="act" href="/app/threads" title="LINE · Mika Tanaka · the whole thread">
            the thread
          </a>
          <a className="act" href="#" title="LINE OA grant · scoped, budgeted, revocable">
            the grant
          </a>
        </>
      ),
    },
    b2: {
      crumb: 'Eiri · asks · linkedin',
      title: 'Reach the Hokuei COO through Yurii’s account?',
      by: (
        <span className="aname" data-agent="eiri" title="Eiri · outbound">
          Eiri
        </span>
      ),
      body: (
        <>
          <span className="bd-why">
            A new audience for the LinkedIn grant, so it asks before it reaches. Every send stays
            a human click.
          </span>
          <span className="bd-acts">
            <a className="act" href="#" title="mints a scoped, budgeted, revocable grant (OF-050)" onClick={b2.act(true, 'allowed')}>
              allow once
            </a>
            <a className="act" href="#" onClick={b2.act(true, 'granted')}>
              allow + grant
            </a>
            <a className="act" href="#" onClick={b2.act(false, 'denied')}>
              deny
            </a>
          </span>
          <input className="reply-input" type="text" placeholder="or answer Eiri in your words…" aria-label="reply to Eiri" />
        </>
      ),
      acts: (
        <>
          <a className="act" href="#" title="linkedin grant · yurii's account · scope, budget, expiry">
            the grant
          </a>
          <a className="act" href="/app/orgs" title="Hokuei · the org dossier">
            who they are
          </a>
        </>
      ),
    },
    c1: {
      crumb: 'prepared · brief',
      read: true,
      title: 'Meeting brief: Hokuei pilot call, Thursday 10:00',
      body: 'Every load-bearing sentence cites the claims under it, so the brief can be read backwards into the vault.',
      acts: (
        <>
          <a className="act" href="/app/briefs">
            open brief
          </a>
          <a className="act" href="/app/orgs" title="Hokuei · the org dossier">
            the org
          </a>
        </>
      ),
    },
    c2: {
      crumb: 'prepared · note',
      read: true,
      title: 'Night-shift note: the 03:12 run',
      body: 'What the night did, in the order it did it. One line per receipt, nothing summarised away.',
      acts: (
        <a className="act" href="/app/agents" title="run rx_7b12 · the run's receipts">
          the receipts
        </a>
      ),
    },
    d1: {
      crumb: 'linkedin import · paused',
      title: 'The burst guard stopped this import',
      body: 'Unusual write volume for this source, so the run paused itself. The bundle waits as one decision.',
      acts: (
        <a className="act" href="/app/agents" title="run rx_9a04 · the run's receipts">
          the run
        </a>
      ),
    },
    w1: {
      crumb: 'today · 14:05 · slack',
      read: true,
      title: 'Answered #ops: the pilot timeline question',
      by: (
        <span className="aname" data-agent="antevon" title="Antevon · the house mind">
          Antevon
        </span>
      ),
      body: 'The answer cites the scope note; the citation is its receipt.',
      acts: (
        <>
          <a className="act" href="/app/threads" title="slack · #ops · the whole thread">
            the thread
          </a>
          <a className="act" href="#">
            the receipt
          </a>
        </>
      ),
    },
    w2: {
      crumb: 'today · 14:02 · linkedin',
      read: true,
      title: 'DM to the Hokuei COO, sent',
      by: (
        <>
          <span className="seal seal-human" title="y · yurii">
            y
          </span>
          <span className="meta-line">yurii</span>
        </>
      ),
      body: "Sent from Yurii's account under the outreach grant.",
      acts: (
        <>
          <a className="act" href="/app/threads" title="linkedin · the whole thread">
            the thread
          </a>
          <a className="act" href="/app/settings" title="linkedin grant · scope, budget, expiry">
            the grant
          </a>
        </>
      ),
    },
    w3: {
      crumb: 'today · 11:48 · email',
      read: true,
      title: 'Pilot scope summary, delivered',
      by: (
        <span className="aname" data-agent="antevon" title="Antevon · the house mind">
          Antevon
        </span>
      ),
      body: 'Verified in the thread; the receipt holds the delivery.',
      acts: (
        <>
          <a className="act" href="/app/threads" title="email · the whole thread">
            the thread
          </a>
          <a className="act" href="#">
            the receipt
          </a>
        </>
      ),
    },
    w4: {
      crumb: 'today · 09:15 · LINE',
      read: true,
      title: 'Inbound from Mika Tanaka',
      by: (
        <>
          <span className="seal seal-human seal-class" title="m · Mika Tanaka">
            m
          </span>
          <span className="meta-line">Mika Tanaka</span>
        </>
      ),
      body: 'A quote request. The claim it carried is already in the vault.',
      acts: (
        <>
          <a className="act" href="/app/threads" title="LINE · the whole thread">
            the thread
          </a>
          <Link className="act" to="/app/vault" title="the extracted claim">
            open the claim
          </Link>
        </>
      ),
    },
  }
  const c = ctx ? CTX[ctx] : null
  /* gesture law: what unfolds UNDER a row — the why + the acts; a `read`
     door into the column only where there is a record to read */
  const glanceFor = (key: CtxKey) => {
    if (law !== 'gesture') return null
    const g = CTX[key]
    return (
      <div className="brow-detail">
        <div className="bd-inner">
          {typeof g.body === 'string' ? <span className="bd-why">{g.body}</span> : g.body}
          <span className="bd-acts">
            {g.acts}
            {g.read && (
              <a className="act" href="#" title="read it in the column" onClick={openCol(key)}>
                open →
              </a>
            )}
          </span>
        </div>
      </div>
    )
  }
  const wireGlance = (key: CtxKey) =>
    law === 'gesture' ? <div className={rowCls(key, 'brow w-glance')}>{glanceFor(key)}</div> : null

  return (
    <main className={ctx ? 'pane ctx-on' : 'pane'} id="pane">
      <div className="pane-body" ref={paneRef}>
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

      {/* the empty inbox (08-15 eve): the flock (the queue flew off), one line.
          fixtures always fill the inbox, so ?empty previews it. */}
      {empty && (
        <div className="inbox-empty">
          <img className="spot" src="/art/spot-flock.png" alt="" width={150} />
          <span className="lead">
            Nothing waits for you.
            <span className="sub">Your agents are on it; anything that needs you lands here.</span>
          </span>
        </div>
      )}
      {!empty && (
        <>
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
          <div className={rowCls('a1')}>
            <div className="brow-line" onClick={select('a1')}>
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
            {glanceFor('a1')}
          </div>
          <div className={rowCls('a2')}>
            <div className="brow-line" onClick={select('a2')}>
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
            {glanceFor('a2')}
          </div>
        </div>
        {/* the 40 that went in on their own are AUTO-ACCEPTED (owner
            08-15): no bundle verbs — the count is a door, nothing more */}
        <div className="bmore">
          <a className="act" href="#" title="the 40 that went in on their own · every write receipted">
            40 more
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
            className={law === 'column' ? rowCls('b1') : b1.open ? 'brow open' : 'brow'}
            aria-expanded={law === 'column' ? ctx === 'b1' : b1.open}
            tabIndex={0}
            onKeyDown={b1.onKeyDown}
          >
            <div className="brow-line" onClick={law === 'column' ? select('b1') : b1.onLineClick}>
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
                    onClick={law === 'column' ? openCol('b1') : b1.openRow}
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
                  <a className="act" href="/app/threads" title="LINE · Mika Tanaka · the whole thread">
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
            className={law === 'column' ? rowCls('b2') : b2.open ? 'brow open' : 'brow'}
            aria-expanded={law === 'column' ? ctx === 'b2' : b2.open}
            tabIndex={0}
            onKeyDown={b2.onKeyDown}
          >
            <div className="brow-line" onClick={law === 'column' ? select('b2') : b2.onLineClick}>
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
                <span className="aname" data-agent="eiri" title="Eiri · outbound · every send waits for your click">Eiri</span> asks: reach the Hokuei COO through Yurii’s account?
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
                    title="linkedin grant · yurii's account · scope, budget, expiry"
                  >
                    the grant
                  </a>
                  <a className="act" href="/app/orgs" title="Hokuei · the org dossier">
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
          <div className={rowCls('c1')}>
            <div className="brow-line" onClick={select('c1')}>
              <span className="dot dot-auto" title="prepared · nothing waits on you"></span>
              <span
                className="claim conf-2"
                title="brief · compiled for Thursday 10:00, cites every claim under it"
              >
                Meeting brief: Hokuei pilot call, Thursday 10:00
              </span>
              <span className="rverbs">
                <a className="act" href="/app/briefs">
            open brief
          </a>
              </span>
            </div>
            {glanceFor('c1')}
          </div>
          <div className={rowCls('c2')}>
            <div className="brow-line" onClick={select('c2')}>
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
            {glanceFor('c2')}
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
          <div className={rowCls('d1')}>
            <div className="brow-line" onClick={select('d1')}>
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
            {glanceFor('d1')}
          </div>
        </div>
      </Bundle>

      {/* DEFAULT STATE · the digest, in plain words (owner 08-14 eve) */}
        </>
      )}
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
          line per event: time · channel glyph · who · what happened.
          a row clicks into the context column (owner 08-15). agent
          events carry the NAME in ink (rule 15: seals are humans only —
          herald was internal vocabulary). */}
      <section className="wire" aria-label="every surface event">
        <div className="wire-head">
          Everything that crossed a channel today, in order. Reads only; the receipts hold the
          detail.
        </div>
        <div className="thread">
          <div className={rowCls('w1', 'w-row')} onClick={select('w1')}>
            <span className="w-time">14:05</span>
            <span className="w-chan" title="slack">
              <ChanSlack />
            </span>
            <span className="aname w-by" data-agent="antevon" title="Antevon · the house mind">
              Antevon
            </span>
            <span className="t-msg conf-3">
              Answered #ops: pilot timeline question, cited the scope note.
            </span>
          </div>
          {wireGlance('w1')}
          <div className={rowCls('w2', 'w-row')} onClick={select('w2')}>
            <span className="w-time">14:02</span>
            <span className="w-chan" title="linkedin">
              <ChanLinkedin />
            </span>
            <span className="seal seal-human" title="y · yurii">
              y
            </span>
            <span className="t-msg conf-3">DM to Hokuei COO sent · verifying</span>
          </div>
          {wireGlance('w2')}
          <div className={rowCls('w3', 'w-row')} onClick={select('w3')}>
            <span className="w-time">11:48</span>
            <span className="w-chan" title="email">
              <ChanMail />
            </span>
            <span className="aname w-by" data-agent="antevon" title="Antevon · the house mind">
              Antevon
            </span>
            <span className="t-msg conf-3">
              Pilot scope summary delivered · verified in thread · receipted
            </span>
          </div>
          {wireGlance('w3')}
          <div className={rowCls('w4', 'w-row')} onClick={select('w4')}>
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
          {wireGlance('w4')}
        </div>
      </section>
      </div>

      {/* the context column (owner 08-15, the Slack model): read-only
          detail docks here; the draft rows keep their in-place thread */}
      <aside className="context" hidden={!ctx} aria-label="the record">
        {c && (
          <>
            <div className="ctx-head">
              <span className="ctx-crumb">{c.crumb}</span>
              <button
                className="chat-close"
                aria-label="close the record"
                title="close · esc"
                onClick={() => setCtx(null)}
              >
                ×
              </button>
            </div>
            <div className="ctx-title">{c.title}</div>
            {c.by && <div className="ctx-by">{c.by}</div>}
            {typeof c.body === 'string' ? <span className="bd-why">{c.body}</span> : c.body}
            <span className="bd-acts">{c.acts}</span>
          </>
        )}
      </aside>
    </main>
  )
}
