import * as React from 'react'
import { Link, createFileRoute } from '@tanstack/react-router'
import { ChanLine, ChanLinkedin, ChanMail, ChanSlack, Chevron } from '~/components/safelight/icons'
import { DraftCard, Throbber } from '~/components/safelight/Widgets'
import { cue, markCued, useDocumentEvent, useEscape } from '~/components/safelight/hooks'
import { previewReply, settleFixture, type FixtureAction, type FixtureReceipt, type ReplyPreview } from '~/components/safelight/inbox-fixture'
import inboxCss from '~/styles/inbox.css?url'

export const Route = createFileRoute('/app/inbox')({
  head: () => ({
    links: [{ rel: 'stylesheet', href: inboxCss }],
  }),
  component: Inbox,
})

/* ── rows settle in place: the dot fills, the verbs become the record.
   no toast ever — the outcome IS the row (08-14) ── */
type Settled = FixtureReceipt | null

function dotClass(settled: Settled, rest: string) {
  if (!settled) return `dot ${rest}`
  return `dot ${settled.ok ? 'dot-approved' : 'dot-rejected'}`
}
function dotTitle(settled: Settled, rest: string) {
  if (!settled) return rest
  return `${settled.word} · ${settled.clock}`
}
/* one icon: the channel glyph takes the outcome ink */
function chanClass(settled: Settled) {
  if (!settled) return 'w-chan'
  return `w-chan ${settled.ok ? 'chan-ok' : 'chan-no'}`
}
function chanTitle(settled: Settled, rest: string) {
  if (!settled) return rest
  return `${settled.word} · ${settled.clock}`
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

/* Native title buttons inspect; clicks on unused row space do the same.
   Nested controls own their events, never a parent button or key handler. */
function rowSurface(handler: (e: React.MouseEvent) => void) {
  return (e: React.MouseEvent) => {
    if ((e.target as Element).closest('a, button, input, textarea, select, [contenteditable]')) return
    handler(e)
  }
}

function Receipt({ value }: { value: FixtureReceipt }) {
  return <span className="meta-line">{value.word} · {value.clock}</span>
}

/* The first local decision wins. Nothing here is an engine receipt. */
function useSettle() {
  const [settled, setSettled] = React.useState<Settled>(null)
  const decided = React.useRef<Settled>(null)
  const focusAfter = React.useRef<{ from: HTMLElement; to: HTMLElement | null } | null>(null)
  React.useLayoutEffect(() => {
    const pending = focusAfter.current
    if (pending && !pending.from.isConnected && pending.to?.isConnected) pending.to.focus()
    focusAfter.current = null
  }, [settled])
  const act = (action: FixtureAction) => (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    markCued(e)
    if (decided.current) return
    const from = e.currentTarget as HTMLElement
    focusAfter.current = {
      from,
      to: from.closest('[data-inbox-row]')?.querySelector<HTMLElement>('[data-inbox-trigger]')
        ?? from.closest('aside.context')?.querySelector<HTMLElement>('.chat-close') ?? null,
    }
    decided.current = settleFixture(decided.current, action)
    setSettled(decided.current)
    cue(decided.current.ok ? 'success' : 'press')
  }
  return { settled, act }
}

/* Draft/consent rows retain their in-place act surface under kind/gesture. */
function useBrow() {
  const decision = useSettle()
  const [open, setOpen] = React.useState(false)
  const [replyText, setReplyText] = React.useState('')
  const [reply, setReply] = React.useState<ReplyPreview | null>(null)
  const openRow = (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    markCued(e)
    setOpen((o) => !o)
    cue('toggle')
  }
  return { ...decision, open, openRow, replyText, setReplyText, reply, setReply }
}

function ReplyInput({ row, placeholder }: { row: ReturnType<typeof useBrow>; placeholder: string }) {
  const noteId = React.useId()
  return (
    <div className="reply-preview">
      <input
        className="reply-input"
        type="text"
        placeholder={placeholder}
        aria-label="local reply preview for Eiri"
        aria-describedby={`inbox-preview-scope ${noteId}`}
        title="Enter keeps these words here only; nothing is sent to Eiri"
        value={row.replyText}
        onChange={(e) => row.setReplyText(e.target.value)}
        onKeyDown={(e) => {
          const next = previewReply(row.reply, e.currentTarget.value, {
            key: e.key, isComposing: e.nativeEvent.isComposing, keyCode: e.nativeEvent.keyCode,
            repeat: e.repeat, metaKey: e.metaKey, ctrlKey: e.ctrlKey, altKey: e.altKey, shiftKey: e.shiftKey,
          })
          if (next === row.reply) return
          e.preventDefault()
          e.stopPropagation()
          row.setReply(next)
        }}
      />
      <span id={noteId} className="fixture-feedback" role="status" aria-atomic="true">
        {row.reply && <>Kept here, not sent: “{row.reply.text}” · {row.reply.clock}</>}
      </span>
    </div>
  )
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
  const closeRef = React.useRef<HTMLButtonElement>(null)
  const ctxInvoker = React.useRef<{ key: CtxKey; element: HTMLElement } | null>(null)
  const glanceInvoker = React.useRef<{ key: CtxKey; element: HTMLElement } | null>(null)
  const [feedback, setFeedback] = React.useState<Record<string, string>>({})
  const [revealWire, setRevealWire] = React.useState(false)
  const wireRef = React.useRef<HTMLElement>(null)
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

  const restoreFocus = (invoker: { key: CtxKey; element: HTMLElement } | null) => {
    if (!invoker) return
    const row = paneRef.current?.querySelector<HTMLElement>(`[data-inbox-row="${invoker.key}"]`)
    const fallback = row?.querySelector<HTMLElement>('[data-inbox-trigger]') ?? row
    const heading = row?.closest('.bundle')?.querySelector<HTMLElement>('.head')
    for (const element of [invoker.element, fallback, heading, paneRef.current?.querySelector<HTMLElement>('.pane-tools button')]) {
      if (element?.isConnected && !element.closest('[inert]') &&
          element.getClientRects().length && getComputedStyle(element).visibility === 'visible') {
        element.focus()
        return
      }
    }
  }
  const closeColumn = () => {
    setCtx(null)
    restoreFocus(ctxInvoker.current)
  }
  const toggleColumn = (key: CtxKey, e: React.MouseEvent) => {
    if (ctx === key) closeColumn()
    else {
      const target = e.currentTarget as HTMLElement
      ctxInvoker.current = {
        key,
        element: target.matches('.brow-line')
          ? target.querySelector<HTMLElement>('[data-inbox-trigger]') ?? target
          : target,
      }
      setCtx(key)
    }
  }
  React.useEffect(() => {
    if (ctx) closeRef.current?.focus()
  }, [ctx])

  /* Gesture selects a glance only; kind/column summons the record. */
  const select = (key: CtxKey) => (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    markCued(e)
    if (law === 'gesture') {
      const target = e.currentTarget as HTMLElement
      glanceInvoker.current = {
        key,
        element: target.matches('.brow-line')
          ? target.querySelector<HTMLElement>('[data-inbox-trigger]') ?? target
          : target,
      }
      setGlance((cur) => (cur === key ? null : key))
    } else toggleColumn(key, e)
    cue('toggle')
  }
  const openCol = (key: CtxKey) => (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    markCued(e)
    toggleColumn(key, e)
    cue('toggle')
  }
  useEscape(() => {
    // Preserve the current asymmetry: column first, then gesture glance.
    // Kind/gesture draft unfolds are not dismissed by Escape.
    if (ctx) closeColumn()
    else if (glance) {
      setGlance(null)
      restoreFocus(glanceInvoker.current)
    }
  })
  const trigger = (key: CtxKey) => ({
    'data-inbox-trigger': key,
    'aria-expanded': law === 'gesture' ? glance === key : ctx === key,
    'aria-controls': law === 'gesture' ? `inbox-glance-${key}` : 'inbox-context',
    onClick: select(key),
  })
  const explain = (key: string, message: string) => (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    markCued(e)
    setFeedback((current) => current[key] === message ? current : { ...current, [key]: message })
  }
  const feedbackFor = (key: string, inColumn = false) => (
    <span className="fixture-feedback" role={(ctx === key) === inColumn ? 'status' : undefined} aria-atomic="true">
      {feedback[key]}
    </span>
  )
  React.useEffect(() => {
    if (!revealWire) return
    wireRef.current?.focus()
    wireRef.current?.scrollIntoView({ block: 'nearest' })
    setRevealWire(false)
  }, [revealWire])
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
          <button type="button" className="act" title="the April mention · LINE thread" onClick={explain('a1', 'The full April source is not included in this preview.')}>
            source
          </button>
          <Link className="act" to="/app/vault" title="Browse the fixture claims; no individual claim is selected">
            browse claims
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
          <button type="button" className="act" title="the supplier scout’s public filings" onClick={explain('a2', 'The scout’s source filings are not included in this preview.')}>
            source
          </button>
          <Link className="act" to="/app/vault" title="Browse the fixture claims; no individual claim is selected">
            browse claims
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
            <span className="seal seal-human seal-class" title="Mika Tanaka · LINE">
              m
            </span>
            <div className="bd-msg-body">
              <span className="bd-msg-meta">Mika Tanaka · 09:15 · LINE</span>
              <span className="bd-msg-text" lang="ja">
                見積書、火曜までにいただけますか。概算だけでも先にあると助かります。
              </span>
            </div>
          </div>
          <DraftCard
            agent="eiri"
            name="Eiri"
            nameTitle="Eiri wrote this draft · edit it in place"
            envelope="to Mika Tanaka · as Antevon OA"
            lang="ja"
            rows={3}
            ariaLabel="the draft to Mika Tanaka"
            defaultValue="お見積もりの件、承知しました。火曜までに正式版をお送りします。先に概算だけ共有します…"
            sendTitle="Local send preview only · nothing is sent"
            onSend={b1.act('send')}
          />
          <ReplyInput row={b1} placeholder="or tell Eiri what to change…" />
        </>
      ),
      acts: (
        <>
          <a className="act" href="/app/threads" title="Browse channel records, including Mika’s LINE quote request">
            browse threads
          </a>
          <button type="button" className="act" title="LINE OA grant" onClick={explain('b1', 'This LINE send grant is not included in the preview. No grant was created.')}>
            the grant
          </button>
        </>
      ),
    },
    b2: {
      crumb: 'Eiri · asks · linkedin',
      title: 'Reach the Hokuei COO through Yuki’s account?',
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
          <span className="bd-msg-meta" title="Proposed scope only · the preview creates no grant">
            proposed grant: LinkedIn · Hokuei people · through Yuki’s account
          </span>
          <span className="bd-acts">
            {!b2.settled && (
              <>
                <button type="button" className="act" title="Preview this choice locally · nothing is sent" onClick={b2.act('allow')}>
                  allow once
                </button>
                <button type="button" className="act" title="Preview this choice locally · no grant is created" onClick={b2.act('grant')}>
                  allow + grant
                </button>
                <button type="button" className="act" onClick={b2.act('deny')}>
                  deny
                </button>
              </>
            )}
          </span>
          <ReplyInput row={b2} placeholder="or answer Eiri in your words…" />
        </>
      ),
      acts: (
        <>
          <button type="button" className="act" title="LinkedIn grant · Yuki’s account" onClick={explain('b2', 'This LinkedIn grant is not included in the preview. No grant was created.')}>
            the grant
          </button>
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
        <button type="button" className="act" onClick={explain('c2', 'Only the note summary is included here; the run’s individual receipts are not.')}>
          the receipts
        </button>
      ),
    },
    d1: {
      crumb: 'linkedin import · paused',
      title: 'The burst guard stopped this import',
      body: 'Unusual write volume for this source, so the run paused itself. The bundle waits as one decision. Individual writes are not included in this preview.',
      acts: (
        <button type="button" className="act" onClick={explain('d1', 'The paused run’s full record is not included in this preview.')}>
          the run
        </button>
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
          <a className="act" href="/app/threads" title="Browse the Slack channel records">
            browse threads
          </a>
          <button type="button" className="act" onClick={explain('w1', 'The full receipt is not included here; this record is a fixture summary.')}>
            the receipt
          </button>
        </>
      ),
    },
    w2: {
      crumb: 'today · 14:02 · linkedin',
      read: true,
      title: 'DM to the Hokuei COO, sent',
      by: (
        <>
          <span className="seal seal-human" title="y · Yuki">
            y
          </span>
          <span className="meta-line">Yuki</span>
        </>
      ),
      body: "Sent from Yuki's account under the outreach grant.",
      acts: (
        <>
          <button type="button" className="act" onClick={explain('w2', 'The LinkedIn thread is not included in this preview.')}>
            the thread
          </button>
          <Link className="act" to="/settings/grants" title="Browse the fixture grants ledger; this LinkedIn grant is not included">
            grants ledger
          </Link>
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
          <a className="act" href="/app/threads" title="Browse channel records, including the pilot scope email">
            browse threads
          </a>
          <button type="button" className="act" onClick={explain('w3', 'The full receipt is not included here; this record is a fixture summary.')}>
            the receipt
          </button>
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
          <a className="act" href="/app/threads" title="Browse channel records, including Mika’s LINE quote request">
            browse threads
          </a>
          <Link className="act" to="/app/vault" title="Browse the fixture claims; no individual claim is selected">
            browse claims
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
      <div className="brow-detail" id={`inbox-glance-${key}`} inert={glance !== key}>
        <div className="bd-inner">
          {typeof g.body === 'string' ? <span className="bd-why">{g.body}</span> : g.body}
          <span className="bd-acts">
            {g.acts}
            {g.read && (
              <button type="button" className="act" title="read it in the column" aria-expanded={ctx === key} aria-controls="inbox-context" onClick={openCol(key)}>
                open →
              </button>
            )}
          </span>
        </div>
      </div>
    )
  }
  const wireGlance = (key: CtxKey) =>
    law === 'gesture' ? <div className={rowCls(key, 'brow w-glance')}>{glanceFor(key)}</div> : null

  return (
    <main className={ctx ? 'pane ctx-on' : 'pane'} id="pane" onClickCapture={(e) => {
      // Existing bare-act sound delegation must not add navigation sounds.
      if ((e.target as Element).closest('a[href^="/"]')) markCued(e)
    }}>
      <div className="pane-body" ref={paneRef}>
      {/* select anything → hand it to an agent (OF-248) */}
      <span
        className={summon.on ? 'summon on' : 'summon'}
        id="summon"
        style={{ left: summon.left, top: summon.top }}
      >
        <span className="meta-line">Agent hand-off is not available in this preview.</span>
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
      <p className="inbox-preview-scope" id="inbox-preview-scope">
        Local preview · actions stay on this screen until you leave. Nothing is sent or changed in an engine.
        Times are fixture times. Reply fields: Enter keeps your words here.
      </p>
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
          <div className={rowCls('a1')} data-inbox-row="a1">
            <div className="brow-line" onClick={rowSurface(select('a1'))}>
              <span
                className={dotClass(a1.settled, 'dot-proposed')}
                title={dotTitle(a1.settled, 'proposed · held for review')}
              ></span>
              <button type="button" {...trigger('a1')}
                className={claimClass(a1.settled, 'claim conf-3')}
                title="0.52 · held: low-confidence critical, one mention in April"
              >
                May be allergic to shellfish
              </button>
              <span className="rverbs" role="status" aria-atomic="true">
                {a1.settled ? (
                  <Receipt value={a1.settled} />
                ) : (
                  <>
                    <button type="button"
                      className="act"
                      title="Accept in this local preview"
                      onClick={a1.act('accept')}
                    >
                      accept
                    </button>
                    <button type="button"
                      className="act"
                      title="Reject in this local preview"
                      onClick={a1.act('reject')}
                    >
                      reject
                    </button>
                  </>
                )}
              </span>
            </div>
            {feedbackFor('a1')}
            {glanceFor('a1')}
          </div>
          <div className={rowCls('a2')} data-inbox-row="a2">
            <div className="brow-line" onClick={rowSurface(select('a2'))}>
              <span
                className={dotClass(a2.settled, 'dot-proposed')}
                title={dotTitle(a2.settled, 'proposed · held for review')}
              ></span>
              <button type="button" {...trigger('a2')}
                className={claimClass(a2.settled, 'claim conf-2')}
                title="0.81 · held: it contradicts a standing claim"
              >
                Hokuei may be consolidating suppliers this fiscal year
              </button>
              <span className="rverbs" role="status" aria-atomic="true">
                {a2.settled ? (
                  <Receipt value={a2.settled} />
                ) : (
                  <>
                    <button type="button" className="act" onClick={a2.act('accept')}>
                      accept
                    </button>
                    <button type="button" className="act" onClick={a2.act('reject')}>
                      reject
                    </button>
                  </>
                )}
              </span>
            </div>
            {feedbackFor('a2')}
            {glanceFor('a2')}
          </div>
        </div>
        {/* the 40 that went in on their own are AUTO-ACCEPTED (owner
            08-15): no bundle verbs — the count is a door, nothing more */}
        <div className="bmore">
          <button type="button" className="act" title="the other 40 claims" onClick={explain('more', 'Only the two held claims are included here; the other 40 are not listed in this preview.')}>
            40 more
          </button>
          {feedbackFor('more')}
        </div>
      </Bundle>

      {/* Eiri session: drafts + consent · LIVE, so the headline wears the
          [data-work] well in herald's ink; the byline signs the authorship */}
      <Bundle
        label="Eiri session"
        titleTip="Eiri works the Hokuei outreach · session sn_31a8 · fixture"
        title={
          <>
            <span className="aname" data-agent="eiri">Eiri</span>: Hokuei outreach
          </>
        }
        meta={
          <span className="meta-line" title="session sn_31a8 · fixture">
            2 wait · working <Throbber initial="⠧" />
          </span>
        }
      >
        <div className="brows">
          <div
            className={law === 'column' ? rowCls('b1') : b1.open ? 'brow open' : 'brow'}
            data-inbox-row="b1"
          >
            <div className="brow-line" onClick={rowSurface(law === 'column' ? select('b1') : b1.openRow)}>
              <span
                className={chanClass(b1.settled)}
                title={chanTitle(b1.settled, 'LINE · a draft waits on your click')}
              >
                <ChanLine />
              </span>
              <button
                type="button"
                data-inbox-trigger="b1"
                aria-expanded={law === 'column' ? ctx === 'b1' : b1.open}
                aria-controls={law === 'column' ? 'inbox-context' : 'inbox-detail-b1'}
                onClick={law === 'column' ? select('b1') : b1.openRow}
                className={claimClass(b1.settled, 'claim conf-1')}
                title="Open the draft and its local send preview"
              >
                Reply to Mika Tanaka: the quote for Tuesday
              </button>
              <span className="rverbs" role="status" aria-atomic="true">
                {b1.settled ? (
                  <Receipt value={b1.settled} />
                ) : (
                  <button type="button"
                    className="act"
                    title="the draft opens here; send sits beside it"
                    onClick={law === 'column' ? openCol('b1') : b1.openRow}
                  >
                    read
                  </button>
                )}
              </span>
            </div>
            {feedbackFor('b1')}
            <div className="brow-detail" id="inbox-detail-b1" inert={law === 'column' || !b1.open}>
              <div className="bd-inner">
                {/* what it answers (owner): the message being replied to, then
                    the editable draft with send right beside it */}
                <div className="bd-msg">
                  <span className="seal seal-human seal-class" title="Mika Tanaka · LINE">
                    m
                  </span>
                  <div className="bd-msg-body">
                    <span className="bd-msg-meta">Mika Tanaka · 09:15 · LINE</span>
                    <span className="bd-msg-text" lang="ja">
                      見積書、火曜までにいただけますか。概算だけでも先にあると助かります。
                    </span>
                  </div>
                </div>
                <DraftCard
                  agent="eiri"
                  name="Eiri"
                  nameTitle="Eiri wrote this draft · edit it in place"
                  envelope="to Mika Tanaka · as Antevon OA"
                  lang="ja"
                  rows={2}
                  ariaLabel="the draft to Mika Tanaka"
                  defaultValue="お見積もりの件、承知しました。火曜までに正式版をお送りします。先に概算だけ共有します…"
                  sendTitle="Local send preview only · nothing is sent"
                  onSend={b1.act('send')}
                />
                <ReplyInput row={b1} placeholder="or tell Eiri what to change…" />
                <span className="bd-acts">
                  <a className="act" href="/app/threads" title="Browse channel records, including Mika’s LINE quote request">
            browse threads
          </a>
                  <button type="button" className="act" title="LINE OA grant" onClick={explain('b1', 'This LINE send grant is not included in the preview. No grant was created.')}>
                    the grant
                  </button>
                </span>
              </div>
            </div>
          </div>
          <div
            className={law === 'column' ? rowCls('b2') : b2.open ? 'brow open' : 'brow'}
            data-inbox-row="b2"
          >
            <div className="brow-line" onClick={rowSurface(law === 'column' ? select('b2') : b2.openRow)}>
              <span
                className={chanClass(b2.settled)}
                title={chanTitle(b2.settled, 'LinkedIn · a consent ask waits on you')}
              >
                <ChanLinkedin />
              </span>
              <button
                type="button"
                data-inbox-trigger="b2"
                aria-expanded={law === 'column' ? ctx === 'b2' : b2.open}
                aria-controls={law === 'column' ? 'inbox-context' : 'inbox-detail-b2'}
                onClick={law === 'column' ? select('b2') : b2.openRow}
                className={claimClass(b2.settled, 'claim conf-2')}
                title="a new audience for the linkedin grant"
              >
                <span className="aname" data-agent="eiri" title="Eiri · outbound · every send waits for your click">Eiri</span> asks: reach the Hokuei COO through Yuki’s account?
              </button>
              <span className="rverbs" role="status" aria-atomic="true">
                {b2.settled ? (
                  <Receipt value={b2.settled} />
                ) : (
                  <>
                    <button type="button"
                      className="act"
                      title="Preview this choice locally · nothing is sent"
                      onClick={b2.act('allow')}
                    >
                      allow once
                    </button>
                    <button type="button" className="act" title="Preview this choice locally · no grant is created" onClick={b2.act('grant')}>
                      allow + grant
                    </button>
                    <button type="button" className="act" onClick={b2.act('deny')}>
                      deny
                    </button>
                  </>
                )}
              </span>
            </div>
            {feedbackFor('b2')}
            <div className="brow-detail" id="inbox-detail-b2" inert={law === 'column' || !b2.open}>
              <div className="bd-inner">
                <span className="bd-why">
                  A new audience for the LinkedIn grant, so it asks before it reaches. Every send
                  stays a human click.
                </span>
                <span className="bd-msg-meta" title="Proposed scope only · the preview creates no grant">
                  proposed grant: LinkedIn · Hokuei people · through Yuki’s account
                </span>
                <ReplyInput row={b2} placeholder="or answer Eiri in your words…" />
                <span className="bd-acts">
                  <button type="button"
                    className="act"
                    title="LinkedIn grant · Yuki’s account"
                    onClick={explain('b2', 'This LinkedIn grant is not included in the preview. No grant was created.')}
                  >
                    the grant
                  </button>
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
          <div className={rowCls('c1')} data-inbox-row="c1">
            <div className="brow-line" onClick={rowSurface(select('c1'))}>
              <span className="dot dot-auto" title="prepared · nothing waits on you"></span>
              <button type="button" {...trigger('c1')}
                className="claim conf-2"
                title="brief · compiled for Thursday 10:00, cites every claim under it"
              >
                Meeting brief: Hokuei pilot call, Thursday 10:00
              </button>
              <span className="rverbs">
                <a className="act" href="/app/briefs">
            open brief
          </a>
              </span>
            </div>
            {feedbackFor('c1')}
            {glanceFor('c1')}
          </div>
          <div className={rowCls('c2')} data-inbox-row="c2">
            <div className="brow-line" onClick={rowSurface(select('c2'))}>
              <span className="dot dot-auto" title="prepared · nothing waits on you"></span>
              <button type="button" {...trigger('c2')} className="claim conf-3" title="note · the 03:12 run, one line per receipt">
                Night-shift note: 03:12 run, one line per receipt
              </button>
              <span className="rverbs">
                <button type="button" className="act" aria-expanded={ctx === 'c2'} aria-controls="inbox-context" onClick={openCol('c2')}>
                  read
                </button>
              </span>
            </div>
            {feedbackFor('c2')}
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
          <div className={rowCls('d1')} data-inbox-row="d1">
            <div className="brow-line" onClick={rowSurface(select('d1'))}>
              <span
                className={dotClass(d1.settled, 'dot-proposed')}
                title={dotTitle(d1.settled, 'paused · waiting on you')}
              ></span>
              <button type="button" {...trigger('d1')}
                className={claimClass(d1.settled, 'claim conf-2')}
                title="paused run · the burst guard stopped it, nothing landed"
              >
                The burst guard stopped this import before anything landed
              </button>
              <span className="rverbs" role="status" aria-atomic="true">
                {d1.settled ? (
                  <Receipt value={d1.settled} />
                ) : (
                  <>
                    <button type="button" className="act" aria-expanded={ctx === 'd1'} aria-controls="inbox-context" onClick={openCol('d1')}>
                      review bundle
                    </button>
                    <button type="button" className="act" title="Resume is unavailable in this preview" onClick={explain('d1', 'Resume is unavailable in this preview. The import remains paused.')}>
                      resume
                    </button>
                    <button type="button"
                      className="act"
                      title="Discard locally · the run is unchanged"
                      onClick={d1.act('discard')}
                    >
                      discard
                    </button>
                  </>
                )}
              </span>
            </div>
            {feedbackFor('d1')}
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
        <button type="button" className="act" onClick={(e) => {
          e.preventDefault()
          markCued(e)
          setDialAll(true)
          setRevealWire(true)
          cue('toggle')
        }}>
          open receipts
        </button>
      </div>

      {/* DIAL = REVIEW EVERYTHING · the live stream unfolds. one tight
          line per event: time · channel glyph · who · what happened.
          a row clicks into the context column (owner 08-15). agent
          events carry the NAME in ink (rule 15: seals are humans only —
          herald was internal vocabulary). */}
      <section className={dialAll ? 'wire revealed' : 'wire'} aria-label="fixture channel receipts" tabIndex={-1} ref={wireRef}>
        <div className="wire-head">
          Everything that crossed a channel today, in order. Reads only; the receipts hold the
          detail.
        </div>
        <div className="thread">
          <button type="button" className={rowCls('w1', 'w-row')} data-inbox-row="w1" {...trigger('w1')}>
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
          </button>
          {feedbackFor('w1')}
          {wireGlance('w1')}
          <button type="button" className={rowCls('w2', 'w-row')} data-inbox-row="w2" {...trigger('w2')}>
            <span className="w-time">14:02</span>
            <span className="w-chan" title="linkedin">
              <ChanLinkedin />
            </span>
            <span className="seal seal-human" title="y · Yuki">
              y
            </span>
            <span className="t-msg conf-3">DM to Hokuei COO sent · verifying</span>
          </button>
          {feedbackFor('w2')}
          {wireGlance('w2')}
          <button type="button" className={rowCls('w3', 'w-row')} data-inbox-row="w3" {...trigger('w3')}>
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
          </button>
          {feedbackFor('w3')}
          {wireGlance('w3')}
          <button type="button" className={rowCls('w4', 'w-row')} data-inbox-row="w4" {...trigger('w4')}>
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
          </button>
          {feedbackFor('w4')}
          {wireGlance('w4')}
        </div>
      </section>
      </div>

      {/* the context column (owner 08-15, the Slack model): read-only
          detail docks here; the draft rows keep their in-place thread */}
      <aside className="context" id="inbox-context" hidden={!ctx} aria-label="the record">
        {c && (
          <>
            <div className="ctx-head">
              <span className="ctx-crumb">{c.crumb}</span>
              <button
                className="chat-close"
                aria-label="close the record"
                title="close · esc"
                ref={closeRef}
                onClick={closeColumn}
              >
                ×
              </button>
            </div>
            <div className="ctx-title">{c.title}</div>
            {c.by && <div className="ctx-by">{c.by}</div>}
            {typeof c.body === 'string' ? <span className="bd-why">{c.body}</span> : c.body}
            <span className="bd-acts">{c.acts}</span>
            {ctx && feedbackFor(ctx, true)}
            {ctx === 'a1' && a1.settled && <Receipt value={a1.settled} />}
            {ctx === 'a2' && a2.settled && <Receipt value={a2.settled} />}
            {ctx === 'b1' && b1.settled && <Receipt value={b1.settled} />}
            {ctx === 'b2' && b2.settled && <Receipt value={b2.settled} />}
            {ctx === 'd1' && d1.settled && <Receipt value={d1.settled} />}
          </>
        )}
      </aside>
    </main>
  )
}
