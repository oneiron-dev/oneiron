import * as React from 'react'
import { Link, createFileRoute } from '@tanstack/react-router'
import { ChanLine, ChanMail, ChanSlack, Chevron } from '~/components/safelight/icons'
import { Throbber } from '~/components/safelight/Widgets'
import { cue, markCued, useEscape } from '~/components/safelight/hooks'
import threadsCss from '~/styles/threads.css?url'

export const Route = createFileRoute('/app/threads')({
  head: () => ({
    links: [{ rel: 'stylesheet', href: threadsCss }],
  }),
  component: Threads,
})

/* ── fixtures (FLOWS §2 cast · app-channels.html content) ──
   the channel identity is Antevon, the house mind: one persona per
   surface, each a grant you can revoke in place. */
type IdentKey = 'slack' | 'line' | 'email'
const IDENTS: Array<{
  key: IdentKey
  chan: string
  glyph: React.ReactNode
  handle: string
  aud: string
  audTitle: string
  state: string
  stateTitle: string
  receipts: number
  receiptsTitle: string
  revokeTitle: string
  charter: string
  scope: string
}> = [
  {
    key: 'slack',
    chan: 'slack',
    glyph: <ChanSlack />,
    handle: 'as @antevon',
    aud: '#ops · antevon workspace',
    audTitle: 'the antevon workspace · #ops and #pilot-hokuei',
    state: 'connected',
    stateTitle: 'connected 07-02 · granted by o',
    receipts: 41,
    receiptsTitle: '41 posts, each one receipted · open the receipts',
    revokeTitle: 'verb: revoke_grant · Antevon stops posting at once; the receipt lands in this row',
    charter: 'Antevon answers in #ops when someone addresses it. It never opens a thread on its own.',
    scope: 'scope: channel.read · channel.post · 40 posts a month · granted by o, 07-02',
  },
  {
    key: 'line',
    chan: 'LINE',
    glyph: <ChanLine />,
    handle: 'as @antevon',
    aud: 'official account · Hokuei contacts',
    audTitle: 'the Antevon official account · 3 contact threads',
    state: 'connected',
    stateTitle: 'connected 06-18 · read only · granted by o',
    receipts: 12,
    receiptsTitle: '12 inbound messages read and receipted · no send has ever left from here',
    revokeTitle: 'verb: revoke_grant · Antevon stops reading the account at once',
    charter: 'Mika writes to the account, not to an agent. Replies still leave from your hand.',
    scope: 'scope: inbound.read · no send verb granted · granted by o, 06-18',
  },
  {
    key: 'email',
    chan: 'email',
    glyph: <ChanMail />,
    handle: 'as ops@antevon.jp',
    aud: 'clients',
    audTitle: 'a verified sender on a domain you own · replies return to the same thread',
    state: 'verified',
    stateTitle: 'verified sender · SPF and DKIM pass · verified 06-30',
    receipts: 8,
    receiptsTitle: '8 sends, each with a delivery receipt · open the receipts',
    revokeTitle: 'verb: revoke_grant · the sender is retired and future sends fail closed',
    charter: 'Recipients see ops@antevon.jp, signed. Their replies come back into the same thread.',
    scope: 'scope: outbound.email · 20 sends a month · SPF and DKIM pass · verified 06-30',
  },
]

/* one ThreadEntry for every channel; slack #ops here. newest first: what
   is still verifying sits at the top, what settled sits below it. */
type Who = { seal: 'o' | 'y' } | { agent: 'antevon' }
type SendState = 'pending' | 'verified' | 'receipted'
type Entry = {
  key: string
  who: Who
  whoTitle: string
  voice: string
  conf: 1 | 2 | 3
  voiceTitle?: string
  send?: { state: SendState; word: string; title: string }
  end?: { word: string; title: string }
  door?: { text: string; title: string }
}
const ENTRIES: Entry[] = [
  {
    key: 'e1',
    who: { agent: 'antevon' },
    whoTitle: 'Antevon · 08-13 14:05 · slack #ops · sent on your click at 14:04',
    voice: 'Moving the freight terms question into #pilot-hokuei so it does not get lost here.',
    conf: 2,
    send: { state: 'pending', word: 'verifying', title: 'sent · verifying in the thread · the receipt lands when it is seen' },
  },
  {
    key: 'e2',
    who: { agent: 'antevon' },
    whoTitle: 'Antevon · 08-13 13:41 · slack #ops · answered because it was addressed',
    voice: 'Answered the timeline question in thread with the September start.',
    conf: 2,
    send: { state: 'receipted', word: 'receipted', title: 'delivery confirmed 13:42 · open the receipt' },
  },
  {
    key: 'e3',
    who: { seal: 'y' },
    whoTitle: 'y · yurii · 08-13 13:02 · slack #ops',
    voice: 'Their ops lead asked about freight terms. Parking it here until we hear it a second time.',
    conf: 2,
    voiceTitle: 'nothing minted · one mention is under the evidence floor',
  },
  {
    key: 'e4',
    who: { seal: 'o' },
    whoTitle: 'o · oleksii · 08-13 10:38 · slack · a direct message',
    voice: 'Note to self: ask whether Mika’s team can host the kickoff in Osaka.',
    conf: 3,
    end: { word: 'DM → your vault', title: 'a direct message writes to your own vault, never the shared one' },
  },
  {
    key: 'e5',
    who: { agent: 'antevon' },
    whoTitle: 'Antevon · 08-13 09:11 · slack #ops · posted on your click at 09:10',
    voice: 'Posted the scope note and cited the desk floor agreed in May.',
    conf: 2,
    send: { state: 'verified', word: 'verified', title: 'verified in thread 09:12 · open the receipt' },
  },
  {
    key: 'e6',
    who: { seal: 'o' },
    whoTitle: 'o · oleksii · 08-08 09:02 · slack #ops',
    voice: 'Confirmed with Mika: six weeks, starting the first week of September.',
    conf: 1,
    door: {
      text: '→ claim minted · antevon vault',
      title: 'cl_9f21 · 0.94 · the pilot runs six weeks from the first week of September · occurred 08-08 · learned 08-08',
    },
  },
  {
    key: 'e7',
    who: { seal: 'y' },
    whoTitle: 'y · yurii · 08-08 08:40 · slack #ops',
    voice: 'Hokuei want to move the pilot start. I said we would confirm today.',
    conf: 2,
    end: { word: '→ the shared vault', title: '#ops is a shared room · what it mints goes to antevon / ops' },
  },
]

/* what the context column shows: a record you READ (rule 39, rec A) */
type CtxKey = 'rc-slack' | 'rc-line' | 'rc-email' | 'e1' | 'e2' | 'e5'
type Ctx = {
  crumb: string
  title: string
  why?: string
  kv?: Array<{ k: string; v: React.ReactNode }>
  list?: Array<{ time: string; what: string; st: string; verified?: boolean }>
  acts: React.ReactNode
}
const CTX: Record<CtxKey, Ctx> = {
  'rc-slack': {
    crumb: 'slack #ops · receipts',
    title: '41 posts, each one receipted',
    why: 'Every send Antevon made into #ops, newest first. A receipt holds the message id, the audience, and the claims it cited.',
    list: [
      { time: '14:05', what: 'Moved the freight terms question into #pilot-hokuei.', st: 'verifying' },
      { time: '13:41', what: 'Answered the timeline question with the September start.', st: 'receipted' },
      { time: '09:11', what: 'Posted the scope note, cited the May desk floor.', st: 'verified', verified: true },
      { time: '08-12', what: 'Confirmed the Thursday call time in #pilot-hokuei.', st: 'receipted' },
      { time: '08-11', what: 'Shared the pilot scope summary.', st: 'receipted' },
    ],
    acts: (
      <>
        <a className="act" href="#" title="the 36 older receipts">
          36 more
        </a>
        <a className="act" href="#" title="the grant behind this identity · scope, budget, expiry">
          the grant
        </a>
      </>
    ),
  },
  'rc-line': {
    crumb: 'LINE · receipts',
    title: '12 inbound messages, read and receipted',
    why: 'Nothing has ever left from here. Each row is a message Antevon read on the official account.',
    list: [
      { time: '09:15', what: 'Mika Tanaka: a quote request for Tuesday.', st: 'read' },
      { time: '08-12', what: 'Mika Tanaka: confirmed the Thursday call.', st: 'read' },
      { time: '08-09', what: 'Hokuei ops: asked for the scope note.', st: 'read' },
    ],
    acts: (
      <>
        <a className="act" href="#" title="the 9 older receipts">
          9 more
        </a>
        <a className="act" href="#" title="the grant behind this identity · read only">
          the grant
        </a>
      </>
    ),
  },
  'rc-email': {
    crumb: 'email · receipts',
    title: '8 sends, each with a delivery receipt',
    why: 'Sent as ops@antevon.jp, signed. A receipt holds the delivery, the recipient, and the claims cited.',
    list: [
      { time: '11:48', what: 'Pilot scope summary to Hokuei ops.', st: 'delivered', verified: true },
      { time: '08-11', what: 'Thursday call agenda to Mika Tanaka.', st: 'delivered', verified: true },
      { time: '08-06', what: 'Introduction to the Hokuei COO.', st: 'delivered', verified: true },
    ],
    acts: (
      <>
        <a className="act" href="#" title="the 5 older receipts">
          5 more
        </a>
        <a className="act" href="#" title="the grant behind this identity · sender, budget, expiry">
          the grant
        </a>
      </>
    ),
  },
  e1: {
    crumb: 'send receipt · slack #ops · 14:05',
    title: 'Moving the freight terms question into #pilot-hokuei so it does not get lost here.',
    kv: [
      { k: 'message', v: 'sm_7c2e' },
      { k: 'audience', v: '#ops · 6 members' },
      { k: 'sent', v: '14:04 · your click' },
      { k: 'verify', v: 'in progress' },
      { k: 'cites', v: 'nothing' },
    ],
    acts: (
      <a className="act" href="#" title="slack · #ops · the message in place">
        open in slack
      </a>
    ),
  },
  e2: {
    crumb: 'send receipt · slack #ops · 13:41',
    title: 'Answered the timeline question in thread with the September start.',
    kv: [
      { k: 'message', v: 'sm_41d2' },
      { k: 'audience', v: '#ops · 6 members' },
      { k: 'sent', v: '13:41 · addressed' },
      { k: 'delivered', v: '13:42' },
      {
        k: 'cites',
        v: (
          <Link to="/app/vault" title="cl_9f21 · 0.94 · the pilot runs six weeks from the first week of September">
            cl_9f21
          </Link>
        ),
      },
    ],
    acts: (
      <>
        <a className="act" href="#" title="slack · #ops · the message in place">
          open in slack
        </a>
        <Link className="act" to="/app/vault" title="cl_9f21 · the claim it cited">
          the claim
        </Link>
      </>
    ),
  },
  e5: {
    crumb: 'send receipt · slack #ops · 09:11',
    title: 'Posted the scope note and cited the desk floor agreed in May.',
    kv: [
      { k: 'message', v: 'sm_39a0' },
      { k: 'audience', v: '#ops · 6 members' },
      { k: 'sent', v: '09:10 · your click' },
      { k: 'verified', v: '09:12 · in thread' },
      {
        k: 'cites',
        v: (
          <Link to="/app/vault" title="cl_77b3 · 0.91 · the desk floor agreed in May">
            cl_77b3
          </Link>
        ),
      },
    ],
    acts: (
      <>
        <a className="act" href="#" title="slack · #ops · the message in place">
          open in slack
        </a>
        <Link className="act" to="/app/vault" title="cl_77b3 · the claim it cited">
          the claim
        </Link>
      </>
    ),
  },
}

/* a section head that folds in place; the count shows only when closed */
function Section({
  label,
  className,
  title,
  titleTip,
  meta,
  eyebrow,
  children,
}: {
  label: string
  className?: string
  title: React.ReactNode
  titleTip?: string
  meta?: React.ReactNode
  eyebrow?: React.ReactNode
  children: React.ReactNode
}) {
  const [closed, setClosed] = React.useState(false)
  const toggle = () => {
    setClosed((c) => !c)
    cue('toggle')
  }
  return (
    <section
      className={['tsec', className, closed ? 'closed' : ''].filter(Boolean).join(' ')}
      aria-label={label}
    >
      {eyebrow}
      <div
        className="head"
        tabIndex={0}
        role="button"
        aria-expanded={!closed}
        onClick={(e) => {
          if ((e.target as HTMLElement).closest('a, button')) return
          toggle()
        }}
        onKeyDown={(e) => {
          if ((e.key === 'Enter' || e.key === ' ') && !(e.target as HTMLElement).closest('a, button')) {
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

function Threads() {
  const [hintOpen, setHintOpen] = React.useState(false)
  const [openIdent, setOpenIdent] = React.useState<IdentKey | null>(null)
  const [revoked, setRevoked] = React.useState<Record<IdentKey, boolean>>({
    slack: false,
    line: false,
    email: false,
  })
  const [promoted, setPromoted] = React.useState(false)
  const [ctx, setCtx] = React.useState<CtxKey | null>(null)

  /* esc closes what you opened: the record first, then the unfold */
  useEscape(() => {
    if (ctx) setCtx(null)
    else if (openIdent) setOpenIdent(null)
  })

  const toggleIdent = (key: IdentKey) => {
    setOpenIdent((cur) => (cur === key ? null : key))
    cue('toggle')
  }
  const onIdentClick = (key: IdentKey) => (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest('a, button')) return
    toggleIdent(key)
  }
  const onIdentKey = (key: IdentKey) => (e: React.KeyboardEvent) => {
    if ((e.key === 'Enter' || e.key === ' ') && !(e.target as HTMLElement).closest('a, button')) {
      e.preventDefault()
      toggleIdent(key)
    }
  }
  /* revoke settles in place: the act cools into the receipt line */
  const revoke = (key: IdentKey) => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setRevoked((r) => ({ ...r, [key]: true }))
    cue('press')
  }
  /* a record opens in the column; the same door closes it */
  const open = (key: CtxKey) => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setCtx((cur) => (cur === key ? null : key))
    cue('toggle')
  }
  /* promote settles in place: queued, with the door to the inbox */
  const promote = (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setPromoted(true)
    cue('success')
  }

  const c = ctx ? CTX[ctx] : null
  const pending = ENTRIES.filter((x) => x.send?.state === 'pending').length

  return (
    <main className={ctx ? 'pane ctx-on' : 'pane'} id="pane">
      <div className="pane-body">
        <div className="pane-head">
          <h1>Threads</h1>
          <span className="pane-tools">
            <button
              className="hint-btn"
              aria-expanded={hintOpen}
              aria-controls="threads-why"
              title="what this screen is"
              onClick={() => {
                setHintOpen((o) => !o)
                cue('toggle')
              }}
            >
              ?
            </button>
          </span>
        </div>
        <div className="dial-why" id="threads-why" hidden={!hintOpen}>
          <span className="why-voice">
            Who you are on each channel, and what each channel carries. An identity is a grant.
            Revoke it here and it stops at once. Promote the thread and its claims go to your inbox.
            Nothing goes out without your click.
          </span>
        </div>

        {/* ── identities · chrome: a flat ledger, unfold in place ── */}
        <Section
          label="channel identities"
          title="Channels"
          titleTip="one identity per surface · each is a grant you can revoke here"
          meta={
            <span className="meta-line" title="slack · LINE · email">
              3 identities
            </span>
          }
        >
          <div className="ident-wrap">
            <table className="ident" aria-label="channel identities">
              <thead>
                <tr>
                  <th className="c-chan">
                    <span className="sr-only">channel</span>
                  </th>
                  <th className="c-who">identity</th>
                  <th>audience</th>
                  <th className="c-state">state</th>
                  <th className="c-rcpt">receipts</th>
                  <th className="c-act"></th>
                </tr>
              </thead>
              <tbody>
                {IDENTS.map((id) => {
                  const on = openIdent === id.key
                  const gone = revoked[id.key]
                  const rcKey = `rc-${id.key}` as CtxKey
                  return (
                    <React.Fragment key={id.key}>
                      <tr
                        className={[
                          'idr',
                          on ? 'on' : '',
                          gone ? 'revoked' : '',
                          ctx === rcKey ? 'on' : '',
                        ]
                          .filter(Boolean)
                          .join(' ')}
                        tabIndex={0}
                        role="button"
                        aria-expanded={on}
                        aria-controls={`det-${id.key}`}
                        title={on ? 'close the grant behind this identity' : 'open the grant behind this identity'}
                        onClick={onIdentClick(id.key)}
                        onKeyDown={onIdentKey(id.key)}
                      >
                        <td className="c-chan">
                          <span className="w-chan" title={id.chan}>
                            {id.glyph}
                          </span>
                        </td>
                        <td className="c-who">
                          <span className="who">
                            <span
                              className="aname"
                              data-agent="antevon"
                              title="Antevon · the house mind · speaks as itself, never as you"
                            >
                              Antevon
                            </span>
                            <span className="as">{id.handle}</span>
                          </span>
                        </td>
                        <td>
                          <span className="aud" title={id.audTitle}>
                            {id.aud}
                          </span>
                        </td>
                        <td className="c-state">
                          <span className="st" title={id.stateTitle}>
                            {id.state}
                          </span>
                        </td>
                        <td className="c-rcpt">
                          <button className="door" title={id.receiptsTitle} onClick={open(rcKey)}>
                            {id.receipts}
                          </button>
                        </td>
                        <td className="c-act" aria-live="polite">
                          {gone ? (
                            <span className="meta-line" title="the grant is retired · the receipt is in this row">
                              revoked 14:07
                            </span>
                          ) : (
                            <a className="act" href="#" title={id.revokeTitle} onClick={revoke(id.key)}>
                              revoke
                            </a>
                          )}
                        </td>
                      </tr>
                      <tr className={on ? 'det on' : 'det'} id={`det-${id.key}`}>
                        <td colSpan={6}>
                          <div className="fold">
                            <div className="in">
                              <div className="in-pad">
                                <span className="charter">{id.charter}</span>
                                <span className="meta-line">{id.scope}</span>
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    </React.Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
        </Section>

        {/* ── the thread · an instrument: the agent-rendered lens, one
            component for every channel, slack #ops here ── */}
        <Section
          label="the thread"
          className="instrument"
          title="Slack #ops"
          titleTip="slack #ops · antevon workspace · 6 members · a shared room writes to the shared vault"
          eyebrow={
            <span
              className="label"
              title="agent-rendered lens · Antevon · slack #ops · synced 14:07"
            >
              antevon · as of 14:07
            </span>
          }
          meta={
            <span className="meta-line" title={`${ENTRIES.length} entries · ${pending} verifying`}>
              {ENTRIES.length} entries · {pending} verifying
            </span>
          }
        >
          <span className="thr-quiet" title="slack hides messages older than 90 days on the free plan">
            Durable decisions live in the vault.
          </span>

          <div className="tx-list" role="list">
            {ENTRIES.map((en) => {
              const isCtx = ctx === (en.key as CtxKey)
              return (
                <div className={isCtx ? 'tx sel' : 'tx'} key={en.key} role="listitem">
                  <span className="tx-who">
                    {'agent' in en.who ? (
                      <span className="aname" data-agent={en.who.agent} title={en.whoTitle}>
                        Antevon
                      </span>
                    ) : (
                      <span className="seal seal-human" title={en.whoTitle}>
                        {en.who.seal}
                      </span>
                    )}
                  </span>
                  <span className="tx-body">
                    <span className={`tx-voice conf-${en.conf}`} title={en.voiceTitle}>
                      {en.voice}
                    </span>
                    {en.door && (
                      <Link className="tx-door" to="/app/vault" title={en.door.title}>
                        {en.door.text}
                      </Link>
                    )}
                  </span>
                  {en.send && (
                    <button
                      className={`tx-end is-${en.send.state}`}
                      title={en.send.title}
                      aria-pressed={isCtx}
                      onClick={open(en.key as CtxKey)}
                    >
                      {en.send.word}
                      {en.send.state === 'pending' && <Throbber initial="⠋" />}
                    </button>
                  )}
                  {en.end && (
                    <span className="tx-end" title={en.end.title}>
                      {en.end.word}
                    </span>
                  )}
                </div>
              )
            })}
          </div>

          {/* the screen's one write: it queues ONE review bundle in the
              inbox; the outcome lands here as a receipt line, no toast */}
          <div className="thr-foot" aria-live="polite">
            {promoted ? (
              <>
                <span className="meta-line" title="run rx_5d19 · 3 candidates · nothing written yet · accepting the bundle writes it">
                  queued for review 14:07
                </span>
                <Link className="act" to="/app/inbox" title="one bundle, one decision, in the needs-you queue">
                  in your inbox
                </Link>
              </>
            ) : (
              <a
                className="act"
                href="#"
                title="verb: queue_review_bundle · the candidate claims in this thread go to the inbox as one decision"
                onClick={promote}
              >
                promote this thread
              </a>
            )}
            <button className="act" title="every send from #ops, in order, with its audience" onClick={open('rc-slack')}>
              open receipts
            </button>
          </div>
        </Section>
      </div>

      {/* the context column: a record you READ docks here (rule 39, rec A) */}
      <aside className="context" hidden={!ctx} aria-label="the record">
        {c && (
          <>
            <div className="ctx-head">
              <span className="ctx-crumb">{c.crumb}</span>
              <button
                className="chat-close"
                aria-label="close the record"
                title="close · esc"
                onClick={() => {
                  setCtx(null)
                  cue('toggle')
                }}
              >
                ×
              </button>
            </div>
            <div className="ctx-title">{c.title}</div>
            {c.why && <span className="ctx-why">{c.why}</span>}
            {c.kv && (
              <div className="ctx-kv">
                {c.kv.map((row) => (
                  <div className="kv" key={row.k}>
                    <span className="k">{row.k}</span>
                    <span className="v">{row.v}</span>
                  </div>
                ))}
              </div>
            )}
            {c.list && (
              <div className="rlist">
                {c.list.map((r, i) => (
                  <div className="rrow" key={i}>
                    <span className="r-time">{r.time}</span>
                    <span className="r-what">{r.what}</span>
                    <span className={r.verified ? 'r-st is-verified' : 'r-st'}>{r.st}</span>
                  </div>
                ))}
              </div>
            )}
            <span className="ctx-acts">{c.acts}</span>
          </>
        )}
      </aside>
    </main>
  )
}
