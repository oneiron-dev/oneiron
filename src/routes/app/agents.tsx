import * as React from 'react'
import { Link, createFileRoute, useNavigate } from '@tanstack/react-router'
import { ChanLine, ChanLinkedin, ChanMail, ChanSlack, Chevron, IconSettings } from '~/components/safelight/icons'
import { cue, markCued, openChat, useDocumentEvent, useEscape } from '~/components/safelight/hooks'
import { SelTools, selWithin, useSelTools } from '~/components/safelight/SelTools'
import { searchEmoji } from '~/components/safelight/emoji'
import { createPortal } from 'react-dom'
import agentsCss from '~/styles/agents.css?url'

/* ══ Agents · THE ROOM (owner 09-07) ══
   "chat integrated with the agents; chatting with the agent can help set it
   up; Grok Bot and squad.so are chat-first; Oneiron does progressive
   disclosure." So: the roster stands left, and the room on the right is the
   conversation with the chosen agent. SETUP (charter · channels · scopes ·
   schedule · budget · voice) and RUNS (now · earlier today) are the disclosed
   layers under the room head — one click down, the same column. Finished
   work is a CARD that points at the world (the inbox row, the claim, the
   receipt); the room never carries the work. A gate in the room is the
   inbox's own gate with the inbox's own verbs. The house is a room too. A
   new agent starts as a conversation with Antevon, who proposes the pieces
   and you confirm each one. Nothing rests red here. */

type AgentKey = 'eiri' | 'tory' | 'antevon'
type RunKey = 'eiri' | 'tory'
type Creature = AgentKey | 'none'
type ChanId = 'slack' | 'line' | 'mail' | 'linkedin'
type Schedule = 'continuous' | 'mornings' | 'nights' | 'on ask'
type RoomParam = AgentKey | 'house' | 'new'

export const Route = createFileRoute('/app/agents')({
  validateSearch: (s: Record<string, unknown>): { with?: RoomParam } => {
    const w = s.with
    return w === 'eiri' || w === 'tory' || w === 'antevon' || w === 'house' || w === 'new' ? { with: w } : {}
  },
  head: () => ({
    links: [{ rel: 'stylesheet', href: agentsCss }],
  }),
  component: Agents,
})

type Door = { label: string; tip: string; to?: '/app/inbox' | '/app/vault' | '/app/threads' | '/app/briefs'; href?: string }
type Tail = { when: string; what: string; door: Door }
type Grant = { v: string; tip: string; by: 'o' | 'y'; byTip: string; when: string; whenTip: string }

type Agent = {
  key: AgentKey
  name: string
  tip: string
  creature: { w: number; h: number; alt: string }
  charter: string
  detail: string
  model: string
  modelTip: string
  budget: string
  budgetTip: string
  budgetLadder: string[] | null
  budgetCap: string | null
  channels: ChanId[]
  schedule: Schedule
  scheduleTip: string
  voice: string
  last: string
  lastTip: string
  verbs: Grant[]
  tail: Tail[]
}

const AGENTS: Agent[] = [
  {
    key: 'eiri',
    name: 'Eiri',
    tip: 'Eiri · outbound · bound to you',
    creature: { w: 30, h: 24, alt: 'Iris, the messenger' },
    charter: 'Reaches out and keeps the thread warm.',
    detail:
      'Eiri writes outward in your register: intros, follow-ups, the note after a call. She may draft anything and promise nothing. Every send waits for your click. The sent copy comes back into the vault as a record.',
    model: 'kimi-k2.6',
    modelTip: 'kimi-k2.6 · pinned 08-02 · the model card and what it costs',
    budget: '¥170 of ¥600',
    budgetTip: '¥170 spent today of a ¥600 day cap · the cap pauses the agent, it never bills past it',
    budgetLadder: ['¥300', '¥600', '¥1,200'],
    budgetCap: '¥600',
    channels: ['line', 'mail'],
    schedule: 'on ask',
    scheduleTip: 'wakes on your ask, an inbound message, or a click on send',
    voice:
      'Writes in Yuki’s register. Short and warm, no exclamation marks. Japanese when the contact writes Japanese.',
    last: '14:09',
    lastTip: 'the last run settled at 14:09',
    verbs: [
      { v: 'read', tip: 'clients, base · standing · never the internal world', by: 'o', byTip: 'granted by Owen', when: '08-02', whenTip: 'granted 2026-08-02 · standing' },
      { v: 'propose', tip: 'claims from what she sends and hears · they wait for you', by: 'o', byTip: 'granted by Owen', when: '08-02', whenTip: 'granted 2026-08-02 · standing' },
      { v: 'draft', tip: 'any world she can read · drafts land in the inbox', by: 'o', byTip: 'granted by Owen', when: '08-02', whenTip: 'granted 2026-08-02 · standing' },
      { v: 'send', tip: 'LINE, email · one click per send · 20 a month', by: 'y', byTip: 'granted by Yuki', when: '08-07', whenTip: 'granted 2026-08-07 · expires 2026-10-07 · 20 sends a month' },
    ],
    tail: [
      { when: '14:02', what: 'Drafted the quote reply for Mika Tanaka. It waits on you.', door: { label: 'open', tip: 'the draft, in the inbox', to: '/app/inbox' } },
      { when: '11:20', what: 'Sent the pilot scope summary and verified it in the thread.', door: { label: 'receipt', tip: 'run rx_8c41 · the send, its grant and its verification', href: '#' } },
      { when: '09:15', what: 'Turned Mika Tanaka’s message into one claim.', door: { label: 'receipt', tip: 'run rx_8104 · source span, confidence, world', href: '#' } },
    ],
  },
  {
    key: 'tory',
    name: 'Tory',
    tip: 'Tory · research',
    creature: { w: 21, h: 26, alt: 'Athena, watchful' },
    charter: 'Reads filings and rumors, brings back claims.',
    detail:
      'Tory reads outward: filings, trade press, the client’s own site. She proposes claims and grades her own evidence, so a thin source stays thin. Nothing she finds becomes a memory until someone accepts it. She has never had a write.',
    model: 'kimi-k2.6',
    modelTip: 'kimi-k2.6 · pinned 08-02 · the model card and what it costs',
    budget: '¥110 of ¥450',
    budgetTip: '¥110 spent today of a ¥450 day cap · research is the cheap half of the roster',
    budgetLadder: ['¥150', '¥450', '¥900'],
    budgetCap: '¥450',
    channels: [],
    schedule: 'continuous',
    scheduleTip: 'the filings watch wakes every four hours · reads only',
    voice: 'Reports plainly. Grades every source. Says so when she finds nothing.',
    last: '14:09',
    lastTip: 'the last run settled at 14:09',
    verbs: [
      { v: 'read', tip: 'clients, base, the open web · standing', by: 'o', byTip: 'granted by Owen', when: '08-02', whenTip: 'granted 2026-08-02 · standing' },
      { v: 'propose', tip: 'claims only · every one carries its source and its floor', by: 'o', byTip: 'granted by Owen', when: '08-02', whenTip: 'granted 2026-08-02 · standing' },
    ],
    tail: [
      { when: '12:48', what: 'Read the Kansai freight filings for anything on Hokuei.', door: { label: 'receipt', tip: 'run rx_9033 · four writes, none waited', href: '#' } },
      { when: '11:05', what: 'Found nothing new in the July filings. The absence is recorded.', door: { label: 'receipt', tip: 'run rx_8e77 · a silence is evidence too · nothing minted', href: '#' } },
      { when: '08:30', what: 'Graded the supplier rumor at 0.41, one source.', door: { label: 'the claim', tip: 'the claim, its confidence and its lone source', to: '/app/vault' } },
    ],
  },
  {
    key: 'antevon',
    name: 'Antevon',
    tip: 'Antevon · the house mind · the vault’s own voice',
    creature: { w: 30, h: 16, alt: 'Mnemosyne, memory' },
    charter: 'Consolidates the vault every night and speaks for the house.',
    detail:
      'Antevon is the vault’s own voice. Every night it consolidates what the day brought in, and every write carries a receipt. By day it answers for the house, in Slack and email, and cites the vault when it does. It runs on this machine, so nothing leaves it.',
    model: 'qwen3-4b',
    modelTip: 'qwen3-4b · runs on this machine · nothing leaves it',
    budget: '¥0 · local',
    budgetTip: 'local inference · no credits, no metered tokens · electricity is the whole bill',
    budgetLadder: null,
    budgetCap: null,
    channels: ['slack', 'mail'],
    schedule: 'nights',
    scheduleTip: 'the nightly pass · 02:40, every night · answers by day when asked',
    voice: 'Speaks for the house. Cites the vault. Never promises.',
    last: '03:12',
    lastTip: 'run rx_7b12 · finished 03:12 · 42 writes · every write receipted',
    verbs: [
      { v: 'read', tip: 'every world, including internal · standing', by: 'o', byTip: 'granted by Owen', when: '07-19', whenTip: 'granted 2026-07-19 · at mint · standing' },
      { v: 'consolidate', tip: 'the nightly pass · claims in, receipts out', by: 'o', byTip: 'granted by Owen', when: '07-19', whenTip: 'granted 2026-07-19 · at mint · standing' },
      { v: 'answer', tip: 'Slack, email · answers cite the vault', by: 'o', byTip: 'granted by Owen', when: '07-28', whenTip: 'granted 2026-07-28 · Slack, email' },
    ],
    tail: [
      { when: '14:05', what: 'Answered #ops on the pilot timeline and cited the scope note.', door: { label: 'receipt', tip: 'slack · #ops · the answer and its citation', to: '/app/threads' } },
      { when: '03:20', what: 'Wrote the night-shift note after the consolidation.', door: { label: 'open', tip: 'the note, in the inbox', to: '/app/inbox' } },
      { when: '03:12', what: 'Consolidated the night: 42 claims went in, two waited for you.', door: { label: 'receipt', tip: 'run rx_7b12 · every claim the night pass touched, with its reason', href: '#' } },
    ],
  },
]

/* the live runs (the agent line points here) */
const RUNS: Array<{ agent: RunKey; doing: string; tip: string; since: string; world: string; elapsed: string; tokens: string; cost: string; needs?: string; helpers: Array<{ what: string; state: string; needs?: boolean }> }> = [
  { agent: 'eiri', doing: 'Drafting the COO intro, in Yuki’s register', tip: 'run rx_9b20 · started 13:55 · it will queue, not send', since: '13:55', world: 'hokuei', elapsed: '12m', tokens: '3.1k', cost: '¥4', needs: 'reaching the COO', helpers: [{ what: 'read the site and the org chart', state: 'done 13:58' }, { what: 'drafting, in Yuki’s register', state: '12m' }, { what: 'reaching the COO', state: 'needs you', needs: true }] },
  { agent: 'tory', doing: 'Checking the supplier rumor against the filings', tip: 'run rx_9b07 · started 13:26 · read-only scope', since: '13:26', world: 'hokuei', elapsed: '41m', tokens: '18k', cost: '¥21', helpers: [{ what: 'two filings open', state: '41m' }, { what: 'grading the source', state: '6m' }] },
]

/* what already ran today, newest first */
const HISTORY: Array<{ id: string; tip: string; ran: string; by: AgentKey; writes: number; waited: number; waitedTip: string; receiptTip: string; wake: string; wakeTip: string }> = [
  { id: 'rx_9033', tip: 'run rx_9033 · 12:41 to 12:48 · 31k tokens · ¥17', ran: 'Read the Kansai freight filings for anything on Hokuei', by: 'tory', writes: 4, waited: 0, waitedTip: 'nothing waited · every write cleared the floor', receiptTip: 'sources read, claims written, cost', wake: 'woke 12:41 · schedule', wakeTip: 'the filings watch wakes every four hours' },
  { id: 'rx_8c41', tip: 'run rx_8c41 · 11:14 to 11:20 · 8k tokens · ¥5', ran: 'Sent the pilot scope summary, then verified it in the thread', by: 'eiri', writes: 1, waited: 0, waitedTip: 'nothing waited · you had already approved the send', receiptTip: 'the draft you approved, the grant it sent under, the verification', wake: 'woke 11:14 · your click', wakeTip: 'your click on send woke the run' },
  { id: 'rx_8104', tip: 'run rx_8104 · 09:15 · 3k tokens · ¥2', ran: 'Turned Mika Tanaka’s LINE message into one claim', by: 'eiri', writes: 2, waited: 0, waitedTip: 'nothing waited · the claim came straight from her words', receiptTip: 'the thread entry the claim came from', wake: 'woke 09:15 · LINE', wakeTip: 'an inbound LINE message woke the run' },
  { id: 'rx_7b12', tip: 'run rx_7b12 · 02:40 to 03:12 · 76k tokens · ¥0 · local', ran: 'Nightly consolidation across base and clients', by: 'antevon', writes: 42, waited: 2, waitedTip: 'two claims waited for you · both accepted at 08:20 · history, not a queue', receiptTip: 'every claim the night pass touched, with its reason', wake: 'woke 02:40 · nightly', wakeTip: 'the nightly pass · 02:40, every night' },
]

const NAMES: Record<AgentKey, string> = { eiri: 'Eiri', tory: 'Tory', antevon: 'Antevon' }

type HistRow = (typeof HISTORY)[number]
type HistColId = 'ran' | 'by' | 'writes' | 'waited' | 'receipt' | 'wake'
const HIST_COLS: Array<{ id: HistColId; header: string; cls?: string; accessor?: (r: HistRow) => string | number }> = [
  { id: 'ran', header: 'run', accessor: (r) => r.ran },
  { id: 'by', header: 'by', cls: 'c-by', accessor: (r) => NAMES[r.by] },
  { id: 'writes', header: 'writes', cls: 'c-num num', accessor: (r) => r.writes },
  { id: 'waited', header: 'waited', cls: 'c-num num', accessor: (r) => r.waited },
  { id: 'receipt', header: 'receipt', cls: 'c-rcpt' },
  { id: 'wake', header: 'wake', cls: 'c-wake', accessor: (r) => r.wake },
]
const SETTLE_AT = '14:09'

const CHANNELS: Array<{ id: ChanId; label: string; tip: string; Glyph: () => React.JSX.Element }> = [
  { id: 'slack', label: 'Slack', tip: 'Slack · the workspace connected in settings', Glyph: ChanSlack },
  { id: 'line', label: 'LINE', tip: 'LINE · the official account connected in settings', Glyph: ChanLine },
  { id: 'mail', label: 'email', tip: 'email · the house mailbox', Glyph: ChanMail },
  { id: 'linkedin', label: 'LinkedIn', tip: 'LinkedIn · Yuki’s account, reads only', Glyph: ChanLinkedin },
]
const SCHEDULES: Array<{ id: Schedule; tip: string }> = [
  { id: 'continuous', tip: 'wakes on its own watch, every few hours' },
  { id: 'mornings', tip: 'one pass every morning at 08:00' },
  { id: 'nights', tip: 'one pass every night at 02:40' },
  { id: 'on ask', tip: 'wakes only when asked, or when a message arrives' },
]
const CREATURES: Array<{ id: Creature; alt: string; tip: string }> = [
  { id: 'eiri', alt: 'Iris, the messenger', tip: 'Iris · the messenger' },
  { id: 'tory', alt: 'Athena, watchful', tip: 'Athena · watchful' },
  { id: 'antevon', alt: 'Mnemosyne, memory', tip: 'Mnemosyne · memory' },
  { id: 'none', alt: '', tip: 'no creature · the name alone' },
]
/* what a proposed verb means, in the words the grants ledger uses */
const VERB_TIPS: Record<string, string> = {
  read: 'clients, base · standing · never the internal world',
  propose: 'claims from what it reads · they wait for you',
  draft: 'any world it can read · drafts land in the inbox',
}

/* ── the editable configuration of one agent — the fixtures seed it; a new
   agent starts empty. Every change settles in place with a quiet stamp. ── */
type Config = {
  id: string
  ink: AgentKey | null
  creature: Creature
  name: string
  role: string
  detail: string
  channels: ChanId[]
  grants: Array<Grant & { revoked?: string }>
  schedule: Schedule | null
  cap: string | null
  voice: string
  fixture: Agent | null
}

function seed(a: Agent): Config {
  return { id: a.key, ink: a.key, creature: a.key, name: a.name, role: a.charter, detail: a.detail, channels: a.channels, grants: a.verbs.map((g) => ({ ...g })), schedule: a.schedule, cap: a.budgetCap, voice: a.voice, fixture: a }
}
function blank(id: string): Config {
  return { id, ink: null, creature: 'none', name: '', role: '', detail: '', channels: [], grants: [], schedule: null, cap: null, voice: '', fixture: null }
}

function now() {
  const d = new Date()
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
}
function today() {
  const d = new Date()
  return `${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
}

/* ── the threads: one per room. a message is a line of voice, a card that
   points at the world, or a handoff between agents. ── */
type Who = 'o' | AgentKey
type Card =
  | { kind: 'door'; title: string; line: string; doors: Door[] }
  | { kind: 'gate'; id: string; title: string; why: string; remembers: string }
  | { kind: 'propose'; id: string; step: Step; title: string }
type Step = 'identity' | 'channels' | 'grants' | 'schedule'
type Msg = {
  id: string
  who: Who
  at: string
  text?: string
  live?: boolean
  card?: Card
  handoff?: { to: AgentKey; what: string }
  /* reply = a message (the 0010 pointer) · quote = a selection (the same
     pointer with the span) · thread = a branch HEAD never enters (0006a):
     the replies under a trunk message, depth one (owner 09-08) */
  replyTo?: { id: string; span?: string }
  replies?: Msg[]
  /* reactions (owner 09-08): a glyph and who put it there. agents react too;
     a 👀 from an agent is "seen", cheaper than a message (OF-372) */
  reacts?: Array<{ glyph: string; by: Who[] }>
}
const GLYPHS = ['👍', '❤️', '👀', '✅', '🙏', '✨']
type RoomKey = AgentKey | 'house' | string

const THREADS: Record<AgentKey | 'house', Msg[]> = {
  eiri: [
    { id: 'e1', who: 'eiri', at: '09:15', text: 'Mika Tanaka wrote on LINE: a quote request for Tuesday. I turned it into one claim.', card: { kind: 'door', title: 'Mika Tanaka prefers LINE for quick questions', line: 'one claim · 0.90 · waits on nobody', doors: [{ label: 'the claim', tip: 'the claim, its source span and its confidence', to: '/app/vault' }] } },
    { id: 'e2', who: 'eiri', at: '11:20', text: 'Sent the pilot scope summary and verified it in the thread.', card: { kind: 'door', title: 'Pilot scope summary · to Hokuei ops', line: 'sent 11:14 on your click · verified in thread 11:20', doors: [{ label: 'receipt', tip: 'run rx_8c41 · the send, its grant and its verification', href: '#' }, { label: 'the thread', tip: 'email · Hokuei ops', to: '/app/threads' }] } },
    { id: 'e3', who: 'o', at: '13:12', text: 'Draft a reply to Mika about the quote. Short. Japanese.' },
    { id: 'e4', who: 'eiri', at: '13:14', text: 'Drafting. It waits for your click before anything leaves.' },
    { id: 'e5', who: 'eiri', at: '14:02', text: 'The reply is ready.', card: { kind: 'door', title: 'Reply to Mika Tanaka: the quote for Tuesday', line: 'a draft · LINE · waits in your inbox', doors: [{ label: 'open', tip: 'the draft, in the inbox · edit it there, send from there', to: '/app/inbox' }] } },
    { id: 'e6', who: 'eiri', at: '14:06', card: { kind: 'gate', id: 'g-eiri-linkedin', title: 'Reach the Hokuei COO through Yuki’s account?', why: 'A new audience for the LinkedIn grant, so I ask before I reach. Every send stays a human click.', remembers: 'allow + grant remembers: LinkedIn · Hokuei people · through Yuki’s account' } },
  ],
  tory: [
    { id: 't1', who: 'tory', at: '08:30', text: 'Graded the supplier rumor at 0.41. One source, second-hand.', card: { kind: 'door', title: 'Hokuei may be consolidating suppliers this fiscal year', line: 'proposed · 0.61 after the email · contradicts the May claim', doors: [{ label: 'the claim', tip: 'the claim, its confidence and its lone source', to: '/app/vault' }] } },
    { id: 't2', who: 'tory', at: '11:05', text: 'Found nothing new in the July filings. The absence is recorded.', card: { kind: 'door', title: 'July filings · nothing on Hokuei', line: 'a silence is evidence too · nothing minted', doors: [{ label: 'receipt', tip: 'run rx_8e77', href: '#' }] } },
    { id: 't2q', who: 'o', at: '11:40', text: 'Why so low?', replyTo: { id: 't1', span: '0.41' } },
    { id: 't2a', who: 'tory', at: '11:42', text: 'One source, and it is second-hand. The floor for a critical claim is two, so it stays a proposal until a second one lands.' },
    { id: 't3', who: 'o', at: '12:30', text: 'Anything in the Kansai freight filings on Hokuei?' },
    { id: 't4', who: 'tory', at: '12:48', text: 'Read them. Four claims written, none waited.', replyTo: { id: 't3' }, reacts: [{ glyph: '✅', by: ['o'] }], card: { kind: 'door', title: 'Kansai freight filings · Hokuei', line: 'four writes · every one cleared the floor', doors: [{ label: 'receipt', tip: 'run rx_9033 · sources read, claims written, cost', href: '#' }] } },
    { id: 't5', who: 'tory', at: '13:26', live: true, text: 'Checking the supplier rumor against the filings now. Two filings open so far; neither of them says consolidation.' },
  ],
  antevon: [
    { id: 'a1', who: 'antevon', at: '03:12', text: 'Consolidated the night. 42 claims went in on their own. Two wait for you: the allergy claim has one source, and the supplier claim contradicts a claim from May.', card: { kind: 'door', title: 'Nightly consolidation', line: '42 in · 2 wait for you', doors: [{ label: 'open', tip: 'the two claims, in the inbox', to: '/app/inbox' }, { label: 'receipt', tip: 'run rx_7b12 · every claim the night pass touched, with its reason', href: '#' }] } },
    { id: 'a2', who: 'antevon', at: '03:20', text: 'Wrote the night-shift note.', card: { kind: 'door', title: 'Night-shift note: the 03:12 run', line: 'one line per receipt', doors: [{ label: 'read', tip: 'the note, in the inbox', to: '/app/inbox' }] } },
    { id: 'a3', who: 'o', at: '08:20', text: 'Accepted both. Keep the allergy one proposed until a second source.' },
    { id: 'a4', who: 'antevon', at: '08:20', text: 'Kept. The floor stays at two sources for a critical claim.' },
    { id: 'a5', who: 'antevon', at: '14:05', text: 'Answered #ops on the pilot timeline and cited the scope note.', card: { kind: 'door', title: 'Slack #ops · the pilot timeline', line: 'answered because it was addressed · cites cl_9f21', doors: [{ label: 'the thread', tip: 'slack #ops · the answer in place', to: '/app/threads' }] } },
  ],
  house: [
    { id: 'h1', who: 'o', at: '09:02', text: 'Hokuei want to move the pilot start. Tory, anything in the filings? Eiri, hold the COO intro until we know.', reacts: [{ glyph: '👀', by: ['tory', 'eiri'] }] },
    { id: 'h2', who: 'antevon', at: '09:03', handoff: { to: 'tory', what: 'the Kansai freight filings, anything on Hokuei' } },
    { id: 'h3', who: 'antevon', at: '09:03', handoff: { to: 'eiri', what: 'hold the COO intro · draft only' } },
    { id: 'h4', who: 'tory', at: '12:48', text: 'Read the Kansai filings. Nothing on Hokuei moving; four claims on freight terms.', replyTo: { id: 'h1' }, card: { kind: 'door', title: 'Kansai freight filings · Hokuei', line: 'four writes · none waited', doors: [{ label: 'receipt', tip: 'run rx_9033', href: '#' }] }, reacts: [{ glyph: '👍', by: ['o'] }], replies: [
      { id: 'h4r1', who: 'o', at: '12:50', text: 'Any freight terms that bite us?' },
      { id: 'h4r2', who: 'tory', at: '12:52', text: 'Two. A 30-day settlement clause and a fuel surcharge cap. Both are on the claims.', replyTo: { id: 'h4r1', span: 'bite us' } },
    ] },
    { id: 'h5', who: 'eiri', at: '13:55', text: 'Starting the COO intro in Yuki’s register. It will queue, not send.' },
    { id: 'h6', who: 'eiri', at: '14:02', text: 'The Mika reply is ready.', card: { kind: 'door', title: 'Reply to Mika Tanaka: the quote for Tuesday', line: 'a draft · LINE · waits in your inbox', doors: [{ label: 'open', tip: 'the draft, in the inbox', to: '/app/inbox' }] } },
    { id: 'h7', who: 'antevon', at: '14:07', text: 'Today was mostly Eiri. Nothing left the building without you. Tory’s supplier rumor still rests on one source, so it stays a proposal.' },
  ],
}

/* what a room answers when you write into it (the fixture's voice) */
const REPLY: Record<AgentKey, string> = {
  eiri: 'On it. Nothing leaves without your click; it will wait in your inbox.',
  tory: 'Reading. I grade every source, so a thin one stays thin.',
  antevon: 'Noted. I will cite the vault when I answer.',
}

/* ── the new-agent conversation: Antevon proposes, you confirm each piece ── */
const NAME_POOL = ['Wren', 'Sable', 'Juno', 'Nell']
type Proposal = { name: string; role: string; channels: ChanId[]; verbs: string[]; schedule: Schedule }
function propose(brief: string, taken: string[]): Proposal {
  const b = brief.toLowerCase()
  const name = NAME_POOL.find((n) => !taken.includes(n)) ?? 'Wren'
  let role = brief.trim().replace(/[.!\s]+$/, '')
  role = role.charAt(0).toUpperCase() + role.slice(1)
  if (role.length > 72) role = role.slice(0, 69).replace(/\s\S*$/, '') + '…'
  const channels: ChanId[] = []
  if (/\bline\b/.test(b)) channels.push('line')
  if (/mail|invoice|quote|newsletter|reply|replies/.test(b)) channels.push('mail')
  if (/slack|#/.test(b)) channels.push('slack')
  if (/linkedin/.test(b)) channels.push('linkedin')
  const reads = /research|read|filing|watch|monitor|track|registry|news|compare/.test(b)
  const verbs = reads ? ['read', 'propose'] : ['read', 'propose', 'draft']
  const schedule: Schedule = /night|overnight/.test(b)
    ? 'nights'
    : /morning|daily|every day|each day/.test(b)
      ? 'mornings'
      : /watch|monitor|every|track|hourly/.test(b)
        ? 'continuous'
        : 'on ask'
  return { name, role: role + '.', channels, verbs, schedule }
}

const STEP_AFTER: Record<Step, Step | 'done'> = { identity: 'channels', channels: 'grants', grants: 'schedule', schedule: 'done' }
function stepIntro(step: Step, p: Proposal): string {
  switch (step) {
    case 'identity':
      return 'Here is a name and a role to start from. Change either in place, then confirm.'
    case 'channels':
      return p.channels.length
        ? 'Channels it may use. I read them from what you said; turn any off before you confirm.'
        : 'No channel yet. It can still read and propose; connect one later in its setup.'
    case 'grants':
      return 'The grants it would hold. Send stays yours to grant, always, one click per send.'
    case 'schedule':
      return 'When it wakes. Confirm this and it is set up.'
  }
}

/* a door: a Link where the route exists, a plain anchor otherwise */
function DoorAct({ door, className = 'act' }: { door: Door; className?: string }) {
  if (door.to) {
    return (
      <Link className={className} to={door.to} title={door.tip}>
        {door.label}
      </Link>
    )
  }
  return (
    <a className={className} href={door.href ?? '#'} title={door.tip} onClick={(e) => e.preventDefault()}>
      {door.label}
    </a>
  )
}

/* the face: one mask in the agent's ink; 72 in the room head, small in rows */
/* the pause glyph is a button, not a word (owner 09-08) */
/* the hover tier speaks in glyphs (owner 09-08, "use symbols more"): the
   reply arrow, and a bubble for the thread. the word rides the tooltip. */
function IconReply() {
  return (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M6.5 3.5 3 7l3.5 3.5" />
      <path d="M3 7h5.5a4.5 4.5 0 0 1 4.5 4.5V13" />
    </svg>
  )
}
function IconThread() {
  return (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M3 13V4.5A1.5 1.5 0 0 1 4.5 3h7A1.5 1.5 0 0 1 13 4.5v4.6a1.5 1.5 0 0 1-1.5 1.5H6z" />
      <path d="M6 6.2h4M6 8.2h2.5" />
    </svg>
  )
}
function IconReact() {
  return (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="7" cy="9" r="5.5" />
      <path d="M4.8 10.4a2.9 2.9 0 0 0 4.4 0" />
      <path d="M5.3 7.6h.01M8.7 7.6h.01" strokeWidth="1.8" />
      <path d="M13 1.8v3.6M11.2 3.6h3.6" />
    </svg>
  )
}
function IconPause() {
  return (
    <svg viewBox="0 0 12 12" aria-hidden="true">
      <rect x="2" y="1.5" width="3" height="9" rx="0.6" />
      <rect x="7" y="1.5" width="3" height="9" rx="0.6" />
    </svg>
  )
}
function IconPlay() {
  return (
    <svg viewBox="0 0 12 12" aria-hidden="true">
      <path d="M3 1.5 L10.5 6 L3 10.5 Z" />
    </svg>
  )
}

function Face({ c, size, alt }: { c: Creature; size: number; alt?: string }) {
  if (c === 'none') return <span className="creature-none" aria-hidden="true" />
  const spec = CREATURES.find((x) => x.id === c)!
  return <span className="face" data-agent={c} role="img" aria-label={alt ?? spec.alt} style={{ width: size, height: size }} />
}

/* headings collapse in place (rule 10); the count shows only when closed */
function Section({ label, title, meta, voice, children }: { label: string; title: string; meta?: React.ReactNode; voice?: React.ReactNode; children: React.ReactNode }) {
  const [closed, setClosed] = React.useState(false)
  const toggle = () => {
    setClosed((c) => !c)
    cue('toggle')
  }
  return (
    <section className={closed ? 'ag-sec closed' : 'ag-sec'} aria-label={label}>
      <div
        className="ag-head"
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
        <span className="ag-title">{title}</span>
        <span className="fold-hint" aria-hidden="true">
          <Chevron ariaHidden={false} />
        </span>
        {meta}
      </div>
      {voice}
      <div className="ag-rows">{children}</div>
    </section>
  )
}

/* an editable line or paragraph: contentEditable, settles on blur */
function Editable({ as = 'span', className, value, placeholder, onCommit, autoFocus, title }: { as?: 'span' | 'p' | 'h2'; className?: string; value: string; placeholder: string; onCommit: (next: string) => void; autoFocus?: boolean; title?: string }) {
  const ref = React.useRef<HTMLElement | null>(null)
  React.useEffect(() => {
    if (autoFocus && ref.current) ref.current.focus()
  }, [autoFocus])
  const Tag = as as 'span'
  return (
    <Tag
      ref={ref as React.RefObject<HTMLSpanElement>}
      className={className ? `edit ${className}` : 'edit'}
      contentEditable
      suppressContentEditableWarning
      spellCheck={false}
      role="textbox"
      aria-label={placeholder}
      aria-multiline={as === 'p' || undefined}
      data-empty={value ? undefined : ''}
      data-placeholder={placeholder}
      title={title ?? 'click to edit · it settles when you leave'}
      onInput={(e) => {
        const el = e.currentTarget as HTMLElement
        const empty = !(el.textContent ?? '').trim()
        if (empty && el.innerHTML) el.innerHTML = ''
        el.toggleAttribute('data-empty', empty)
      }}
      onBlur={(e) => {
        const next = (e.currentTarget.textContent ?? '').trim()
        if (next !== value) onCommit(next)
      }}
      onKeyDown={(e) => {
        if (as !== 'p' && e.key === 'Enter') {
          e.preventDefault()
          ;(e.currentTarget as HTMLElement).blur()
        }
      }}
    >
      {value}
    </Tag>
  )
}

type Layer = 'thread' | 'setup'

function Agents() {
  const search = Route.useSearch()
  const navigate = useNavigate({ from: Route.fullPath })
  const [hintOpen, setHintOpen] = React.useState(false)
  /* the roster's configuration; fixtures seed it, new agents join it */
  const [configs, setConfigs] = React.useState<Config[]>(() => AGENTS.map(seed))
  /* the room: which key stands on the right */
  const [room, setRoomState] = React.useState<RoomKey>('eiri')
  const [layer, setLayer] = React.useState<Layer>('thread')
  /* the threads, seeded by the fixtures; what you write joins them */
  const [threads, setThreads] = React.useState<Record<string, Msg[]>>(() => ({ ...THREADS }))
  /* gates and proposals settle in place */
  const [gates, setGates] = React.useState<Record<string, { ok: boolean; word: string; when: string }>>({})
  const [done, setDone] = React.useState<Record<string, string>>({})
  /* the proposal under discussion for a new agent (edited in place) */
  const [prop, setProp] = React.useState<Proposal | null>(null)
  const [draft, setDraft] = React.useState('')
  /* the quiet stamps: `${id}:${section}` → hh:mm */
  const [saved, setSaved] = React.useState<Record<string, string>>({})
  /* revoke arms red, then settles on the second click */
  const [armed, setArmed] = React.useState<string | null>(null)
  /* pause parks the agent (nothing new starts; the live run finishes) */
  const [paused, setPaused] = React.useState<Record<string, string>>({})
  /* the live run prints in the thread (owner 09-08: the merge into the conversation);
     when its card scrolls out of view a thin line above the composer carries the count */
  const liveRef = React.useRef<HTMLDivElement>(null)
  const [liveSeen, setLiveSeen] = React.useState(true)
  /* the work pane (owner 09-08, "the floaty thing on top right … can expand
     into a sidebar like Codex"): closed = one mark in the air; open = docked */
  const [pane, setPane] = React.useState(false)
  /* stop = the cancel signal (rule 34): the run settles midway, in place */
  const [stopped, setStopped] = React.useState<Partial<Record<RunKey, boolean>>>({})
  /* the ledger sorts on its heads: asc → desc → off */
  const [sort, setSort] = React.useState<{ id: HistColId; dir: 'asc' | 'desc' } | null>(null)
  /* the house composer addresses one agent or everyone */
  const [addr, setAddr] = React.useState<AgentKey | 'all'>('all')
  const [amenuOpen, setAmenuOpen] = React.useState(false)
  /* reply · quote · thread (owner 09-08): what the composer answers, the
     thread standing in the right slot, and that thread's own composer */
  const [quoting, setQuoting] = React.useState<{ id: string; span?: string } | null>(null)
  const [openThread, setOpenThread] = React.useState<string | null>(null)
  const [tdraft, setTdraft] = React.useState('')
  const [tquoting, setTquoting] = React.useState<{ id: string; span?: string } | null>(null)
  const [alsoRoom, setAlsoRoom] = React.useState(false)
  /* the message a strip travelled to lights up for a beat */
  const [lit, setLit] = React.useState<string | null>(null)
  /* the glyph row open on one message; `+` opens the search (a fixed card
     off the chip, portaled so the thread's scroll box never clips it) */
  const [picking, setPicking] = React.useState<string | null>(null)
  const [emoji, setEmoji] = React.useState<{ q: string; x: number; y: number; up: boolean } | null>(null)
  const emojiRef = React.useRef<HTMLInputElement>(null)
  const roomRef = React.useRef<HTMLElement>(null)
  const tinputRef = React.useRef<HTMLInputElement>(null)
  const { sel, raise: raiseSel, clear: clearSel } = useSelTools(roomRef, { min: 2 })
  const newCount = React.useRef(0)
  const msgCount = React.useRef(0)
  const rowRefs = React.useRef<Record<string, HTMLButtonElement | null>>({})
  const inputRef = React.useRef<HTMLInputElement>(null)
  const threadRef = React.useRef<HTMLDivElement>(null)

  const newest = React.useMemo(() => configs.find((c) => !c.fixture) ?? null, [configs])
  const current = configs.find((c) => c.id === room) ?? null
  const isHouse = room === 'house'
  /* the room's kind decides the verbs: threads only where several parties
     talk (group · channel · mirror); replies and quotes everywhere */
  const canThread = isHouse
  React.useEffect(() => {
    setQuoting(null)
    setOpenThread(null)
    setTquoting(null)
    setTdraft('')
  }, [room])
  const isNew = !!current && !current.fixture

  /* the url names the room (?with=) so a room can be handed on as a link;
     `new` is the draft agent, made on demand */
  const setRoom = React.useCallback(
    (key: RoomKey, opts?: { layer?: Layer }) => {
      setRoomState(key)
      setLayer(opts?.layer ?? 'thread')
      setAmenuOpen(false)
      const w: RoomParam | undefined = key === 'house' ? 'house' : key === 'eiri' || key === 'tory' || key === 'antevon' ? key : key.startsWith('new') ? 'new' : undefined
      navigate({ search: w ? { with: w } : {}, replace: true })
    },
    [navigate],
  )
  const openNew = React.useCallback(
    (from?: React.MouseEvent) => {
      if (from) markCued(from)
      const existing = configs.find((c) => !c.fixture)
      if (existing) {
        setRoom(existing.id)
        cue('toggle')
        return
      }
      newCount.current += 1
      const id = `new-${newCount.current}`
      setConfigs((cs) => [...cs, blank(id)])
      setThreads((t) => ({
        ...t,
        [id]: [
          { id: `${id}-0`, who: 'antevon', at: now(), text: 'A new agent. Tell me what it should do, in one sentence. I will propose a name, its channels, its grants and when it wakes; you confirm each piece, or change it.' },
        ],
      }))
      setProp(null)
      setRoom(id)
      cue('toggle')
      setTimeout(() => inputRef.current?.focus(), 120)
    },
    [configs, setRoom],
  )
  /* the url on arrival */
  React.useEffect(() => {
    const w = search.with
    if (!w) return
    if (w === 'new') {
      if (!newest) openNew()
      else setRoomState(newest.id)
      return
    }
    setRoomState(w)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search.with])

  /* the thread keeps its foot in view */
  React.useEffect(() => {
    const el = threadRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [threads, room, layer])
  React.useEffect(() => {
    const el = liveRef.current
    const root = threadRef.current
    if (!el || !root) {
      setLiveSeen(true)
      return
    }
    const io = new IntersectionObserver(([e]) => setLiveSeen(e.isIntersecting), { root, threshold: 0.2 })
    io.observe(el)
    return () => io.disconnect()
  }, [room, layer, threads, stopped])

  useEscape(() => {
    const el = document.activeElement as HTMLElement | null
    if (el && el.classList.contains('edit')) {
      el.blur()
      return
    }
    if (picking) {
      setPicking(null)
      setEmoji(null)
      return
    }
    if (amenuOpen) {
      setAmenuOpen(false)
      return
    }
    if (armed) {
      setArmed(null)
      return
    }
    if (layer !== 'thread') {
      setLayer('thread')
      cue('toggle')
      return
    }
    setHintOpen(false)
  })
  useDocumentEvent('click', (e) => {
    const t = e.target as HTMLElement | null
    if (!t?.closest('.agent-chip') && !t?.closest('.amenu')) setAmenuOpen(false)
    if (!t?.closest('.rtier') && !t?.closest('.rsearch')) {
      setPicking(null)
      setEmoji(null)
    }
  })

  const stamp = (id: string, section: string) => {
    setSaved((s) => ({ ...s, [`${id}:${section}`]: now() }))
    cue('press')
  }
  const patch = (id: string, section: string, fn: (c: Config) => Config) => {
    setConfigs((cs) => cs.map((c) => (c.id === id ? fn(c) : c)))
    stamp(id, section)
  }
  const push = (key: string, m: Omit<Msg, 'id' | 'at'>) => {
    msgCount.current += 1
    const id = `m-${msgCount.current}`
    setThreads((t) => ({ ...t, [key]: [...(t[key] ?? []), { ...m, id, at: now() }] }))
    return id
  }
  /* a reply in a thread: the chain under its trunk message. `also send to
     the room` lands it on the trunk too, as a reply to that message */
  const pushReply = (key: string, trunkId: string, m: Omit<Msg, 'id' | 'at'>, also = false) => {
    msgCount.current += 1
    const id = `m-${msgCount.current}`
    const at = now()
    setThreads((t) => ({ ...t, [key]: (t[key] ?? []).map((x) => (x.id === trunkId ? { ...x, replies: [...(x.replies ?? []), { ...m, id, at }] } : x)) }))
    if (also) push(key, { ...m, replyTo: { id: trunkId } })
    return id
  }
  /* any message in the room, trunk or thread, by id */
  const findMsg = (id: string): Msg | null => {
    for (const m of threads[room] ?? []) {
      if (m.id === id) return m
      const r = m.replies?.find((x) => x.id === id)
      if (r) return r
    }
    return null
  }
  /* a strip is a door: the room travels to the message, which lights up */
  const goTo = (id: string) => {
    const el = roomRef.current?.querySelector<HTMLElement>(`[data-id="${id}"]`)
    el?.scrollIntoView({ block: 'center', behavior: 'smooth' })
    setLit(id)
    setTimeout(() => setLit((l) => (l === id ? null : l)), 1400)
    cue('press')
  }
  /* a reaction toggles: yours joins the glyph's pill or leaves it */
  const toggleReact = (id: string, glyph: string) => {
    const flip = (m: Msg): Msg => {
      if (m.id !== id) return m
      const list = (m.reacts ?? []).map((r) => ({ ...r, by: [...r.by] }))
      const hit = list.find((r) => r.glyph === glyph)
      if (!hit) list.push({ glyph, by: ['o'] })
      else if (hit.by.includes('o')) hit.by = hit.by.filter((w) => w !== 'o')
      else hit.by.push('o')
      return { ...m, reacts: list.filter((r) => r.by.length) }
    }
    setThreads((t) => ({ ...t, [room]: (t[room] ?? []).map((m) => ({ ...flip(m), replies: m.replies?.map(flip) })) }))
    setPicking(null)
    setEmoji(null)
    cue('press')
  }

  /* ── the composer: a message into the room; the fixture answers ── */
  const send = () => {
    const text = draft.trim()
    if (!text) return
    const key = room
    const rt = quoting ?? undefined
    setDraft('')
    setQuoting(null)
    cue('press')
    if (current && !current.fixture) {
      /* the new agent's conversation: the first sentence is the brief */
      push(key, { who: 'o', text, replyTo: rt })
      if (!prop) {
        const p = propose(text, configs.map((c) => c.name))
        setProp(p)
        setTimeout(() => {
          push(key, { who: 'antevon', text: stepIntro('identity', p), card: { kind: 'propose', id: `${key}-identity`, step: 'identity', title: 'name and role' } })
        }, 700)
      } else {
        setTimeout(() => push(key, { who: 'antevon', text: 'Noted. Confirm or change the card above and we go on.' }), 700)
      }
      return
    }
    if (isHouse) {
      /* @name addresses one agent; otherwise the house mind routes */
      const m = /^@(eiri|tory|antevon)\b\s*/i.exec(text)
      const to = m ? (m[1].toLowerCase() as AgentKey) : addr === 'all' ? null : addr
      push(key, { who: 'o', text, replyTo: rt })
      setTimeout(() => {
        if (to) {
          push(key, { who: to, text: REPLY[to] })
        } else {
          push(key, { who: 'antevon', text: 'I will route it. Eiri takes the words, Tory the filings.' })
          setTimeout(() => push(key, { who: 'antevon', handoff: { to: 'eiri', what: text.length > 48 ? text.slice(0, 45) + '…' : text } }), 400)
        }
      }, 800)
      return
    }
    const agent = key as AgentKey
    push(key, { who: 'o', text, replyTo: rt })
    setTimeout(() => push(key, { who: agent, text: REPLY[agent] ?? 'Noted.' }), 800)
  }

  /* the thread's composer: the reply joins the chain; the fixture answers there */
  const sendThread = () => {
    const text = tdraft.trim()
    const trunkId = openThread
    if (!text || !trunkId) return
    const rt = tquoting ?? undefined
    setTdraft('')
    setTquoting(null)
    cue('press')
    pushReply(room, trunkId, { who: 'o', text, replyTo: rt }, alsoRoom)
    const root = findMsg(trunkId)
    const to: AgentKey = root && root.who !== 'o' ? root.who : 'antevon'
    setTimeout(() => pushReply(room, trunkId, { who: to, text: REPLY[to] ?? 'Noted.' }), 800)
  }
  /* quote = the words you picked inside one message (OF-248 at the span
     grain): the pointer carries the message and the span */
  const selMsg = sel ? selWithin(sel.range, '.rtext')?.closest<HTMLElement>('.rmsg') ?? null : null
  const quoteSel = (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    const id = selMsg?.dataset.id
    if (!sel || !id) return
    const span = sel.text.trim()
    if (selMsg?.closest('.tpane')) {
      setTquoting({ id, span })
      setTimeout(() => tinputRef.current?.focus(), 0)
    } else {
      setQuoting({ id, span })
      setTimeout(() => inputRef.current?.focus(), 0)
    }
    clearSel()
    cue('press')
  }

  /* ── gates settle in place; the inbox row settles with them (one fact) ── */
  const settleGate = (id: string, ok: boolean, word: string) => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setGates((g) => ({ ...g, [id]: { ok, word, when: now() } }))
    cue(ok ? 'success' : 'press')
  }

  /* ── proposals: confirm patches the config and asks for the next piece ── */
  const confirmStep = (c: Config, step: Step) => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    if (!prop) return
    const when = now()
    const day = today()
    if (step === 'identity') {
      patch(c.id, 'identity', (x) => ({ ...x, name: prop.name, role: prop.role }))
    } else if (step === 'channels') {
      patch(c.id, 'channels', (x) => ({ ...x, channels: prop.channels }))
    } else if (step === 'grants') {
      patch(c.id, 'scopes', (x) => ({
        ...x,
        grants: prop.verbs.map((v) => ({ v, tip: VERB_TIPS[v] ?? v, by: 'o' as const, byTip: 'granted by Owen · confirmed in the room', when: day, whenTip: `granted ${day} · in the room · under your seal` })),
      }))
    } else {
      patch(c.id, 'schedule', (x) => ({ ...x, schedule: prop.schedule, cap: x.cap ?? '¥300' }))
    }
    setDone((d) => ({ ...d, [`${c.id}-${step}`]: when }))
    const next = STEP_AFTER[step]
    setTimeout(() => {
      if (next === 'done') {
        push(c.id, { who: 'antevon', text: `${prop.name} is set up and wakes ${prop.schedule === 'on ask' ? 'when asked' : prop.schedule}. Say something to it here, or open its setup.` })
      } else {
        push(c.id, { who: 'antevon', text: stepIntro(next, prop), card: { kind: 'propose', id: `${c.id}-${next}`, step: next, title: next } })
      }
    }, 600)
  }
  const openSetupFrom = (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setLayer('setup')
    cue('toggle')
  }

  const pause = (id: string) => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setPaused((p) => ({ ...p, [id]: now() }))
    cue('press')
  }
  const resume = (id: string) => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setPaused((p) => {
      const next = { ...p }
      delete next[id]
      return next
    })
    cue('press')
  }
  const stop = (key: RunKey) => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setStopped((s) => ({ ...s, [key]: true }))
    cue('press')
  }

  /* what the roster derives from the live runs */
  const runOf = (id: string) => RUNS.find((r) => r.agent === id)
  const isLive = (id: string) => {
    const r = runOf(id)
    return !!r && !stopped[r.agent]
  }
  const rowLine = (c: Config) => {
    if (!c.fixture) return { word: c.name ? 'draft · not yet running' : 'a new agent', tip: 'not yet running · confirm the pieces in the room' }
    if (paused[c.id]) return { word: `paused ${paused[c.id]}`, tip: 'nothing new starts · the live run finishes' }
    const r = runOf(c.id)
    if (r && !stopped[r.agent]) return { word: r.doing.charAt(0).toLowerCase() + r.doing.slice(1), tip: `live now · ${r.tip}` }
    return { word: c.schedule ?? '', tip: c.fixture.scheduleTip }
  }

  /* the ledger sorts on its heads: asc → desc → off, the given order last */
  const cycleSort = (id: HistColId) => {
    setSort((x) => (!x || x.id !== id ? { id, dir: 'asc' } : x.dir === 'asc' ? { id, dir: 'desc' } : null))
    cue('toggle')
  }
  const histRows = React.useMemo(() => {
    const scoped = isHouse ? HISTORY : HISTORY.filter((h) => h.by === room)
    const col = sort ? HIST_COLS.find((c) => c.id === sort.id) : null
    if (!sort || !col?.accessor) return scoped
    const get = col.accessor
    const dir = sort.dir === 'asc' ? 1 : -1
    return [...scoped].sort((a, b) => {
      const x = get(a)
      const y = get(b)
      return (typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y))) * dir
    })
  }, [sort, room, isHouse])
  const runRows = isHouse ? RUNS : RUNS.filter((r) => r.agent === room)
  const liveCount = runRows.filter((r) => !stopped[r.agent]).length
  const needsCount = runRows.filter((r) => !stopped[r.agent] && r.needs).length
  const writes = histRows.reduce((n, h) => n + h.writes, 0)
  const waited = histRows.reduce((n, h) => n + h.waited, 0)

  /* ↑↓ walk the roster; enter opens the room */
  const rowKey = (e: React.KeyboardEvent, keys: string[], i: number) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault()
      const next = keys[i + (e.key === 'ArrowDown' ? 1 : -1)]
      if (next) rowRefs.current[next]?.focus()
    }
  }

  const Saved = ({ id, k }: { id: string; k: string }) => {
    const t = saved[`${id}:${k}`]
    return t ? (
      <span className="meta-line saved" title="settled in place · nothing to confirm">
        saved · {t}
      </span>
    ) : null
  }

  /* ── the message ── */
  /* who-marks (owner 09-08): your turns never carry a name; position or type
     carries your voice (html[data-voice]). In a one-to-one room the agent is
     named in the head, so no row is labelled. In the house each change of
     speaker opens with the face + the name in ink, once; following turns by
     the same voice fold under it. */
  const renderMsg = (m: Msg, c: Config | null, head: boolean, house: boolean, where: 'trunk' | 'root' | 'thread' = 'trunk') => {
    const mine = m.who === 'o'
    const who = house && !mine ? configs.find((x) => x.id === m.who) : null
    /* the verbs: reply on every message, thread only on a group's trunk */
    const acts = !m.live && where !== 'root' && (house || !!c?.fixture)
    const replyTo = (e: React.MouseEvent) => {
      markCued(e)
      if (where === 'thread') {
        setTquoting({ id: m.id })
        tinputRef.current?.focus()
      } else {
        setQuoting({ id: m.id })
        inputRef.current?.focus()
      }
      cue('press')
    }
    const openThreadOn = (e: React.MouseEvent) => {
      markCued(e)
      setOpenThread(m.id)
      cue('toggle')
    }
    const n = m.replies?.length ?? 0
    return (
      <div key={m.id} data-id={m.id} className={['rmsg', mine ? 'mine' : '', m.live ? 'live' : '', house && head ? 'head' : '', lit === m.id ? 'lit' : '', picking === m.id ? 'picking' : ''].filter(Boolean).join(' ')}>
        {house ? (
          <span className="rwho">
            {head && mine ? (
              <>
                <span className="rme" title="you">
                  you
                </span>
                <span className="rat" title={`${m.at} · today`}>
                  {m.at}
                </span>
              </>
            ) : head ? (
              <>
                <Face c={who?.creature ?? 'none'} size={20} alt={who?.fixture?.creature.alt} />
                <span className="aname" data-agent={m.who} title={NAMES[m.who as AgentKey]}>
                  {NAMES[m.who as AgentKey]}
                </span>
                <span className="rat" title={`${m.at} · today`}>
                  {m.at}
                </span>
              </>
            ) : null}
          </span>
        ) : null}
        <span className="rbody">
          {m.handoff ? (
            <span className="rhand" title="a handoff · the run tree carries it">
              <span className="arrow" aria-hidden="true">
                →
              </span>
              <span className="aname" data-agent={m.handoff.to}>
                {NAMES[m.handoff.to]}
              </span>
              <span>{m.handoff.what}</span>
            </span>
          ) : null}
          {m.replyTo ? renderStrip(m.replyTo) : null}
          {m.text ? <span className="rtext">{m.text}</span> : null}
          {m.card ? renderCard(m.card, c) : null}
          {m.reacts?.length ? (
            <span className="rreacts">
              {m.reacts.map((r) => (
                <button
                  key={r.glyph}
                  type="button"
                  className={r.by.includes('o') ? 'rpill mine' : 'rpill'}
                  title={r.by.map((w) => (w === 'o' ? 'you' : NAMES[w])).join(', ')}
                  aria-pressed={r.by.includes('o')}
                  onClick={(e) => { markCued(e); toggleReact(m.id, r.glyph) }}
                >
                  <span className="g">{r.glyph}</span>
                  <span className="n">{r.by.length}</span>
                </button>
              ))}
            </span>
          ) : null}
          {where === 'trunk' && n ? (
            <button type="button" className="door rthread" title="the thread under this message · open it beside the room" onClick={openThreadOn}>
              {n} {n === 1 ? 'reply' : 'replies'} · {m.replies![n - 1].at}
            </button>
          ) : null}
        </span>
        <span className="rtier">
          <span className="rat" title={`${m.at} · today`}>
            {m.at}
          </span>
          {acts ? (
            <span className="racts">
              {picking === m.id ? (
                <span className="rpick" role="group" aria-label="react">
                  {GLYPHS.map((g) => (
                    <button key={g} type="button" title={g} onClick={(e) => { markCued(e); toggleReact(m.id, g) }}>
                      {g}
                    </button>
                  ))}
                  <button
                    type="button"
                    className="plus"
                    title="more · search every emoji by name"
                    aria-label="search emoji"
                    onClick={(e) => {
                      markCued(e)
                      const r = (e.currentTarget.closest('.rtier') as HTMLElement | null)?.getBoundingClientRect()
                      if (!r) return
                      const up = r.bottom + 240 > innerHeight
                      setEmoji({ q: '', x: r.right, y: up ? r.top - 6 : r.bottom + 6, up })
                      setTimeout(() => emojiRef.current?.focus(), 0)
                      cue('toggle')
                    }}
                  >
                    +
                  </button>
                </span>
              ) : null}
              <button type="button" className="gact" title="react · a glyph on this message" aria-label="react" aria-expanded={picking === m.id} onClick={(e) => { markCued(e); setPicking((p) => (p === m.id ? null : m.id)); cue('toggle') }}>
                <IconReact />
              </button>
              <button type="button" className="gact" title="reply · the pointer carries this message" aria-label="reply" onClick={replyTo}>
                <IconReply />
              </button>
              {where === 'trunk' && canThread ? (
                <button type="button" className="gact" title={n ? 'thread · open it beside the room' : 'thread · a branch under this message, the room keeps reading'} aria-label="thread" onClick={openThreadOn}>
                  <IconThread />
                </button>
              ) : null}
            </span>
          ) : null}
        </span>
      </div>
    )
  }

  /* the emoji search: a fixed card off the chip; Enter takes the first hit */
  const renderEmojiSearch = () => {
    if (!emoji || !picking) return null
    const id = picking
    const hits = searchEmoji(emoji.q)
    return createPortal(
      <span
        className={emoji.up ? 'rsearch up' : 'rsearch'}
        role="dialog"
        aria-label="search emoji"
        style={emoji.up ? { left: emoji.x, bottom: innerHeight - emoji.y } : { left: emoji.x, top: emoji.y }}
      >
        <input
          ref={emojiRef}
          className="rs-in"
          type="text"
          placeholder="search emoji"
          aria-label="search emoji"
          value={emoji.q}
          onChange={(e) => setEmoji((x) => (x ? { ...x, q: e.target.value } : x))}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && hits[0]) toggleReact(id, hits[0][0])
          }}
        />
        <span className="rs-grid">
          {hits.map(([g, name]) => (
            <button key={g} type="button" title={name} onClick={(e) => { markCued(e); toggleReact(id, g) }}>
              {g}
            </button>
          ))}
          {hits.length === 0 ? <span className="rs-none">nothing by that name</span> : null}
        </span>
      </span>,
      document.body,
    )
  }

  /* the strip: whose words the message answers, and which. a door: the click
     travels to them. in the composer the same strip is droppable. */
  const renderStrip = (rt: { id: string; span?: string }, onDrop?: () => void) => {
    const src = findMsg(rt.id)
    if (!src) return null
    const by = src.who === 'o' ? null : src.who
    const line = rt.span ?? src.text ?? src.card?.title ?? (src.handoff ? `→ ${NAMES[src.handoff.to]} · ${src.handoff.what}` : '')
    const excerpt = line.length > 96 ? line.slice(0, 93) + '…' : line
    return (
      <span className={onDrop ? 'rquote pending' : 'rquote'}>
        <button type="button" className="rq-go" title={rt.span ? 'the words this answers · go to them' : 'the message this answers · go to it'} onClick={(e) => { markCued(e); goTo(rt.id) }}>
          {by ? (
            <span className="aname rq-who" data-agent={by}>
              {NAMES[by]}
            </span>
          ) : (
            <span className="rq-who">you</span>
          )}
          <span className="rq-text">{rt.span ? `“${excerpt}”` : excerpt}</span>
        </button>
        {onDrop ? (
          <button type="button" className="rq-x" title="drop the pointer" aria-label="drop the pointer" onClick={(e) => { markCued(e); onDrop(); cue('toggle') }}>
            ×
          </button>
        ) : null}
      </span>
    )
  }

  /* ── the thread: a branch under one message, in the right slot the work
     pane uses (the ladder's dock). the root reads whole at the top, the
     chain under it, its own composer at the foot. no thread inside a thread. ── */
  const renderThread = () => {
    const root = openThread ? findMsg(openThread) : null
    if (!root) return null
    const replies = root.replies ?? []
    return (
      <aside className="rpane tpane" aria-label="thread">
        <div className="rp-head">
          <span className="meta-line" title="a branch under one message · the room keeps reading">
            thread · {replies.length ? `${replies.length} ${replies.length === 1 ? 'reply' : 'replies'}` : 'no replies yet'}
          </span>
          <button type="button" className="act" title="close the thread" onClick={(e) => { markCued(e); setOpenThread(null); cue('toggle') }}>
            close
          </button>
        </div>
        <div className="tp-body">
          {renderMsg(root, current, true, true, 'root')}
          <span className="tp-rule" aria-hidden="true" />
          {replies.map((m, i) => renderMsg(m, current, i === 0 || replies[i - 1].who !== m.who, true, 'thread'))}
        </div>
        <div className="tp-foot">
          {tquoting ? renderStrip(tquoting, () => setTquoting(null)) : null}
          <input
            ref={tinputRef}
            className="gask-input"
            type="text"
            placeholder="reply in thread"
            aria-label="reply in thread"
            value={tdraft}
            onChange={(e) => setTdraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') sendThread()
            }}
          />
          <label className="tp-also" title="the reply lands on the room too, as a reply to this message">
            <input type="checkbox" checked={alsoRoom} onChange={(e) => setAlsoRoom(e.target.checked)} />
            also send to {isHouse ? 'the house' : 'the room'}
          </label>
        </div>
      </aside>
    )
  }

  /* ── the cards: a door to the world · a gate (the inbox's own verbs) ·
     a proposal (confirm or change) ── */
  const renderCard = (card: Card, c: Config | null) => {
    if (card.kind === 'door') {
      return (
        <div className="cwidget">
          <span className="cw-title">{card.title}</span>
          <span className="cw-line">{card.line}</span>
          <span className="cw-foot">
            {card.doors.map((d) => (
              <DoorAct key={d.label} door={d} />
            ))}
          </span>
        </div>
      )
    }
    if (card.kind === 'gate') {
      const g = gates[card.id]
      return (
        <div className={g ? 'cwidget gate settled' : 'cwidget gate'} aria-live="polite">
          <span className="cw-title">{card.title}</span>
          <span className="cw-why">{card.why}</span>
          {g ? (
            <span className="cw-foot">
              <span className="meta-line" title="the same gate as the inbox row · it settled there too">
                {g.word} · {g.when} · settled in your inbox too
              </span>
            </span>
          ) : (
            <>
              <span className="cw-meta" title="the narrowest standing rule the click would mint · it lands on the grants ledger with a receipt">
                {card.remembers}
              </span>
              <span className="cw-foot">
                <a className="act" href="#" title="this one send only · it asks again next time" onClick={settleGate(card.id, true, 'allowed once')}>
                  allow once
                </a>
                <a className="act" href="#" title="mints a scoped, budgeted, revocable grant · a row lands on the grants ledger" onClick={settleGate(card.id, true, 'granted')}>
                  allow + grant
                </a>
                <a className="act" href="#" onClick={settleGate(card.id, false, 'denied')}>
                  deny
                </a>
                <Link className="act" to="/app/inbox" title="the same ask, in the inbox">
                  in the inbox
                </Link>
              </span>
            </>
          )}
        </div>
      )
    }
    /* a proposal for the new agent */
    if (!c || !prop) return null
    const settled = done[`${c.id}-${card.step}`]
    const foot = settled ? (
      <span className="cw-foot">
        <span className="meta-line" title="settled into its setup">
          confirmed · {settled}
        </span>
        <a className="act" href="#" title="its setup, one layer down" onClick={openSetupFrom}>
          setup
        </a>
      </span>
    ) : (
      <span className="cw-foot">
        <a className="act" href="#" title="settles into its setup" onClick={confirmStep(c, card.step)}>
          confirm
        </a>
        <a className="act" href="#" title="open its setup and change it by hand" onClick={openSetupFrom}>
          change by hand
        </a>
      </span>
    )
    if (card.step === 'identity') {
      return (
        <div className={settled ? 'cwidget propose settled' : 'cwidget propose'}>
          <span className="cw-name">
            {settled ? c.name : <Editable as="span" value={prop.name} placeholder="a name" onCommit={(v) => setProp((p) => (p ? { ...p, name: v || p.name } : p))} title="the name · click to change" />}
          </span>
          <span className="cw-line">
            {settled ? c.role : <Editable as="span" value={prop.role} placeholder="what it is for, in one line" onCommit={(v) => setProp((p) => (p ? { ...p, role: v || p.role } : p))} title="the role line · click to change" />}
          </span>
          {foot}
        </div>
      )
    }
    if (card.step === 'channels') {
      return (
        <div className={settled ? 'cwidget propose settled' : 'cwidget propose'}>
          <span className="cw-title">channels it may use</span>
          <span className="cw-vals">
            {CHANNELS.map((ch) => {
              const on = prop.channels.includes(ch.id)
              return (
                <button
                  key={ch.id}
                  type="button"
                  className={on ? 'chan on' : 'chan'}
                  aria-pressed={on}
                  disabled={!!settled}
                  title={ch.tip}
                  onClick={(e) => {
                    markCued(e)
                    setProp((p) => (p ? { ...p, channels: on ? p.channels.filter((k) => k !== ch.id) : [...p.channels, ch.id] } : p))
                    cue('toggle')
                  }}
                >
                  <span className="chan-glyph">
                    <ch.Glyph />
                  </span>
                  <span className="chan-name">{ch.label}</span>
                </button>
              )
            })}
          </span>
          {foot}
        </div>
      )
    }
    if (card.step === 'grants') {
      return (
        <div className={settled ? 'cwidget propose settled' : 'cwidget propose'}>
          <span className="cw-title">the grants it would hold</span>
          <span className="cw-vals">
            {prop.verbs.map((v) => (
              <span key={v} className="rung on" title={VERB_TIPS[v]}>
                {v}
              </span>
            ))}
            <span className="rung" title="send is never proposed · you grant it yourself, one click per send">
              send · yours to grant
            </span>
          </span>
          <span className="cw-meta">each lands on the grants ledger under your seal, with a receipt</span>
          {foot}
        </div>
      )
    }
    return (
      <div className={settled ? 'cwidget propose settled' : 'cwidget propose'}>
        <span className="cw-title">when it wakes</span>
        <span className="cw-vals">
          {SCHEDULES.map((s) => (
            <button
              key={s.id}
              type="button"
              className={prop.schedule === s.id ? 'rung on' : 'rung'}
              aria-pressed={prop.schedule === s.id}
              disabled={!!settled}
              title={s.tip}
              onClick={(e) => {
                markCued(e)
                setProp((p) => (p ? { ...p, schedule: s.id } : p))
                cue('toggle')
              }}
            >
              {s.id}
            </button>
          ))}
        </span>
        {foot}
      </div>
    )
  }

  /* ── the setup layer: the sheet body, one click down ── */
  const renderSetup = (c: Config) => {
    const isDraft = !c.fixture
    return (
      <section className="setup" aria-label={`${c.name || 'new agent'} · setup`}>
        {isDraft ? (
          <div className="sec" aria-label="creature">
            <span className="label">creature</span>
            <div className="picker">
              {CREATURES.map((cr) => (
                <button
                  key={cr.id}
                  type="button"
                  className={c.creature === cr.id ? 'pick on' : 'pick'}
                  aria-pressed={c.creature === cr.id}
                  title={cr.tip}
                  onClick={(e) => {
                    markCued(e)
                    patch(c.id, 'creature', (x) => ({ ...x, creature: cr.id }))
                  }}
                >
                  {cr.id === 'none' ? <span className="pick-none">none</span> : <Face c={cr.id} size={32} />}
                </button>
              ))}
            </div>
            <Saved id={c.id} k="creature" />
          </div>
        ) : null}

        <div className="sec" aria-label="what it does">
          <span className="label">what it does</span>
          <Editable as="p" className="detail" value={c.detail} placeholder="Say what it does. Short sentences. One idea each." onCommit={(v) => patch(c.id, 'detail', (x) => ({ ...x, detail: v }))} />
          <Saved id={c.id} k="detail" />
        </div>

        <div className="sec" aria-label="channels">
          <span className="label">channels it may use</span>
          <div className="chans">
            {CHANNELS.map((ch) => {
              const on = c.channels.includes(ch.id)
              return (
                <button
                  key={ch.id}
                  type="button"
                  className={on ? 'chan on' : 'chan'}
                  aria-pressed={on}
                  title={`${ch.tip} · ${on ? 'on · click to turn off' : 'off · click to turn on'}`}
                  onClick={(e) => {
                    markCued(e)
                    patch(c.id, 'channels', (x) => ({ ...x, channels: on ? x.channels.filter((k) => k !== ch.id) : [...x.channels, ch.id] }))
                  }}
                >
                  <span className="chan-glyph">
                    <ch.Glyph />
                  </span>
                  <span className="chan-name">{ch.label}</span>
                </button>
              )
            })}
            <Link className="act chan-door" to="/settings/connectors" title="connect a workspace, or revoke one">
              connect
            </Link>
          </div>
          <Saved id={c.id} k="channels" />
        </div>

        <div className="sec" aria-label="scopes">
          <span className="label">scopes · the grants it holds</span>
          {c.grants.length === 0 ? (
            <p className="empty">
              No grants yet.{' '}
              <Link className="act" to="/settings/grants" title="grants are given in settings">
                give one
              </Link>
            </p>
          ) : (
            <div className="grants">
              {c.grants.map((g) => {
                const armKey = `${c.id}:${g.v}`
                const isArmed = armed === armKey
                return (
                  <div key={g.v} className={g.revoked ? 'grant revoked' : 'grant'}>
                    <span className="g-scope" title={g.tip}>
                      {g.v}
                    </span>
                    <span className="g-what">{g.tip.split(' · ')[0]}</span>
                    <span className="seal seal-human" title={g.byTip}>
                      {g.by}
                    </span>
                    <span className="g-when" title={g.whenTip}>
                      {g.when}
                    </span>
                    {g.revoked ? (
                      <span className="g-acts">
                        <span className="meta-line" title="the grant is gone · the agent lost this verb">
                          revoked · {g.revoked}
                        </span>
                        <button
                          type="button"
                          className="act"
                          title="give the grant back"
                          onClick={(e) => {
                            markCued(e)
                            patch(c.id, 'scopes', (x) => ({ ...x, grants: x.grants.map((h) => (h.v === g.v ? { ...h, revoked: undefined } : h)) }))
                          }}
                        >
                          restore
                        </button>
                      </span>
                    ) : (
                      <span className="g-acts">
                        <button
                          type="button"
                          className={isArmed ? 'act revoke armed' : 'act revoke'}
                          title={isArmed ? 'click again to revoke · esc keeps it' : 'revoke this grant · asks once'}
                          onClick={(e) => {
                            markCued(e)
                            if (!isArmed) {
                              setArmed(armKey)
                              cue('toggle')
                              return
                            }
                            setArmed(null)
                            patch(c.id, 'scopes', (x) => ({ ...x, grants: x.grants.map((h) => (h.v === g.v ? { ...h, revoked: now() } : h)) }))
                          }}
                          onBlur={() => {
                            if (isArmed) setArmed(null)
                          }}
                        >
                          {isArmed ? 'revoke?' : 'revoke'}
                        </button>
                      </span>
                    )}
                  </div>
                )
              })}
            </div>
          )}
          <Saved id={c.id} k="scopes" />
        </div>

        <div className="sec" aria-label="schedule">
          <span className="label">schedule</span>
          <div className="ladder">
            {SCHEDULES.map((s) => (
              <button
                key={s.id}
                type="button"
                className={c.schedule === s.id ? 'rung on' : 'rung'}
                aria-pressed={c.schedule === s.id}
                title={s.tip}
                onClick={(e) => {
                  markCued(e)
                  patch(c.id, 'schedule', (x) => ({ ...x, schedule: s.id }))
                }}
              >
                {s.id}
              </button>
            ))}
          </div>
          <Saved id={c.id} k="schedule" />
        </div>

        <div className="sec" aria-label="budget">
          <span className="label">budget · a day</span>
          {c.fixture && !c.fixture.budgetLadder ? (
            <div className="ladder">
              <span className="rung local" title={c.fixture.budgetTip}>
                local · no cap
              </span>
            </div>
          ) : (
            <div className="ladder">
              {(c.fixture?.budgetLadder ?? ['¥300', '¥600', '¥1,200']).map((b) => (
                <button
                  key={b}
                  type="button"
                  className={c.cap === b ? 'rung on' : 'rung'}
                  aria-pressed={c.cap === b}
                  title={`${b} a day · the cap pauses the agent, it never bills past it`}
                  onClick={(e) => {
                    markCued(e)
                    patch(c.id, 'budget', (x) => ({ ...x, cap: b }))
                  }}
                >
                  {b}
                </button>
              ))}
              {c.fixture ? (
                <span className="spent" title={c.fixture.budgetTip}>
                  {c.fixture.budget.split(' of ')[0]} today
                </span>
              ) : null}
            </div>
          )}
          <Saved id={c.id} k="budget" />
        </div>

        <div className="sec" aria-label="voice">
          <span className="label">voice</span>
          <Editable as="p" className="voice" value={c.voice} placeholder="How it speaks. Register, length, language." onCommit={(v) => patch(c.id, 'voice', (x) => ({ ...x, voice: v }))} />
          <Saved id={c.id} k="voice" />
        </div>

        {c.fixture ? (
          <div className="sec" aria-label="recent">
            <span className="label">recent</span>
            <div className="rd-tail">
              {c.fixture.tail.map((t) => (
                <div key={t.when + t.what} className="tl">
                  <span className="when">{t.when}</span>
                  <span className="what">{t.what}</span>
                  <DoorAct door={t.door} />
                </div>
              ))}
            </div>
          </div>
        ) : null}
      </section>
    )
  }

  /* ── the runs layer: now · earlier today, scoped to the room ── */
  /* ── the live run, in the thread (owner 09-08: not a pane, not a fold —
     the work prints where it was asked for). One card per live run at the
     foot of the thread: what it is doing, its helpers, the one red dot on
     what needs you, stop at rest; steering is replying. In the house the
     card wears its agent's mark like any other turn. The thread itself is
     the record of what ran earlier. ── */
  const renderLive = () => {
    const live = runRows.filter((r) => !stopped[r.agent])
    return live.map((r, i) => {
      const who = isHouse ? configs.find((x) => x.id === r.agent) : null
      return (
        <div key={r.agent} className="rmsg rlive-row" ref={i === 0 ? liveRef : undefined}>
          {isHouse ? (
            <span className="rwho">
              <Face c={who?.creature ?? 'none'} size={20} alt={who?.fixture?.creature.alt} />
              <span className="aname" data-agent={r.agent}>
                {NAMES[r.agent]}
              </span>
            </span>
          ) : null}
          <span className="rbody">
            <div className="cwidget rlive" data-agent={r.agent}>
              <span className="cw-title" title={r.tip}>
                {r.doing}
              </span>
              <span className="cw-meta">
                running · {r.elapsed} · {r.helpers.length} helpers
              </span>
              <div className="rlive-tree">
                {r.helpers.map((h) => (
                  <div key={h.what} className={h.needs ? 'rp-helper needs' : 'rp-helper'}>
                    <span className="rp-hwhat">{h.what}</span>
                    <span className="rp-hstate">{h.state}</span>
                  </div>
                ))}
              </div>
              <span className="cw-foot">
                <button type="button" className="act" title="verb: stop_run · at the next breakpoint · what landed stays" onClick={stop(r.agent)}>
                  stop
                </button>
                <span className="meta-line" title="say it below · the run hears it at its next breakpoint">
                  reply to steer
                </span>
              </span>
            </div>
          </span>
          <span className="rat" aria-hidden="true" />
        </div>
      )
    })
  }

  /* ── the work pane (owner 09-08): closed = one mono mark at the room's
     top-right corner, in the air (the Codex floatie); open = a well column
     docked at the room's right edge (the vault's inspector rule: a tinted
     zone divides). The run's tree, the one red dot on what needs you, stop
     at rest; steering is replying below. Only under html[data-work-axis="pane"];
     the thread's live card and the agent bar stand down there. ── */
  const renderPane = () => {
    const live = runRows.filter((r) => !stopped[r.agent])
    const one = !isHouse && live.length === 1 ? live[0] : null
    const head = one ? `working · ${one.elapsed}` : `${liveCount} running`
    const words = `${head}${needsCount ? ' · needs you' : ''}`
    return (
      <aside className={pane ? 'rpane open' : 'rpane'} aria-label="work">
        {pane ? (
          <>
            <div className="rp-head">
              <span className="meta-line" title="this room's live work">
                {words}
              </span>
              <button type="button" className="act" title="close the pane" onClick={(e) => { markCued(e); setPane(false); cue('toggle') }}>
                close
              </button>
            </div>
            <div className="rp-body">
              <span className="label">work</span>
              {live.length === 0 ? <p className="ag-none">Nothing runs right now.</p> : null}
              {live.map((r) => (
                <div key={r.agent} className="rp-run" data-agent={r.agent}>
                  {isHouse ? (
                    <span className="aname rp-gname" data-agent={r.agent}>
                      {NAMES[r.agent]}
                    </span>
                  ) : null}
                  <span className="rp-doing" title={r.tip}>
                    {r.doing}
                  </span>
                  <span className="meta-line">
                    running · {r.elapsed} · {r.helpers.length} helpers
                  </span>
                  {r.helpers.map((h) => (
                    <div key={h.what} className={h.needs ? 'rp-helper needs' : 'rp-helper'}>
                      <span className="rp-hwhat">{h.what}</span>
                      <span className="rp-hstate">{h.state}</span>
                    </div>
                  ))}
                  <span className="rp-acts">
                    <button type="button" className="act" title="verb: stop_run · at the next breakpoint · what landed stays" onClick={stop(r.agent)}>
                      stop
                    </button>
                    <button type="button" className="act" title="say it below · the run hears it at its next breakpoint" onClick={(e) => { markCued(e); inputRef.current?.focus(); cue('press') }}>
                      steer
                    </button>
                  </span>
                </div>
              ))}
              <span className="label">earlier</span>
              {histRows.slice(0, 4).map((h) => (
                <div key={h.id} className="rp-earlier" title={h.tip}>
                  <span className="rp-ewhat">{h.ran}</span>
                  <span className="rp-estate">{h.wake.replace('woke ', '')}</span>
                </div>
              ))}
            </div>
          </>
        ) : liveCount ? (
          <button type="button" className="pmark" title={`${words} · open the work pane`} onClick={(e) => { markCued(e); setPane(true); cue('toggle') }}>
            {head}
            {needsCount ? (
              <>
                {' · '}
                <i className="pm-dot" aria-hidden="true" />
                needs you
              </>
            ) : null}
            <span className="pm-chev" aria-hidden="true">
              {' ›'}
            </span>
          </button>
        ) : null}
      </aside>
    )
  }

  /* the agent bar (cross-arch-0009b): when the live card is scrolled off, a
     thin line above the composer keeps the count and jumps back to it */
  const renderBar = () => {
    if (liveSeen || !liveCount) return null
    return (
      <button
        type="button"
        className="agent-bar"
        title="the live run · back to it"
        onClick={() => {
          liveRef.current?.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
        }}
      >
        <span>
          {liveCount} running
          {needsCount ? (
            <>
              {' · '}
              <i className="pm-dot" aria-hidden="true" />
              {needsCount} needs you
            </>
          ) : null}
        </span>
        <span className="chev" aria-hidden="true">
          ↓
        </span>
      </button>
    )
  }

  /* ── the room head: portrait · name in ink · role · the layer switch ── */
  const renderHead = () => {
    if (isHouse) {
      return (
        <div className="room-head">
          <div className="rh-text">
            <h2 className="rh-name">The house</h2>
            <span className="rh-role">Everyone who works here, and you. Antevon routes what you leave unaddressed.</span>
            <div className="rh-line">
              <span className="meta-line" title="what the roster spent today · as of 14:07">
                ¥280 today · as of 14:07
              </span>
            </div>
          </div>
        </div>
      )
    }
    const c = current!
    const editing = layer === 'setup'
    return (
      <div className="room-head" data-agent={c.ink ?? undefined}>
        <div className="rh-face" title={c.fixture?.tip}>
          <Face c={c.creature} size={72} alt={c.fixture?.creature.alt} />
        </div>
        <div className="rh-text">
          <div className="rh-title">
            {editing ? (
              <Editable as="h2" className={c.ink ? 'rh-name aname' : 'rh-name'} value={c.name} placeholder="name your agent" onCommit={(v) => patch(c.id, 'identity', (x) => ({ ...x, name: v }))} />
            ) : (
              <h2 className={c.ink ? 'rh-name aname' : 'rh-name'} title={c.fixture?.tip}>
                {c.name || <span className="unnamed">a new agent</span>}
              </h2>
            )}
            <button
              type="button"
              className="rh-gear"
              aria-pressed={editing}
              aria-label="setup"
              title={editing ? 'back to the conversation' : 'how it is set up · one layer down'}
              onClick={(e) => { markCued(e); setLayer(editing ? 'thread' : 'setup'); cue('toggle') }}
            >
              <IconSettings />
            </button>
          </div>
          {editing ? (
            <Editable as="span" className="rh-role" value={c.role} placeholder="what it is for, in one line" onCommit={(v) => patch(c.id, 'identity', (x) => ({ ...x, role: v }))} />
          ) : (
            <span className="rh-role">{c.role || <span className="unnamed">Say what it should do, below.</span>}</span>
          )}
          <div className="rh-line">
            {editing ? (
              <button type="button" className="door back" title="back to the conversation" onClick={(e) => { markCued(e); setLayer('thread'); cue('toggle') }}>
                <span className="chev" aria-hidden="true">‹</span> thread
              </button>
            ) : null}
            <Saved id={c.id} k="identity" />
            {editing && c.fixture ? (
              <span className="meta-line">
                <span title={c.fixture.modelTip}>{c.fixture.model}</span>
                {' · '}
                <span title={c.fixture.lastTip}>last run {c.fixture.last}</span>
              </span>
            ) : null}
          </div>
        </div>
      </div>
    )
  }

  /* ── the composer ── */
  const renderLine = () => {
    /* while Antevon sets a new agent up, the chip stays Antevon: you answer him, not it */
    const chipName = isHouse ? (addr === 'all' ? 'everyone' : NAMES[addr]) : isNew ? 'Antevon' : current?.name || 'Antevon'
    const chipAgent = isHouse ? (addr === 'all' ? undefined : addr) : current?.fixture ? current.id : 'antevon'
    const placeholder = isNew
      ? prop
        ? 'answer Antevon · or confirm the card above'
        : 'what should it do? one sentence'
      : isHouse
        ? 'message everyone · @eiri, @tory, @antevon to address one · / for commands'
        : `message ${current?.name ?? ''} · / for commands`
    return (
      <div className="room-line">
        {isHouse ? (
          <button
            className="agent-chip switch"
            aria-expanded={amenuOpen}
            aria-haspopup="menu"
            title="who you address · click to switch"
            onClick={() => {
              setAmenuOpen((o) => !o)
              cue('toggle')
            }}
          >
            <span className="aname" data-agent={chipAgent}>
              {chipName}
            </span>
            <Chevron size={8} />
          </button>
        ) : isNew ? (
          <span className="agent-chip" title="Antevon sets it up with you">
            <span className="aname" data-agent={chipAgent}>
              {chipName}
            </span>
          </span>
        ) : null}
        <input
          ref={inputRef}
          className="gask-input"
          type="text"
          placeholder={placeholder}
          aria-label="message"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') send()
          }}
        />
        {current?.fixture && !isHouse ? (
          <span className="line-acts">
            {current.id === 'antevon' ? null : (
              <>
                {paused[current.id] ? (
                  <span className="meta-line" title="nothing new starts · the live run finishes">
                    paused {paused[current.id]}
                  </span>
                ) : null}
                <button
                  type="button"
                  className="pause-btn"
                  aria-pressed={!!paused[current.id]}
                  aria-label={paused[current.id] ? `resume ${current.name}` : `pause ${current.name}`}
                  title={paused[current.id] ? `resume ${current.name}` : `pause ${current.name} · nothing new starts, the live run finishes`}
                  onClick={paused[current.id] ? resume(current.id) : pause(current.id)}
                >
                  {paused[current.id] ? <IconPlay /> : <IconPause />}
                </button>
              </>
            )}
          </span>
        ) : null}
        {isHouse ? (
          <div className="amenu" hidden={!amenuOpen} role="menu" aria-label="address">
            <span className="label">address</span>
            {(['all', 'eiri', 'tory', 'antevon'] as const).map((k) => (
              <button
                key={k}
                className={addr === k ? 'vrow on' : 'vrow'}
                role="menuitem"
                onClick={() => {
                  setAddr(k)
                  setAmenuOpen(false)
                  inputRef.current?.focus()
                  cue('press')
                }}
              >
                {k === 'all' ? (
                  <span className="vname">everyone</span>
                ) : (
                  <span className="aname" data-agent={k}>
                    {NAMES[k]}
                  </span>
                )}
                <span className="meta-line">{k === 'all' ? 'Antevon routes' : k === 'eiri' ? 'outbound' : k === 'tory' ? 'research' : 'the house mind'}</span>
              </button>
            ))}
          </div>
        ) : null}
      </div>
    )
  }

  const rosterKeys = [...configs.map((c) => c.id), 'house']
  const thread = threads[room] ?? []

  return (
    <main className="pane" id="pane">
      <div className="pane-body">
        <div className="agents-grid">
          {/* ══ the roster ══ */}
          <nav className="roster" aria-label="roster">
            {configs.map((c, i) => {
              const line = rowLine(c)
              const live = !!c.fixture && isLive(c.id) && !paused[c.id]
              return (
                <React.Fragment key={c.id}>
                <button
                  type="button"
                  className={['rrow', room === c.id ? 'on' : '', live ? 'live' : '', c.fixture ? '' : 'draft'].filter(Boolean).join(' ')}
                  data-agent={c.ink ?? undefined}
                  aria-current={room === c.id ? 'true' : undefined}
                  ref={(el) => {
                    rowRefs.current[c.id] = el
                  }}
                  title={`${c.name || 'the new agent'} · open the room`}
                  onClick={(e) => {
                    markCued(e)
                    setRoom(c.id)
                    cue('toggle')
                  }}
                  onKeyDown={(e) => rowKey(e, rosterKeys, i)}
                >
                  <Face c={c.creature} size={30} alt={c.fixture?.creature.alt} />
                  <span className="rtext">
                    <span className={c.ink ? 'rname aname' : 'rname'}>{c.name || <span className="unnamed">unnamed</span>}</span>
                    <span className="rdoing" title={line.tip}>
                      {line.word}
                    </span>
                  </span>
                </button>
                </React.Fragment>
              )
            })}
            <span className="rsep" aria-hidden="true"></span>
            <button
              type="button"
              className={room === 'house' ? 'rrow house on' : 'rrow house'}
              aria-current={room === 'house' ? 'true' : undefined}
              ref={(el) => {
                rowRefs.current.house = el
              }}
              title="the house · every agent and you in one room"
              onClick={(e) => {
                markCued(e)
                setRoom('house')
                cue('toggle')
              }}
              onKeyDown={(e) => rowKey(e, rosterKeys, rosterKeys.length - 1)}
            >
              <span className="rtext">
                <span className="rname">The house</span>
                <span className="rdoing" title="Eiri · Tory · Antevon · you">
                  {configs.filter((c) => c.fixture).length} agents · you
                </span>
              </span>
            </button>
            <span className="rsep" aria-hidden="true"></span>
            <button type="button" className="rrow new" title="a new agent · Antevon proposes the pieces, you confirm each" onClick={openNew}>
              <span className="rtext">
                <span className="rname">+ new agent</span>
                <span className="rdoing">by conversation with Antevon</span>
              </span>
            </button>
          </nav>

          {/* ══ the room ══ */}
          <section className="room" aria-label={isHouse ? 'the house' : current?.name || 'new agent'} ref={roomRef} onMouseUp={raiseSel}>
            <div className="room-main">
            {isHouse || current ? renderHead() : null}
            {layer === 'setup' && current ? (
              renderSetup(current)
            ) : (
              <div className={room === 'house' ? 'room-thread house' : 'room-thread solo'} ref={threadRef} aria-live="polite">
                <span className="rday">today</span>
                {thread.map((m, i) => renderMsg(m, current, i === 0 || thread[i - 1].who !== m.who, room === 'house'))}
                {!isNew ? renderLive() : null}
                {isNew && !prop ? (
                  <div className="rmsg">
                    <span className="rwho"></span>
                    <span className="rbody">
                      <span className="cw-foot">
                        <a className="act" href="#" title="skip the conversation · the sheet, by hand" onClick={openSetupFrom}>
                          set up by hand
                        </a>
                      </span>
                    </span>
                  </div>
                ) : null}
              </div>
            )}
            {layer === 'thread' ? renderBar() : null}
            {layer === 'thread' && quoting ? renderStrip(quoting, () => setQuoting(null)) : null}
            {layer === 'thread' ? renderLine() : null}
            </div>
            {(isHouse || current?.fixture) && layer === 'thread' ? (openThread ? renderThread() : renderPane()) : null}
            {renderEmojiSearch()}
            {sel && selMsg ? (
              <SelTools sel={sel}>
                <a className="act" href="#" title="answer these words · the pointer carries the message and the span" onClick={quoteSel}>
                  quote
                </a>
              </SelTools>
            ) : null}
          </section>
        </div>
      </div>
    </main>
  )
}
