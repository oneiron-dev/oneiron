import * as React from 'react'
import { Link, createFileRoute } from '@tanstack/react-router'
import { ChanLine, ChanLinkedin, ChanMail, ChanSlack, Chevron } from '~/components/safelight/icons'
import { cue, markCued, useEscape } from '~/components/safelight/hooks'
import pipelineCss from '~/styles/pipeline.css?url'

export const Route = createFileRoute('/app/pipeline')({
  head: () => ({
    links: [{ rel: 'stylesheet', href: pipelineCss }],
  }),
  component: Pipeline,
})

/* ══ the CRM lens (FLOWS §3 #6) · ONE lens, TWO projections ══
   board (default): every org where it stands, one column per stage,
   sourced → deposit. a card carries the org, the money, the next step and
   who holds it; drag it, or press alt and an arrow, to move it.
   ledger: the same orgs as a work queue, stage groups of one-line rows,
   nearest to money first.
   card and row unfold IN PLACE through the same component (thread tail ·
   claims · acts); acts settle as receipt lines; no toasts, no modals. */

type Stage = 'deposit' | 'proposal' | 'audit' | 'call' | 'replied' | 'outreach' | 'qualified' | 'sourced'
type Chan = 'line' | 'mail' | 'slack' | 'linkedin'
type Human = 'o' | 'y'
type Agent = 'eiri' | 'tory' | 'antevon'

/* the funnel, in spine order (the strip) */
const STAGES: { key: Stage; name: string; n: number; tip: string }[] = [
  { key: 'sourced', name: 'sourced', n: 34, tip: 'sourced · pulled from the trade registry, untouched' },
  { key: 'qualified', name: 'qualified', n: 18, tip: 'qualified · fits the forecasting work, no contact yet' },
  { key: 'outreach', name: 'outreach', n: 11, tip: 'outreach · a touch has gone out, no reply yet' },
  { key: 'replied', name: 'replied', n: 6, tip: 'replied · they answered, the ask is not yet shaped' },
  { key: 'call', name: 'call booked', n: 3, tip: 'call booked · a time sits on both calendars' },
  { key: 'audit', name: 'audit', n: 2, tip: 'audit · the paid diagnostic, four weeks' },
  { key: 'proposal', name: 'proposal', n: 1, tip: 'proposal · scope and price, with them' },
  { key: 'deposit', name: 'deposit', n: 1, tip: 'deposit · signed and paid, the work starts' },
  /* qualified · Tory keeps these warm; the first five show, the rest wait behind `N more` */
]
const BY_STAGE = Object.fromEntries(STAGES.map((s) => [s.key, s])) as Record<Stage, (typeof STAGES)[number]>

const HUMANS: Record<Human, string> = { o: 'o · oleksii · owner', y: 'y · yurii · member' }
const AGENTS: Record<Agent, string> = { eiri: 'Eiri', tory: 'Tory', antevon: 'Antevon' }
const CHAN_TIP: Record<Chan, string> = { line: 'LINE', mail: 'email', slack: 'slack', linkedin: 'linkedin' }

type Tail = {
  by: { seal: string; name: string; contact?: boolean } | { agent: Agent }
  when: string
  chan: Chan | 'meeting'
  msg: string
  lang?: 'ja'
  state?: { text: string; pending?: boolean }
  door?: { label: string; href: string; tip: string }
  tip?: string
}
type Claim = { id: string; text: string; conf: number; dot: 'approved' | 'auto' | 'proposed' | 'rejected'; when: string; tip?: string; superseded?: boolean }
type ActKey = 'draft' | 'book' | 'org' | 'thread' | 'watch' | 'brief' | 'inboxdraft' | 'pager' | 'park' | 'merge'
type Act = ActKey | { key: ActKey; label: string }

type Org = {
  id: string
  name: string
  stage: Stage
  next: string
  who: Human | Agent /* who holds it: a human seal or an agent's name in ink */
  chan: Chan
  step: string /* next step + when, the card line: 'call · Thu 10:00' */
  money?: number /* JPY, the deal on the table (money-end stages only) */
  due?: boolean /* the next step is due today */
  waits?: string /* a draft waits in the inbox: the channel glyph carries the amber */
  last: string
  lastTip: string
  age: string
  since: string
  more?: boolean /* behind the `N more` door */
  tail: Tail[]
  claims: Claim[]
  acts: Act[]
}

const ORGS: Org[] = [
  /* deposit */
  {
    id: 'nishi', name: 'Nishi Trading', stage: 'deposit',
    step: 'kickoff · Mon 10:00', money: 4000000,
    next: 'Kickoff Monday. They still owe us two years of order history.',
    who: 'y', chan: 'mail', last: '08-12', lastTip: 'last touch · 08-12 09:20 · Sato Rie confirmed the room', age: '2d', since: '08-11',
    tail: [
      { by: { seal: 's', name: 'Sato Rie · procurement', contact: true }, when: '08-12 09:20', chan: 'mail', lang: 'ja', msg: '月曜10時、会議室Cで承知しました。データは金曜までに送ります。' },
      { by: { seal: 'y', name: 'yurii' }, when: '08-11 17:40', chan: 'mail', msg: 'Deposit received, thank you. The kickoff checklist follows.', state: { text: 'delivered · receipted' } },
    ],
    claims: [
      { id: 'cl_7a10', text: 'Kickoff is Monday 10:00, on their site', conf: 0.96, dot: 'approved', when: 'occurred 08-12', tip: 'approved by yurii' },
      { id: 'cl_7a11', text: 'Two years of order history arrive by Friday', conf: 0.88, dot: 'auto', when: 'occurred 08-12' },
    ],
    acts: ['draft', 'org', 'thread', 'watch'],
  },
  /* proposal */
  {
    id: 'sakura', name: 'Sakura Retail', stage: 'proposal',
    step: 'follow up · Mon', money: 4800000,
    next: 'The proposal has sat with their CFO since the 8th. Their ops lead is on our side.',
    who: 'o', chan: 'mail', last: '08-11', lastTip: 'last touch · 08-11 16:04 · acknowledged, nothing since', age: '5d', since: '08-08',
    tail: [
      { by: { seal: 'i', name: 'Ide Kazuo · CFO', contact: true }, when: '08-11 16:04', chan: 'mail', msg: 'Received. I will read it with the board pack next week.' },
      { by: { seal: 'o', name: 'oleksii' }, when: '08-08 11:12', chan: 'mail', msg: 'Proposal attached: eight weeks, store level, weekly re-fit.', state: { text: 'delivered · receipted' } },
    ],
    claims: [
      { id: 'cl_62c0', text: 'Their board pack is read on Mondays', conf: 0.92, dot: 'approved', when: 'occurred 08-11', tip: 'approved by oleksii' },
      { id: 'cl_62c4', text: 'May be running a second quote from a Tokyo firm', conf: 0.61, dot: 'proposed', when: 'learned 08-12', tip: 'proposed by Tory · one filing mention · waits in the inbox' },
    ],
    acts: ['draft', 'book', 'org', 'thread', 'watch'],
  },
  /* audit */
  {
    id: 'hokuei', name: 'Hokuei Foods', stage: 'audit',
    step: 'call · Thu 10:00', money: 1200000,
    next: 'Send the pilot scope before Thursday’s call. Then name the pilot.',
    who: 'y', chan: 'line', last: '08-12', lastTip: 'last touch · 08-12 21:10 · Mika confirmed the room', age: '8d', since: '08-05',
    tail: [
      { by: { seal: 'm', name: 'Mika Tanaka · procurement lead', contact: true }, when: '08-12 21:10', chan: 'line', lang: 'ja', msg: '木曜10時、会議室Bで大丈夫です。COOも顔を出します。' },
      { by: { seal: 'y', name: 'yurii' }, when: '08-11 18:02', chan: 'line', msg: 'Thursday 10:00 works. I will bring the summer numbers.', state: { text: 'verified in thread' } },
      { by: { agent: 'antevon' }, when: '08-08 15:30', chan: 'meeting', msg: 'Transcribed the pilot call. 41 minutes, nine claims.', door: { label: 'what it minted', href: '/app/vault', tip: 'the claims this call minted, in the ledger' } },
    ],
    claims: [
      { id: 'cl_31a0', text: 'The pilot runs six weeks from the first week of September', conf: 0.94, dot: 'approved', when: 'occurred 08-08', tip: 'approved by yurii' },
      { id: 'cl_2be7', text: 'Mika leads procurement and prefers LINE for quick questions', conf: 0.86, dot: 'auto', when: 'occurred 06-27' },
    ],
    acts: ['draft', 'brief', 'org', 'thread', 'watch'],
  },
  {
    id: 'aster', name: 'Aster Components', stage: 'audit',
    step: 'send the nudge · today', money: 1200000, due: true,
    next: 'Three months of order lines are still missing. The audit stalls without them.',
    who: 'o', chan: 'mail', waits: 'email · Eiri drafted the nudge at 09:12 · it waits in your inbox until you send it',
    last: '08-09', lastTip: 'last touch · 08-09 11:02 · promised the export, nothing arrived', age: '12d', since: '08-01',
    tail: [
      { by: { agent: 'eiri' }, when: 'today 09:12', chan: 'mail', msg: 'A short nudge on the export, naming the three columns we need.', state: { text: 'unsent', pending: true }, door: { label: 'read it', href: '/app/inbox', tip: 'the draft, in your inbox · the send stays your click' } },
      { by: { seal: 'u', name: 'Ueda Hiroshi · plant manager', contact: true }, when: '08-09 11:02', chan: 'mail', msg: 'Our systems team will pull the export this week.' },
    ],
    claims: [
      { id: 'cl_44f2', text: 'The audit cannot close without three months of order lines', conf: 0.91, dot: 'approved', when: 'occurred 08-01', tip: 'approved by oleksii' },
      { id: 'cl_44a9', text: 'Their systems team pulls exports on Fridays', conf: 0.79, dot: 'auto', when: 'learned 07-28', tip: '0.79 · superseded on 08-09', superseded: true },
    ],
    acts: ['inboxdraft', 'org', 'thread', 'watch'],
  },
  /* call booked */
  {
    id: 'kanto', name: 'Kanto Logistics', stage: 'call',
    step: 'one pager · Mon, call · Tue 15:00',
    next: 'Call Tuesday 15:00. She wants a one-page scope before it, not after.',
    who: 'o', chan: 'line', last: '08-13', lastTip: 'last touch · 08-13 07:55 · she moved the slot', age: '1d', since: '08-12',
    tail: [
      { by: { seal: 'h', name: 'Hoshino Mai · director', contact: true }, when: '08-13 07:55', chan: 'line', lang: 'ja', msg: '火曜15時に変更できますか。あと、進め方の紙を先にいただけますか。' },
      { by: { seal: 'o', name: 'oleksii' }, when: '08-12 19:20', chan: 'line', msg: 'Tuesday works. I will send a one-pager the day before.', state: { text: 'verified in thread' } },
    ],
    claims: [
      { id: 'cl_51d3', text: 'She reads on paper before any call', conf: 0.93, dot: 'approved', when: 'occurred 08-13', tip: 'approved by oleksii' },
      { id: 'cl_51d8', text: 'Their trucks run out of Kawasaki, three depots', conf: 0.82, dot: 'auto', when: 'occurred 08-04' },
    ],
    acts: ['pager', 'draft', 'org', 'thread', 'watch'],
  },
  {
    id: 'nordwerk', name: 'Nordwerk Instruments', stage: 'call',
    step: 'call · 08-20',
    next: 'Intro call on the 20th. They want real numbers beforehand.',
    who: 'o', chan: 'mail', last: '08-10', lastTip: 'last touch · 08-10 18:31 · accepted the invite', age: '3d', since: '08-10',
    tail: [
      { by: { seal: 'l', name: 'Lena Brandt · operations', contact: true }, when: '08-10 18:31', chan: 'mail', msg: 'The 20th works. Send anything with real numbers in it beforehand.' },
      { by: { agent: 'eiri' }, when: '08-06 10:14', chan: 'mail', tip: 'sent by oleksii’s click', msg: 'First touch: what we do, one client outcome, a question about their spares stock.', state: { text: 'delivered · receipted' } },
    ],
    claims: [
      { id: 'cl_70b1', text: 'Their spares stock is counted monthly, by hand', conf: 0.9, dot: 'approved', when: 'occurred 08-10', tip: 'approved by oleksii' },
      { id: 'cl_70b5', text: 'Decisions there need two signatures, ops and finance', conf: 0.8, dot: 'auto', when: 'learned 08-10' },
    ],
    acts: ['draft', 'org', 'thread', 'watch'],
  },
  {
    id: 'sakaide', name: 'Sakaide Chemical', stage: 'call',
    step: 'call · 08-18 13:00',
    next: 'Call on the 18th with their plant lead. Procurement is not in the room yet.',
    who: 'o', chan: 'slack', last: '08-08', lastTip: 'last touch · 08-08 13:47 · picked the slot in #ops', age: '5d', since: '08-08',
    tail: [
      { by: { seal: 'k', name: 'Kojima · plant lead', contact: true }, when: '08-08 13:47', chan: 'slack', msg: 'The 18th at 13:00 is fine. I will bring last winter’s yield sheets.' },
      { by: { agent: 'eiri' }, when: '08-05 09:30', chan: 'slack', msg: 'Offered three slots and asked who owns the yield numbers.', state: { text: 'delivered · receipted' } },
    ],
    claims: [
      { id: 'cl_8e02', text: 'Their winter yield sheets exist on paper, back to 2019', conf: 0.85, dot: 'auto', when: 'occurred 08-08' },
      { id: 'cl_8e07', text: 'Procurement may sit in the Osaka office, not at the plant', conf: 0.57, dot: 'proposed', when: 'learned 08-07', tip: 'proposed by Tory · one mention · waits in the inbox' },
    ],
    acts: ['draft', 'org', 'thread', 'watch'],
  },
  /* replied */
  {
    id: 'meiji', name: 'Meiji Bakeries', stage: 'replied',
    step: 'send the range · Fri',
    next: 'Asked what a pilot costs. Give the range, then find out who signs.',
    who: 'o', chan: 'line', last: '08-12', lastTip: 'last touch · 08-12 12:40 · asked for a rough range', age: '1d', since: '08-12',
    tail: [
      { by: { seal: 'k', name: 'Kubo Aya · store operations', contact: true }, when: '08-12 12:40', chan: 'line', lang: 'ja', msg: 'ざっくりで構いません。パイロットはいくらくらいですか。' },
      { by: { agent: 'eiri' }, when: '08-11 10:05', chan: 'line', msg: 'Asked whether waste or stockouts hurt more in their stores.', state: { text: 'delivered · receipted' } },
    ],
    claims: [
      { id: 'cl_9c31', text: 'Waste hurts them more than stockouts, in their own words', conf: 0.83, dot: 'auto', when: 'occurred 08-12' },
      { id: 'cl_9c38', text: 'Fourteen stores, maybe sixteen after autumn', conf: 0.34, dot: 'proposed', when: 'learned 08-10', tip: 'proposed by Tory · below the evidence floor' },
    ],
    acts: ['draft', 'book', 'org', 'thread', 'watch'],
  },
  {
    id: 'ohta', name: 'Ohta Metals', stage: 'replied',
    step: 'ask Hokuei · Fri',
    next: 'Their COO wants a reference call first. Ask Hokuei if Mika would take one.',
    who: 'y', chan: 'mail', last: '08-11', lastTip: 'last touch · 08-11 09:48 · asked for a reference', age: '2d', since: '08-11',
    tail: [
      { by: { seal: 'h', name: 'Hara Daisuke · COO', contact: true }, when: '08-11 09:48', chan: 'mail', msg: 'Before we go further, could we speak to a client of yours?' },
      { by: { seal: 'y', name: 'yurii' }, when: '08-07 14:20', chan: 'mail', msg: 'Sharing what the summer forecast pilot returned for a food client.', state: { text: 'delivered · receipted' } },
    ],
    claims: [
      { id: 'cl_a1e0', text: 'They want a reference before a call', conf: 0.9, dot: 'approved', when: 'occurred 08-11', tip: 'approved by yurii' },
      { id: 'cl_a1e6', text: 'Runs three plants in Aichi, one on night shifts', conf: 0.74, dot: 'auto', when: 'learned 08-02' },
    ],
    acts: ['draft', 'book', 'org', 'thread', 'watch'],
  },
  {
    id: 'tokiwa', name: 'Tokiwa Frozen', stage: 'replied',
    step: 'answer · Fri',
    next: 'They answered with two questions about data. Answer both, then offer a call.',
    who: 'o', chan: 'mail', last: '08-09', lastTip: 'last touch · 08-09 16:12 · two questions about data', age: '4d', since: '08-09',
    tail: [
      { by: { seal: 'e', name: 'Endo · planning', contact: true }, when: '08-09 16:12', chan: 'mail', msg: 'What data do you need from us, and how far back?' },
      { by: { agent: 'eiri' }, when: '08-06 09:00', chan: 'mail', msg: 'First touch: seasonal waste in frozen lines, one question.', state: { text: 'delivered · receipted' } },
    ],
    claims: [
      { id: 'cl_b2c1', text: 'Their POS history goes back to 2021', conf: 0.78, dot: 'auto', when: 'learned 08-09' },
      { id: 'cl_b2c9', text: 'Planning sits with the plant, not head office', conf: 0.55, dot: 'proposed', when: 'learned 08-09', tip: 'proposed by Tory · waits in the inbox' },
    ],
    acts: ['draft', 'book', 'org', 'thread', 'watch'],
  },
  {
    id: 'rikuzen', name: 'Rikuzen Beverage', stage: 'replied',
    step: 'merge · Fri',
    next: 'They answered a thread from March. Merge it, then answer what they asked.',
    who: 'o', chan: 'mail', last: '08-05', lastTip: 'last touch · 08-05 15:22 · replied under the March subject line', age: '8d', since: '08-05',
    tail: [
      { by: { seal: 's', name: 'Sasaki · planning', contact: true }, when: '08-05 15:22', chan: 'mail', tip: 'landed under a March subject line · two threads, one org', msg: 'Is this forecasting thing something we could try on one prefecture?' },
      { by: { seal: 'o', name: 'oleksii' }, when: '03-19 10:00', chan: 'mail', msg: 'The original intro, from the spring list.' },
    ],
    claims: [
      { id: 'cl_c3d0', text: 'Sasaki runs planning for the northern prefectures', conf: 0.84, dot: 'auto', when: 'learned 08-05', tip: '0.84 · occurred 03-19, learned 08-05 when the mail archive arrived' },
      { id: 'cl_c3d4', text: 'These two threads are one conversation', conf: 0.55, dot: 'proposed', when: 'learned 08-05', tip: 'proposed by Antevon · same sender, same domain, two subject lines' },
    ],
    acts: ['merge', 'draft', 'org', 'thread'],
  },
  {
    id: 'aoba', name: 'Aoba Dairy', stage: 'replied', more: true,
    step: 'write again · Oct',
    next: 'A friendly no until October. Nothing to do before then.',
    who: 'y', chan: 'mail', last: '07-30', lastTip: 'last touch · 07-30 11:15 · a friendly no until October', age: '14d', since: '07-30',
    tail: [
      { by: { seal: 'n', name: 'Nakamura · director', contact: true }, when: '07-30 11:15', chan: 'mail', msg: 'Not before October, our season is on. Please write again then.' },
    ],
    claims: [
      { id: 'cl_d4a1', text: 'Their season runs to the end of September', conf: 0.9, dot: 'approved', when: 'occurred 07-30', tip: 'approved by yurii' },
    ],
    acts: ['org', 'thread', 'watch'],
  },
  {
    id: 'kaga', name: 'Kaga Ceramics', stage: 'replied', more: true,
    step: 'nudge · Fri',
    next: 'Answered, then went quiet. One nudge, then leave it.',
    who: 'o', chan: 'linkedin', last: '08-02', lastTip: 'last touch · 08-02 08:40 · answered, then quiet', age: '11d', since: '08-02',
    tail: [
      { by: { seal: 'f', name: 'Fujii · sales planning', contact: true }, when: '08-02 08:40', chan: 'linkedin', msg: 'Interesting. Let me check with our plant.' },
    ],
    claims: [
      { id: 'cl_e5b2', text: 'Planning decisions sit with the plant, not sales', conf: 0.66, dot: 'auto', when: 'learned 08-02' },
    ],
    acts: ['draft', 'org', 'thread', 'watch'],
  },
  /* outreach */
  {
    id: 'fuji', name: 'Fuji Kitchens', stage: 'outreach',
    step: 'second touch · 08-18',
    next: 'First touch went out Monday. Wait a week before the second.',
    who: 'o', chan: 'mail', last: '08-11', lastTip: 'last touch · 08-11 08:30 · first touch, no reply', age: '2d', since: '08-11',
    tail: [
      { by: { agent: 'eiri' }, when: '08-11 08:30', chan: 'mail', tip: 'sent by oleksii’s click', msg: 'First touch: seasonal demand for their store kitchens, one question.', state: { text: 'delivered · no reply' } },
      { by: { agent: 'tory' }, when: '08-05 22:10', chan: 'linkedin', tip: 'research · read-only scope', msg: 'Their planning lead is listed publicly. Reachable by name.' },
    ],
    claims: [
      { id: 'cl_f6c0', text: 'Their planning lead is Morita, reachable by name', conf: 0.72, dot: 'auto', when: 'learned 08-05' },
      { id: 'cl_f6c3', text: 'Runs forty kitchens across Kanto', conf: 0.66, dot: 'auto', when: 'learned 08-05' },
    ],
    acts: ['draft', 'org', 'thread', 'watch'],
  },
  {
    id: 'yamashina', name: 'Yamashina Precision', stage: 'outreach',
    step: 'second touch · today', due: true,
    next: 'Second touch is due. The first went to a shared inbox, which rarely works.',
    who: 'o', chan: 'mail', last: '08-04', lastTip: 'last touch · 08-04 08:30 · first touch, no reply', age: '9d', since: '08-04',
    tail: [
      { by: { agent: 'eiri' }, when: '08-04 08:30', chan: 'mail', tip: 'sent by oleksii’s click', msg: 'First touch to their shared inbox, asking who owns production planning.', state: { text: 'delivered · no reply' } },
      { by: { agent: 'tory' }, when: '07-30 21:00', chan: 'linkedin', tip: 'research · read-only scope', msg: 'Two plant managers are listed publicly. Neither is reachable by name.' },
    ],
    claims: [
      { id: 'cl_0a71', text: 'Their only public address is a shared inbox', conf: 0.62, dot: 'auto', when: 'learned 08-04' },
      { id: 'cl_0a75', text: 'May have opened a second line in Kurashiki', conf: 0.31, dot: 'proposed', when: 'learned 08-02', tip: 'proposed by Tory · below the evidence floor' },
    ],
    acts: [{ key: 'draft', label: 'draft the second touch' }, 'org', 'thread', 'watch'],
  },
  {
    id: 'bergstrom', name: 'Bergstrom Nutrition', stage: 'outreach',
    step: 'last touch · Fri',
    next: 'Two touches, no answer. One more, then park it.',
    who: 'y', chan: 'linkedin', last: '08-06', lastTip: 'last touch · 08-06 10:12 · second touch, no reply', age: '20d', since: '07-24',
    tail: [
      { by: { agent: 'eiri' }, when: '08-06 10:12', chan: 'linkedin', tip: 'sent through yurii’s account, his click', msg: 'Second touch: one sentence, one question, nothing attached.', state: { text: 'delivered · no reply' } },
      { by: { agent: 'eiri' }, when: '07-24 09:00', chan: 'mail', tip: 'sent by yurii’s click', msg: 'First touch: seasonal demand for their sports line.', state: { text: 'delivered · no reply' } },
    ],
    claims: [
      { id: 'cl_1b80', text: 'Their planning sits with a Stockholm team, not here', conf: 0.58, dot: 'auto', when: 'learned 07-24' },
      { id: 'cl_1b84', text: 'Runs a Japanese distributor in Kobe', conf: 0.29, dot: 'rejected', when: 'learned 07-22', tip: 'rejected by oleksii 08-01 · the source was a stale directory · kept, struck' },
    ],
    acts: ['draft', 'park', 'org', 'thread', 'watch'],
  },
  ...([
    ['shinano', 'Shinano Paper', 'o', 'mail', '08-10', '3d', 'First touch out. Their planning office answers in September.'],
    ['tosa', 'Tosa Marine', 'y', 'linkedin', '08-09', '4d', 'First touch out, no reply yet.'],
    ['hida', 'Hida Furniture', 'o', 'mail', '08-08', '5d', 'First touch out. Their busy season ends this month.'],
    ['izumo', 'Izumo Steel', 'o', 'mail', '08-07', '6d', 'First touch bounced. Find a second address.'],
    ['awaji', 'Awaji Farms', 'y', 'line', '08-06', '7d', 'First touch out on LINE, read, no reply.'],
    ['ise', 'Ise Confectionery', 'o', 'mail', '08-05', '8d', 'First touch out, no reply yet.'],
    ['kiso', 'Kiso Timber', 'o', 'linkedin', '08-03', '10d', 'First touch out, no reply yet.'],
    ['chiba', 'Chiba Cold Storage', 'y', 'mail', '08-01', '12d', 'Two touches, no reply. Park it after one more.'],
  ] as [string, string, Human, Chan, string, string, string][]).map(([id, name, who, chan, last, age, next]): Org => ({
    id, name, stage: 'outreach', more: true, next, who, chan, last, age, since: last, step: 'second touch · next week',
    lastTip: `last touch · ${last} · first touch, no reply`,
    tail: [
      { by: { agent: 'eiri' }, when: `${last} 09:00`, chan, tip: `sent by ${who === 'o' ? 'oleksii' : 'yurii'}’s click`, msg: 'First touch: what we do, one client outcome, one question.', state: { text: 'delivered · no reply' } },
    ],
    claims: [
      { id: `cl_${id.slice(0, 2)}90`, text: 'Fits the forecasting work by size and season', conf: 0.7, dot: 'auto', when: 'learned 07-28' },
    ],
    acts: ['draft', 'org', 'thread', 'watch'],
  })),
  ...([
    ['asahi', 'Asahi Cold Chain', 'mail', '08-12'],
    ['chiyoda', 'Chiyoda Foods', 'mail', '08-12'],
    ['enshu', 'Enshu Textiles', 'linkedin', '08-11'],
    ['harima', 'Harima Bearings', 'mail', '08-11'],
    ['hyogo', 'Hyogo Bakeries', 'line', '08-10'],
    ['iga', 'Iga Ceramics', 'mail', '08-10'],
    ['kansai', 'Kansai Kitchens', 'mail', '08-09'],
    ['kishu', 'Kishu Timber', 'mail', '08-09'],
    ['kofu', 'Kofu Jewelry', 'linkedin', '08-08'],
    ['matsue', 'Matsue Foods', 'mail', '08-08'],
    ['mikawa', 'Mikawa Poultry', 'mail', '08-07'],
    ['nikko', 'Nikko Dairy', 'line', '08-07'],
    ['sanuki', 'Sanuki Udon', 'mail', '08-06'],
    ['seto', 'Seto Glass', 'mail', '08-06'],
    ['shonan', 'Shonan Coffee', 'linkedin', '08-05'],
    ['tsugaru', 'Tsugaru Apples', 'mail', '08-05'],
    ['uji', 'Uji Tea', 'mail', '08-04'],
    ['ushiku', 'Ushiku Steel', 'mail', '08-04'],
  ] as [string, string, Chan, string][]).map(([id, name, chan, last], i): Org => ({
    id, name, stage: 'qualified', more: i >= 5, who: 'tory', chan, last, age: `${13 - Number(last.slice(3))}d`, since: last,
    next: 'Fits the work. Nobody has written yet.', step: 'first touch · when Eiri has a slot',
    lastTip: `last touch · ${last} · Tory read it, nobody wrote`,
    tail: [
      { by: { agent: 'tory' }, when: `${last} 22:00`, chan: 'linkedin', tip: 'research · read-only scope', msg: 'Fits by size and season. The planning lead is not named yet.' },
    ],
    claims: [
      { id: `cl_${id.slice(0, 2)}q0`, text: 'Fits the forecasting work by size and season', conf: 0.7, dot: 'auto', when: `learned ${last}` },
    ],
    acts: ['draft', 'org', 'watch'],
  })),
  /* sourced · straight from the trade registry, read by nobody yet */
  ...([
    ['akita', 'Akita Rice'], ['biwa', 'Biwa Textiles'], ['chugoku', 'Chugoku Glass'], ['daisen', 'Daisen Poultry'],
    ['ehime', 'Ehime Citrus'], ['fukui', 'Fukui Eyewear'], ['gifu', 'Gifu Cutlery'], ['hakone', 'Hakone Springs'],
    ['iwate', 'Iwate Ironworks'], ['joetsu', 'Joetsu Cables'], ['kagawa', 'Kagawa Noodles'], ['kobe', 'Kobe Leather'],
    ['kumano', 'Kumano Timber'], ['kyushu', 'Kyushu Ceramics'], ['miyagi', 'Miyagi Seafood'], ['nagano', 'Nagano Orchards'],
    ['nara', 'Nara Ink'], ['niigata', 'Niigata Sake'], ['noto', 'Noto Salt'], ['oita', 'Oita Springs'],
    ['okayama', 'Okayama Denim'], ['osaka', 'Osaka Fasteners'], ['saga', 'Saga Porcelain'], ['sanin', 'Sanin Fisheries'],
    ['sendai', 'Sendai Packaging'], ['shizuoka', 'Shizuoka Tea'], ['tochigi', 'Tochigi Berries'], ['tottori', 'Tottori Pears'],
    ['toyama', 'Toyama Pharma'], ['wakayama', 'Wakayama Plums'], ['yamagata', 'Yamagata Cherries'], ['yamaguchi', 'Yamaguchi Motors'],
    ['yonago', 'Yonago Optics'], ['yokkaichi', 'Yokkaichi Chemicals'],
  ] as [string, string][]).map(([id, name], i): Org => ({
    id, name, stage: 'sourced', more: i >= 5, who: 'antevon', chan: 'mail', last: '08-03', age: '10d', since: '08-03',
    next: 'Pulled from the registry. Nobody has read it yet.', step: 'read · Tory, weekly',
    lastTip: 'last touch · 08-03 · the registry pull, untouched',
    tail: [
      { by: { agent: 'antevon' }, when: '08-03 06:00', chan: 'mail', tip: 'the weekly registry pull', msg: 'Pulled from the trade registry, one line each. Tory reads the list on Sundays.' },
    ],
    claims: [
      { id: `cl_${id.slice(0, 2)}s0`, text: 'Listed in the trade registry, size in range', conf: 0.5, dot: 'auto', when: 'learned 08-03' },
    ],
    acts: ['org', 'watch'],
  })),
]

/* the board runs the funnel left→right, sourced … deposit, so it reads as a flow;
   the ledger runs money first (the work queue) */
const BOARD_ORDER: Stage[] = ['sourced', 'qualified', 'outreach', 'replied', 'call', 'audit', 'proposal', 'deposit']
const LEDGER_ORDER: Stage[] = ['deposit', 'proposal', 'audit', 'call', 'replied', 'outreach', 'qualified', 'sourced']

/* ── the receipts an act settles into (serif, name in ink) ── */
type Receipt = { key: ActKey; node: React.ReactNode }
const NONE: ActKey[] = []

function confClass(c: number) {
  return c >= 0.9 ? 'conf-1' : c >= 0.7 ? 'conf-2' : c >= 0.4 ? 'conf-3' : 'conf-4'
}
function isHuman(w: Human | Agent): w is Human {
  return w === 'o' || w === 'y'
}
/* money as data: ¥4.8M · ¥900k (mono, tnum) */
function fmtMoney(n: number): string {
  if (n >= 1_000_000) return `¥${(n / 1_000_000).toFixed(1).replace(/\.0$/, '')}M`
  return `¥${Math.round(n / 1000)}k`
}
function actKey(a: Act): ActKey {
  return typeof a === 'string' ? a : a.key
}
function actLabel(a: Act): string {
  if (typeof a !== 'string') return a.label
  switch (a) {
    case 'draft': return 'draft the follow-up'
    case 'book': return 'book the call'
    case 'org': return 'open the org'
    case 'thread': return 'the thread'
    case 'watch': return 'watch this org'
    case 'brief': return 'open the brief'
    case 'inboxdraft': return 'open the draft'
    case 'pager': return 'prepare the one pager'
    case 'park': return 'park it'
    case 'merge': return 'merge the threads'
  }
}
function actTip(a: ActKey): string {
  switch (a) {
    case 'draft': return 'verb: draft_message · Eiri writes it in the house voice, you send it'
    case 'book': return 'verb: book_call · Eiri offers three slots from your calendar, you send it'
    case 'org': return 'the full dossier: claims, thread, commitments, people'
    case 'thread': return 'the whole thread, entry by entry'
    case 'watch': return 'verb: save_query · a saved query, quiet until something moves'
    case 'brief': return 'the meeting brief for Thursday 10:00 · every sentence cites its claims'
    case 'inboxdraft': return 'the draft-to-send, in your inbox · the send stays your click'
    case 'pager': return 'verb: prepare_brief · Antevon writes it from the org’s claims, you read it first'
    case 'park': return 'verb: park_org · it leaves the board; the record keeps every touch'
    case 'merge': return 'verb: merge_threads · one org, one thread; the receipt keeps both origins'
  }
}
function receiptFor(key: ActKey): React.ReactNode {
  switch (key) {
    case 'draft':
      return (<><span className="aname" data-agent="eiri" title="Eiri · outbound · every send waits for your click">Eiri</span> is drafting · lands in your inbox</>)
    case 'book':
      return (<><span className="aname" data-agent="eiri" title="Eiri · outbound · every send waits for your click">Eiri</span> offers three slots · lands in your inbox</>)
    case 'pager':
      return (<><span className="aname" data-agent="antevon" title="Antevon · the house mind">Antevon</span> is writing the one pager · lands in your inbox</>)
    case 'watch':
      return <>watching · changes land in your inbox digest</>
    case 'park':
      return <>parked · off the board, the record stays whole</>
    case 'merge':
      return <>merged · one thread, both origins kept</>
    default:
      return null
  }
}

function ChanGlyph({ chan }: { chan: Chan | 'meeting' }) {
  if (chan === 'line') return <ChanLine />
  if (chan === 'linkedin') return <ChanLinkedin />
  if (chan === 'slack') return <ChanSlack />
  return <ChanMail />
}

/* who holds it: a human seal, or the agent's name in its ink (the name IS the mark) */
function Holder({ who }: { who: Human | Agent }) {
  if (isHuman(who)) {
    return (
      <span className="seal seal-human" title={`${HUMANS[who]} · owns this one`}>
        {who}
      </span>
    )
  }
  return (
    <span className="aname" data-agent={who} title={`${AGENTS[who]} holds it`}>
      {AGENTS[who]}
    </span>
  )
}

/* ── the unfold: thread tail · claims · acts · receipts. ONE component,
   used under a ledger row and inside a board card alike (one place per
   fact). what settled lives with the page (a filter may unmount the row;
   the receipt must survive it) ── */
function OrgDetail({
  org,
  settled,
  onSettle,
}: {
  org: Org
  settled: ActKey[]
  onSettle: (key: ActKey) => void
}) {
  const done = React.useMemo(() => new Set(settled), [settled])
  const receipts: Receipt[] = settled.map((key) => ({ key, node: receiptFor(key) }))
  const settle = (key: ActKey) => (e: React.MouseEvent) => {
    markCued(e)
    onSettle(key)
    cue(key === 'park' ? 'press' : 'success')
  }
  return (
    <div className="rd-inner">
      <div className="rd-cols">
        <div className="rd-col">
          {org.tail.map((t, i) => {
            /* time · channel · send state ride the tooltip (rule 14);
               only a waiting draft shows its state, with its door */
            const where = t.chan === 'meeting' ? 'meeting' : CHAN_TIP[t.chan]
            const tip = [t.when, where, t.state && !t.state.pending ? t.state.text : null, t.tip]
              .filter(Boolean)
              .join(' · ')
            const foot = (t.state && t.state.pending) || t.door
            return (
              <div className="tl" key={i}>
                {'agent' in t.by ? (
                  <span className="aname" data-agent={t.by.agent} title={`${AGENTS[t.by.agent]} · ${tip}`}>
                    {AGENTS[t.by.agent]}
                  </span>
                ) : (
                  <span
                    className={t.by.contact ? 'seal seal-human seal-class' : 'seal seal-human'}
                    title={`${t.by.seal} · ${t.by.name} · ${tip}`}
                  >
                    {t.by.seal}
                  </span>
                )}
                <span className="tl-body">
                  <span className="tl-msg" lang={t.lang}>
                    {t.msg}
                  </span>
                  {foot && (
                    <span className="tl-foot">
                      {t.state && t.state.pending && (
                        <span className="send-state send-pending" title={t.when}>
                          {t.state.text}
                        </span>
                      )}
                      {t.door && (
                        <Link className="act" to={t.door.href} title={t.door.tip}>
                          {t.door.label}
                        </Link>
                      )}
                    </span>
                  )}
                </span>
              </div>
            )
          })}
        </div>
        <div className="rd-col">
          {org.claims.map((c) => (
            <Link
              className="cl"
              to="/app/vault"
              key={c.id}
              title={`${c.id} · ${c.conf.toFixed(2)}${c.tip ? ` · ${c.tip}` : ''} · open the claim`}
            >
              <span className={`dot dot-${c.dot}`}></span>
              <span className={`claim ${confClass(c.conf)}${c.superseded ? ' superseded' : ''}${c.dot === 'rejected' ? ' retracted' : ''}`}>
                {c.text}
              </span>
              <span className="meta-line">{c.when}</span>
            </Link>
          ))}
        </div>
      </div>
      <div className="rd-acts">
        {org.acts.map((a) => {
          const key = actKey(a)
          if (done.has(key)) return null
          const label = actLabel(a)
          const tip = actTip(key)
          switch (key) {
            case 'org':
              return (
                <Link className="act" to="/app/orgs" key={key} title={tip}>
                  {label}
                </Link>
              )
            case 'thread':
              return (
                <Link className="act" to="/app/threads" key={key} title={tip}>
                  {label}
                </Link>
              )
            case 'brief':
              return (
                <Link className="act" to="/app/briefs" key={key} title={tip}>
                  {label}
                </Link>
              )
            case 'inboxdraft':
              return (
                <Link className="act" to="/app/inbox" key={key} title={tip}>
                  {label}
                </Link>
              )
            default:
              return (
                <button type="button" className="act" key={key} title={tip} onClick={settle(key)}>
                  {label}
                </button>
              )
          }
        })}
      </div>
      {receipts.length > 0 && (
        <div className="receipts">
          {receipts.map((r) => (
            <span className="receipt" key={r.key}>
              {r.node}
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

/* ↑/↓ walk the rows or the cards of one column; the handle keeps the focus */
function walk(e: React.KeyboardEvent<HTMLElement>, scope: string, handle: string) {
  if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return false
  e.preventDefault()
  const list = Array.from(e.currentTarget.closest(scope)?.querySelectorAll<HTMLElement>(handle) ?? [])
  const next = list[list.indexOf(e.currentTarget) + (e.key === 'ArrowDown' ? 1 : -1)]
  if (next) {
    next.focus()
    cue('toggle')
  }
  return true
}

/* ── one ledger row: the line, then the unfold under it ── */
function OrgRow({
  org,
  open,
  sel,
  moved,
  settled,
  onSettle,
  onToggle,
  onUndo,
}: {
  org: Org
  open: boolean
  sel: boolean
  moved: Moved | null
  settled: ActKey[]
  onSettle: (key: ActKey) => void
  onToggle: () => void
  onUndo: (e: React.MouseEvent) => void
}) {
  const done = new Set(settled)
  const drafted = done.has('draft') || done.has('book') || done.has('pager')
  const parked = done.has('park')
  const chanWaits = org.waits ?? (drafted ? `${CHAN_TIP[org.chan]} · Eiri’s draft waits in your inbox` : null)

  return (
    <div
      className={['orow', open ? 'open' : '', sel ? 'sel' : '', parked ? 'parked' : ''].filter(Boolean).join(' ')}
      id={`org-${org.id}`}
    >
      <button
        type="button"
        className="r-line"
        aria-expanded={open}
        aria-controls={`fold-${org.id}`}
        onClick={onToggle}
        onKeyDown={(e) => walk(e, '.stack', '.r-line')}
        title={open ? 'close' : 'open the row · thread tail, claims, next steps'}
      >
        <span className="r-org">{org.name}</span>
        <span className="r-next" title={org.next}>
          {org.next}
        </span>
        {org.money !== undefined && (
          <span className="r-money" title="the deal on the table">
            {fmtMoney(org.money)}
          </span>
        )}
        <span className="r-who">
          <Holder who={org.who} />
        </span>
        <span className={chanWaits ? 'r-chan waits' : 'r-chan'} title={chanWaits ?? `last spoke by ${CHAN_TIP[org.chan]}`}>
          <ChanGlyph chan={org.chan} />
        </span>
        <span className="r-when" title={org.lastTip}>
          {org.last}
        </span>
        <span className="r-age" title={`in ${BY_STAGE[org.stage].name} since ${org.since}`}>
          {org.age}
        </span>
      </button>
      <div className="r-detail" id={`fold-${org.id}`}>
        <div className="rd-clip" inert={!open}>
          <OrgDetail org={org} settled={settled} onSettle={onSettle} />
        </div>
      </div>
      {moved && <MovedLine moved={moved} onUndo={onUndo} className="r-moved" />}
    </div>
  )
}

/* the settle line a move lands: where it went, and the way back */
function MovedLine({ moved, onUndo, className }: { moved: Moved; onUndo: (e: React.MouseEvent) => void; className: string }) {
  return (
    <div className={className}>
      <span>moved to {BY_STAGE[moved.to].name}</span>
      <button type="button" className="act" title={`back to ${BY_STAGE[moved.from].name}`} onClick={onUndo}>
        undo
      </button>
    </div>
  )
}

/* ── a stage group in the ledger: serif head (count only when collapsed), rows, `N more` ── */
function StageGroup({
  stage,
  orgs,
  openId,
  selId,
  settled,
  moves,
  onSettle,
  onToggle,
  onUndo,
  forceMore,
}: {
  stage: Stage
  orgs: Org[]
  openId: string | null
  selId: string | null
  settled: Record<string, ActKey[]>
  moves: Record<string, Moved>
  onSettle: (id: string, key: ActKey) => void
  onToggle: (id: string) => void
  onUndo: (id: string) => (e: React.MouseEvent) => void
  forceMore: boolean
}) {
  const [closed, setClosed] = React.useState(false)
  const [more, setMore] = React.useState(false)
  const s = BY_STAGE[stage]
  const hidden = orgs.filter((o) => o.more)
  const showMore = more || forceMore || hidden.some((o) => o.id === openId)
  const shown = showMore ? orgs : orgs.filter((o) => !o.more)

  return (
    <section className={closed ? 'sgroup closed' : 'sgroup'} aria-label={s.name}>
      <button
        type="button"
        className="head"
        aria-expanded={!closed}
        onClick={() => {
          setClosed((c) => !c)
          cue('toggle')
        }}
      >
        <span className="title" title={s.tip}>
          {s.name}
        </span>
        <span className="fold-hint" aria-hidden="true">
          <Chevron />
        </span>
        <span className="meta-line">{orgs.length === 1 ? '1 org' : `${orgs.length} orgs`}</span>
      </button>
      <div className="rows">
        {shown.map((o) => (
          <OrgRow
            key={o.id}
            org={o}
            open={openId === o.id}
            sel={selId === o.id}
            moved={moves[o.id] ?? null}
            settled={settled[o.id] ?? NONE}
            onSettle={(k) => onSettle(o.id, k)}
            onToggle={() => onToggle(o.id)}
            onUndo={onUndo(o.id)}
          />
        ))}
      </div>
      {hidden.length > 0 && !showMore && (
        <div className="more-row">
          <button
            type="button"
            className="act"
            title={`the rest of ${s.name}, oldest last · opens here`}
            onClick={(e) => {
              markCued(e)
              setMore(true)
              cue('toggle')
            }}
          >
            {hidden.length} more
          </button>
        </div>
      )}
    </section>
  )
}

/* ══ the board ══ */

/* a card in flight: which org, where the pointer is, how wide the card was */
type Drag = { id: string; x: number; y: number; w: number; dx: number; dy: number; over: Stage | null; live: boolean }
type Moved = { from: Stage; to: Stage }

/* the card: name · money · next step + when · holder; last touch is the hover
   title. click = select + unfold in place. the head is the drag handle. */
function Card({
  org,
  open,
  sel,
  parked,
  moved,
  dragging,
  settled,
  onSettle,
  onToggle,
  onUndo,
  onPointerDown,
  onKeyDown,
}: {
  org: Org
  open: boolean
  sel: boolean
  parked: boolean
  moved: Moved | null
  dragging: boolean
  settled: ActKey[]
  onSettle: (key: ActKey) => void
  onToggle: () => void
  onUndo: (e: React.MouseEvent) => void
  onPointerDown: (e: React.PointerEvent<HTMLElement>) => void
  onKeyDown: (e: React.KeyboardEvent<HTMLElement>) => void
}) {
  return (
    <article
      className={['card', open ? 'open' : '', sel ? 'sel' : '', parked ? 'parked' : '', dragging ? 'dragging' : ''].filter(Boolean).join(' ')}
      id={`card-${org.id}`}
    >
      <button
        type="button"
        className="c-head"
        aria-expanded={open}
        aria-controls={`cfold-${org.id}`}
        title={`${org.lastTip} · in ${BY_STAGE[org.stage].name} since ${org.since} · drag to move, or alt and an arrow key`}
        onClick={onToggle}
        onPointerDown={onPointerDown}
        onKeyDown={onKeyDown}
      >
        <span className="c-top">
          <span className="c-org">{org.name}</span>
          {org.money !== undefined && <span className="c-money">{fmtMoney(org.money)}</span>}
        </span>
        <span className="c-step" title={org.next}>
          {org.step}
        </span>
        <span className="c-holder">
          <Holder who={org.who} />
          {org.waits && (
            <span className="c-waits" title={org.waits}>
              <ChanGlyph chan={org.chan} />
            </span>
          )}
        </span>
      </button>
      <div className="c-fold" id={`cfold-${org.id}`}>
        <div className="rd-clip" inert={!open}>
          <OrgDetail org={org} settled={settled} onSettle={onSettle} />
        </div>
      </div>
      {moved && <MovedLine moved={moved} onUndo={onUndo} className="c-moved" />}
    </article>
  )
}

type Proj = 'board' | 'ledger'
type Filter = Stage | 'today' | null

function Pipeline() {
  const [proj, setProjState] = React.useState<Proj>('board')
  const [filter, setFilter] = React.useState<Filter>(null)
  const [openId, setOpenId] = React.useState<string | null>(null)
  const [selId, setSelId] = React.useState<string | null>(null)
  const [hintOpen, setHintOpen] = React.useState(false)
  const [q, setQ] = React.useState('')
  const [moreCols, setMoreCols] = React.useState<Partial<Record<Stage, boolean>>>({})
  /* what settled, per org: the receipts outlive any filter or projection flip */
  const [settled, setSettled] = React.useState<Record<string, ActKey[]>>({})
  /* where a card was dragged to, per org; the settle line under it carries `undo` */
  const [moves, setMoves] = React.useState<Record<string, Moved>>({})
  const [drag, setDrag] = React.useState<Drag | null>(null)
  const dragRef = React.useRef<Drag | null>(null)
  const clickBlock = React.useRef(false)
  const boardRef = React.useRef<HTMLDivElement>(null)
  const ghostRef = React.useRef<HTMLDivElement>(null)
  const edgeRef = React.useRef(0)
  const rafRef = React.useRef(0)

  const onSettle = (id: string, key: ActKey) =>
    setSettled((s) => {
      const cur = s[id] ?? []
      return cur.includes(key) ? s : { ...s, [id]: [...cur, key] }
    })
  const isParked = (id: string) => (settled[id] ?? []).includes('park')

  /* the projection persists (the same lens, remembered); the board is the default */
  React.useEffect(() => {
    try {
      const v = localStorage.getItem('oneiron-pipeline-view')
      if (v === 'ledger') setProjState('ledger')
    } catch {
      /* private mode · the board it is */
    }
  }, [])
  const setProj = (p: Proj) => {
    setProjState(p)
    try {
      localStorage.setItem('oneiron-pipeline-view', p)
    } catch {
      /* private mode */
    }
    cue('toggle')
  }

  /* the orgs as they stand now: a moved card lives in its new stage, and it
     stays in sight there — it never falls behind that column's `N more` */
  const orgs = React.useMemo(
    () => ORGS.map((o) => (moves[o.id] ? { ...o, stage: moves[o.id].to, more: false } : o)),
    [moves],
  )
  const query = q.trim().toLowerCase()
  const matches = (o: Org) => !query || o.name.toLowerCase().includes(query)
  const found = React.useMemo(() => orgs.filter(matches), [orgs, query])
  const byStage = (s: Stage) => found.filter((o) => o.stage === s)
  const dueToday = found.filter((o) => o.due)

  const toggleRow = (id: string) => {
    if (clickBlock.current) {
      clickBlock.current = false
      return
    }
    setOpenId((cur) => (cur === id ? null : id))
    setSelId((cur) => (cur === id && openId === id ? null : id))
    cue('toggle')
  }

  /* a strip chip filters: the ledger to that stage; the board dims the other columns */
  const pick = (f: Filter) => {
    setFilter((cur) => (cur === f ? null : f))
    cue('toggle')
  }
  React.useEffect(() => {
    if (proj !== 'board' || !filter || filter === 'today') return
    const el = boardRef.current?.querySelector<HTMLElement>(`[data-col="${filter}"]`)
    const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches
    el?.scrollIntoView({ inline: 'center', block: 'nearest', behavior: reduce ? 'auto' : 'smooth' })
  }, [filter, proj])

  /* Esc closes the last thing you opened: the drag, then the open card,
     then the search, then the stage filter */
  useEscape(() => {
    if (dragRef.current) {
      if (dragRef.current.live) clickBlock.current = true
      stopDrag()
      return
    }
    if (openId) {
      setOpenId(null)
      return
    }
    if (q) {
      setQ('')
      return
    }
    setSelId(null)
    setHintOpen(false)
    setFilter(null)
  })

  /* one move, from either hand: the drop, or alt and an arrow key. a card
     put back where it started keeps no settle line */
  const moveTo = (id: string, to: Stage, kb = false) => {
    const org = ORGS.find((o) => o.id === id)
    if (!org) return
    setMoves((m) => {
      if (to === org.stage) {
        const { [id]: _home, ...rest } = m
        return rest
      }
      return { ...m, [id]: { from: m[id]?.from ?? org.stage, to } }
    })
    setSelId(id)
    cue('success')
    if (kb) {
      requestAnimationFrame(() => {
        document.querySelector<HTMLElement>(`#card-${id} .c-head`)?.focus()
      })
    }
  }
  const undoMove = (id: string) => (e: React.MouseEvent) => {
    markCued(e)
    setMoves((m) => {
      const { [id]: _gone, ...rest } = m
      return rest
    })
    cue('press')
  }

  /* ── drag: hand-rolled pointer events. the head is the handle; six px of
     travel starts it; the ghost follows the pointer (no re-render, it moves
     by transform); the column under the pointer lights; the board scrolls
     when the hand reaches its edge; drop lands the settle line ── */
  const startDrag = (org: Org) => (e: React.PointerEvent<HTMLElement>) => {
    if (e.button !== 0 || (e.pointerType === 'mouse' && e.ctrlKey)) return
    const rect = e.currentTarget.getBoundingClientRect()
    dragRef.current = { id: org.id, x: e.clientX, y: e.clientY, w: rect.width, dx: e.clientX - rect.left, dy: e.clientY - rect.top, over: null, live: false }
    e.currentTarget.setPointerCapture(e.pointerId)
  }
  const scrollEdge = () => {
    rafRef.current = 0
    const b = boardRef.current
    if (!dragRef.current?.live || !b || !edgeRef.current) return
    b.scrollLeft += edgeRef.current
    rafRef.current = requestAnimationFrame(scrollEdge)
  }
  const onPointerMove = (e: React.PointerEvent) => {
    const d = dragRef.current
    if (!d) return
    if (!d.live) {
      if (Math.hypot(e.clientX - d.x, e.clientY - d.y) < 6) return
      d.live = true
      cue('press')
      setDrag({ ...d, x: e.clientX, y: e.clientY })
    }
    d.x = e.clientX
    d.y = e.clientY
    const g = ghostRef.current
    if (g) g.style.transform = `translate3d(${Math.round(d.x - d.dx)}px, ${Math.round(d.y - d.dy)}px, 0) rotate(-1deg)`
    /* the hand at the edge pulls the board along */
    const b = boardRef.current
    if (b) {
      const r = b.getBoundingClientRect()
      const zone = 72
      edgeRef.current =
        e.clientX < r.left + zone ? -Math.ceil((r.left + zone - e.clientX) / 5)
        : e.clientX > r.right - zone ? Math.ceil((e.clientX - (r.right - zone)) / 5)
        : 0
      if (edgeRef.current && !rafRef.current) rafRef.current = requestAnimationFrame(scrollEdge)
    }
    const col = document.elementFromPoint(e.clientX, e.clientY)?.closest<HTMLElement>('[data-col]')?.dataset.col as Stage | undefined
    if ((col ?? null) !== d.over) {
      d.over = col ?? null
      setDrag({ ...d })
    }
  }
  const stopDrag = () => {
    dragRef.current = null
    edgeRef.current = 0
    if (rafRef.current) cancelAnimationFrame(rafRef.current)
    rafRef.current = 0
    setDrag(null)
  }
  const endDrag = () => {
    const d = dragRef.current
    stopDrag()
    if (d?.live) clickBlock.current = true
    /* the click that follows the release belongs to the drag, not the card */
    if (clickBlock.current) {
      setTimeout(() => {
        clickBlock.current = false
      }, 0)
    }
    if (!d || !d.live) return
    const at = moves[d.id]?.to ?? ORGS.find((o) => o.id === d.id)?.stage
    if (!at || !d.over || d.over === at) return
    moveTo(d.id, d.over)
  }
  React.useEffect(() => () => {
    if (rafRef.current) cancelAnimationFrame(rafRef.current)
  }, [])

  /* alt and an arrow key moves the card one stage; ↑/↓ walk the column */
  const onCardKey = (org: Org) => (e: React.KeyboardEvent<HTMLElement>) => {
    if (e.altKey && (e.key === 'ArrowLeft' || e.key === 'ArrowRight')) {
      e.preventDefault()
      const i = BOARD_ORDER.indexOf(org.stage)
      const j = e.key === 'ArrowRight' ? Math.min(BOARD_ORDER.length - 1, i + 1) : Math.max(0, i - 1)
      if (j !== i) moveTo(org.id, BOARD_ORDER[j], true)
      return
    }
    walk(e, '.pc-cards', '.c-head')
  }
  const dragOrg = drag?.live ? orgs.find((o) => o.id === drag.id) : null

  const stripCount = (s: Stage) => found.filter((o) => o.stage === s).length
  const showFilterStage = (s: Stage) => !filter || filter === s || (filter === 'today' && dueToday.some((o) => o.stage === s))
  const ledgerStages = LEDGER_ORDER.filter(showFilterStage)

  return (
    <main className="pane" id="pane" onPointerMove={onPointerMove} onPointerUp={endDrag} onPointerCancel={endDrag}>
      <div className="pane-body">
        <div className="pane-head">
          <h1>Pipeline</h1>
          <span className="pane-tools">
            <input
              className="qs"
              type="search"
              value={q}
              placeholder="find an org"
              aria-label="find an org"
              title="type to filter · Esc clears"
              onChange={(e) => setQ(e.target.value)}
            />
            <span className="proj" role="group" aria-label="view">
              <button
                type="button"
                className="act"
                aria-pressed={proj === 'board'}
                title="board · every org where it stands, sourced to deposit"
                onClick={() => setProj('board')}
              >
                board
              </button>
              <span className="sep" aria-hidden="true">
                ·
              </span>
              <button
                type="button"
                className="act"
                aria-pressed={proj === 'ledger'}
                title="ledger · the work queue, stage by stage, nearest to money first"
                onClick={() => setProj('ledger')}
              >
                ledger
              </button>
            </span>
            <span className="meta-line" title="Antevon swept the pipeline at 09:41 · 76 orgs">
              Antevon · as of 09:41
            </span>
            <button
              type="button"
              className="hint-btn"
              aria-expanded={hintOpen}
              aria-controls="pipe-why"
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
        <div className="dial-why" id="pipe-why" hidden={!hintOpen}>
          <span className="why-voice">
            Every org, and where it stands. The board runs sourced to deposit. Drag a card to move it,
            click it to open it. The ledger holds the same orgs as a queue, money first.
          </span>
        </div>

        {/* the house mind's one line, name-fronted, under the head (rule 9) */}
        <div className="sec-voice">
          <span className="aname" data-agent="antevon" title="Antevon · the house mind · the 09:41 sweep">
            Antevon
          </span>
          <span>
            Six orgs moved this week. Bergstrom has not answered since the 6th. That is usually
            where you park it.
          </span>
        </div>

        {/* the strip: 8 stage chips with counts (spine order) · today · the brief door */}
        <div className="funnel" role="group" aria-label="stages">
          {STAGES.map((s, i) => (
            <React.Fragment key={s.key}>
              {i > 0 && (
                <span className="fsep" aria-hidden="true">
                  ·
                </span>
              )}
              <button
                type="button"
                className={filter === s.key ? 'schip on' : 'schip'}
                aria-pressed={filter === s.key}
                title={`${s.tip} · click: only this stage`}
                onClick={() => pick(s.key)}
              >
                <span>{s.name}</span>
                <span className="n">{stripCount(s.key)}</span>
              </button>
            </React.Fragment>
          ))}
          <span className="fgap" aria-hidden="true" />
          <button
            type="button"
            className={filter === 'today' ? 'schip today on' : 'schip today'}
            aria-pressed={filter === 'today'}
            title="the next steps due today · click: only these"
            onClick={() => pick('today')}
          >
            <span className="n">{dueToday.length}</span>
            <span>{dueToday.length === 1 ? 'next step due today' : 'next steps due today'}</span>
          </button>
          <span className="fsep" aria-hidden="true">
            ·
          </span>
          <span className="t-say">1 call booked: Hokuei, Thursday 10:00</span>
          <Link className="act" to="/app/briefs" title="the meeting brief for Thursday 10:00 · every sentence cites its claims">
            meeting brief
          </Link>
        </div>

        {found.length === 0 ? (
          <div className="ledger-empty">Nothing matches.</div>
        ) : proj === 'board' ? (
          <div
            className={drag?.live ? 'board dragging' : 'board'}
            id="board"
            role="group"
            aria-label="board"
            ref={boardRef}
          >
            {BOARD_ORDER.map((s) => {
              const all = byStage(s)
              const early = s === 'sourced' || s === 'qualified'
              const hidden = all.filter((o) => o.more)
              const unfolded = moreCols[s] || filter === s || hidden.some((o) => o.id === openId)
              const shown = unfolded ? all : all.filter((o) => !o.more)
              const money = all.reduce((n, o) => n + (o.money ?? 0), 0)
              /* a stage with nothing in it goes quiet: the filter, the search */
              const dim =
                filter === 'today' ? !all.some((o) => o.due)
                : filter ? filter !== s
                : query ? all.length === 0
                : false
              /* the column the card already sits in does not light */
              const over = drag?.live && drag.over === s && dragOrg?.stage !== s
              return (
                <section
                  className={['pcol', dim ? 'dim' : '', over ? 'over' : ''].filter(Boolean).join(' ')}
                  key={s}
                  data-col={s}
                  aria-label={BY_STAGE[s].name}
                >
                  <header className="pc-head" title={BY_STAGE[s].tip}>
                    <span className="pc-name">{BY_STAGE[s].name}</span>
                    <span className="pc-n">{all.length}</span>
                    {money > 0 && <span className="pc-money">{fmtMoney(money)}</span>}
                  </header>
                  <div className="pc-cards">
                    {shown
                      .filter((o) => filter !== 'today' || o.due)
                      .map((o) => (
                        <Card
                          key={o.id}
                          org={o}
                          open={openId === o.id}
                          sel={selId === o.id}
                          parked={isParked(o.id)}
                          moved={moves[o.id] ?? null}
                          dragging={drag?.live === true && drag.id === o.id}
                          settled={settled[o.id] ?? NONE}
                          onSettle={(k) => onSettle(o.id, k)}
                          onToggle={() => toggleRow(o.id)}
                          onUndo={undoMove(o.id)}
                          onPointerDown={startDrag(o)}
                          onKeyDown={onCardKey(o)}
                        />
                      ))}
                    {hidden.length > 0 && !unfolded && filter !== 'today' && (
                      <button
                        type="button"
                        className="act pc-more"
                        title={`the rest of ${BY_STAGE[s].name}${early ? ', oldest last' : ''} · opens here`}
                        onClick={(e) => {
                          markCued(e)
                          setMoreCols((m) => ({ ...m, [s]: true }))
                          cue('toggle')
                        }}
                      >
                        {hidden.length} more
                      </button>
                    )}
                    {all.length === 0 && !query && <span className="pc-empty">nothing here</span>}
                  </div>
                </section>
              )
            })}
          </div>
        ) : (
          <div className="stack" id="stack">
            {ledgerStages.map((s) => {
              const list = byStage(s).filter((o) => filter !== 'today' || o.due)
              if (list.length === 0) return null
              return (
                <StageGroup
                  key={s}
                  stage={s}
                  orgs={list}
                  openId={openId}
                  selId={selId}
                  settled={settled}
                  moves={moves}
                  onSettle={onSettle}
                  onToggle={toggleRow}
                  onUndo={undoMove}
                  forceMore={filter === s}
                />
              )
            })}
            {ledgerStages.every((s) => byStage(s).filter((o) => filter !== 'today' || o.due).length === 0) && (
              <div className="ledger-empty">Nothing matches.</div>
            )}
          </div>
        )}
      </div>

      {/* the ghost: the card in the hand, following the pointer */}
      {dragOrg && drag && (
        <div
          className="drag-ghost"
          ref={ghostRef}
          style={{ width: drag.w, transform: `translate3d(${Math.round(drag.x - drag.dx)}px, ${Math.round(drag.y - drag.dy)}px, 0) rotate(-1deg)` }}
          aria-hidden="true"
        >
          <span className="c-top">
            <span className="c-org">{dragOrg.name}</span>
            {dragOrg.money !== undefined && <span className="c-money">{fmtMoney(dragOrg.money)}</span>}
          </span>
          <span className="c-step">{dragOrg.step}</span>
        </div>
      )}
    </main>
  )
}
