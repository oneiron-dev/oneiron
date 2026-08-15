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
   ledger (default): the work queue, stage groups of one-line rows, nearest
   to money first. board: the glance, money-end stages as columns of org
   chips. a chip in the board flips back to the ledger with that row open.
   rows unfold IN PLACE (thread tail · claims · acts); acts settle in place
   as receipt lines; no toasts, no modals, no column. */

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
]
const BY_STAGE = Object.fromEntries(STAGES.map((s) => [s.key, s])) as Record<Stage, (typeof STAGES)[number]>

/* the ledger runs money first; the two early stages collapse to a door each */
const LEDGER_ORDER: Stage[] = ['deposit', 'proposal', 'audit', 'call', 'replied', 'outreach']
const EARLY: Stage[] = ['qualified', 'sourced']

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
  who: Human
  chan: Chan
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
    id, name, stage: 'outreach', more: true, next, who, chan, last, age, since: last,
    lastTip: `last touch · ${last} · first touch, no reply`,
    tail: [
      { by: { agent: 'eiri' }, when: `${last} 09:00`, chan, tip: `sent by ${who === 'o' ? 'oleksii' : 'yurii'}’s click`, msg: 'First touch: what we do, one client outcome, one question.', state: { text: 'delivered · no reply' } },
    ],
    claims: [
      { id: `cl_${id.slice(0, 2)}90`, text: 'Fits the forecasting work by size and season', conf: 0.7, dot: 'auto', when: 'learned 07-28' },
    ],
    acts: ['draft', 'org', 'thread', 'watch'],
  })),
]

const BOARD_STAGES: Stage[] = ['deposit', 'proposal', 'audit', 'call', 'replied', 'outreach']

/* ── the receipts an act settles into (serif, name in ink) ── */
type Receipt = { key: ActKey; node: React.ReactNode }
const NONE: ActKey[] = []

function confClass(c: number) {
  return c >= 0.9 ? 'conf-1' : c >= 0.7 ? 'conf-2' : c >= 0.4 ? 'conf-3' : 'conf-4'
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

/* ── one org row: the line, the unfold, the acts that settle in place.
   what settled lives with the page (a filter may unmount the row; the
   receipt must survive it) ── */
function OrgRow({
  org,
  open,
  sel,
  settled,
  onSettle,
  onToggle,
}: {
  org: Org
  open: boolean
  sel: boolean
  settled: ActKey[]
  onSettle: (key: ActKey) => void
  onToggle: () => void
}) {
  const done = React.useMemo(() => new Set(settled), [settled])
  const receipts: Receipt[] = settled.map((key) => ({ key, node: receiptFor(key) }))
  const drafted = done.has('draft') || done.has('book') || done.has('pager')
  const parked = done.has('park')

  const settle = (key: ActKey) => (e: React.MouseEvent) => {
    markCued(e)
    onSettle(key)
    cue(key === 'park' ? 'press' : 'success')
  }

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
        title={open ? 'close' : 'open the row · thread tail, claims, next steps'}
      >
        <span className="r-org">{org.name}</span>
        <span className="r-next" title={org.next}>
          {org.next}
        </span>
        <span className="r-who">
          <span className="seal seal-human" title={`${HUMANS[org.who]} · owns this one`}>
            {org.who}
          </span>
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
      </div>
    </div>
  )
}

/* ── a stage group: serif head (count only when collapsed), rows, `N more` ── */
function StageGroup({
  stage,
  orgs,
  openId,
  selId,
  settled,
  onSettle,
  onToggle,
  forceMore,
}: {
  stage: Stage
  orgs: Org[]
  openId: string | null
  selId: string | null
  settled: Record<string, ActKey[]>
  onSettle: (id: string, key: ActKey) => void
  onToggle: (id: string) => void
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
          <Chevron ariaHidden={false} />
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
            settled={settled[o.id] ?? NONE}
            onSettle={(k) => onSettle(o.id, k)}
            onToggle={() => onToggle(o.id)}
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

type Proj = 'ledger' | 'board'

function Pipeline() {
  const [proj, setProjState] = React.useState<Proj>('ledger')
  const [stage, setStage] = React.useState<Stage | null>(null)
  const [openId, setOpenId] = React.useState<string | null>(null)
  const [selId, setSelId] = React.useState<string | null>(null)
  const [hintOpen, setHintOpen] = React.useState(false)
  const scrollTo = React.useRef<string | null>(null)
  /* what settled, per org: the receipts outlive any filter or projection flip */
  const [settled, setSettled] = React.useState<Record<string, ActKey[]>>({})
  const onSettle = (id: string, key: ActKey) =>
    setSettled((s) => {
      const cur = s[id] ?? []
      return cur.includes(key) ? s : { ...s, [id]: [...cur, key] }
    })
  const isParked = (id: string) => (settled[id] ?? []).includes('park')

  /* the projection persists (the same lens, remembered) */
  React.useEffect(() => {
    try {
      const v = localStorage.getItem('oneiron-pipeline-proj')
      if (v === 'board') setProjState('board')
    } catch {
      /* private mode · the ledger it is */
    }
  }, [])
  const setProj = (p: Proj) => {
    setProjState(p)
    try {
      localStorage.setItem('oneiron-pipeline-proj', p)
    } catch {
      /* private mode */
    }
    cue('toggle')
  }

  const toggleRow = (id: string) => {
    setOpenId((cur) => (cur === id ? null : id))
    setSelId(null)
    cue('toggle')
  }

  /* a chip filters the ledger to that stage (toggle) */
  const pickStage = (s: Stage) => {
    setStage((cur) => (cur === s ? null : s))
    cue('toggle')
  }

  /* a board chip selects the org: back to the ledger, that row open */
  const selectFromBoard = (org: Org) => {
    if (stage && stage !== org.stage) setStage(null)
    setOpenId(org.id)
    setSelId(org.id)
    scrollTo.current = org.id
    setProj('ledger')
  }
  React.useEffect(() => {
    if (proj !== 'ledger' || !scrollTo.current) return
    const id = scrollTo.current
    scrollTo.current = null
    const el = document.getElementById(`org-${id}`)
    const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches
    el?.scrollIntoView({ block: 'center', behavior: reduce ? 'auto' : 'smooth' })
  }, [proj, openId])

  useEscape(() => {
    setOpenId(null)
    setSelId(null)
    setHintOpen(false)
  })

  const groups = LEDGER_ORDER.filter((s) => !stage || s === stage)
  const early = EARLY.filter((s) => !stage || s === stage)

  return (
    <main className="pane" id="pane">
      <div className="pane-body">
        <div className="pane-head">
          <h1>Pipeline</h1>
          <span className="pane-tools">
            <span className="proj" role="group" aria-label="projection">
              <button
                className="act"
                aria-pressed={proj === 'ledger'}
                title="ledger · the work queue, stage by stage, nearest to money first"
                onClick={() => setProj('ledger')}
              >
                ledger
              </button>
              <span className="sep" aria-hidden="true">
                ⇄
              </span>
              <button
                className="act"
                aria-pressed={proj === 'board'}
                title="board · where every org stands, at a glance"
                onClick={() => setProj('board')}
              >
                board
              </button>
            </span>
            <button
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
            Every org, and where it stands. The ledger is the queue, money first. A row opens in
            place. The board is the same orgs at a glance. Click a stage to see only it.
          </span>
        </div>

        {/* the funnel as data: 8 stage chips with counts, spine order */}
        <div className="funnel" role="group" aria-label="stages">
          {STAGES.map((s, i) => (
            <React.Fragment key={s.key}>
              {i > 0 && (
                <span className="fsep" aria-hidden="true">
                  ·
                </span>
              )}
              <button
                className={stage === s.key ? 'schip on' : 'schip'}
                aria-pressed={stage === s.key}
                title={`${s.tip} · click: only this stage`}
                onClick={() => pickStage(s.key)}
              >
                <span>{s.name}</span>
                <span className="n">{s.n}</span>
              </button>
            </React.Fragment>
          ))}
        </div>

        {/* today: the clock facts, one quiet line */}
        <div className="tstrip">
          <span className="t-say">
            2 next steps due today <span className="q">·</span> 1 call booked: Hokuei, Thursday 10:00
          </span>
          <Link className="act" to="/app/briefs" title="the meeting brief for Thursday 10:00 · every sentence cites its claims">
            meeting brief
          </Link>
        </div>

        {/* ══ INSTRUMENT · the pipeline lens, two projections ══ */}
        <section className="lens instrument" aria-label="pipeline lens">
          <div
            className="instrument-eyebrow"
            title="agent-rendered lens · pack crm · 76 orgs · the ledger runs money first · swept 09:41"
          >
            <span>pipeline lens · Antevon · as of 09:41</span>
          </div>
          <div className="sec-voice">
            <span className="aname" data-agent="antevon" title="Antevon · the house mind · the 09:41 sweep">
              Antevon
            </span>
            <span>
              Six orgs moved this week. Bergstrom has not answered since the 6th. That is usually
              where you park it.
            </span>
          </div>

          {proj === 'ledger' ? (
            <div className="stack" id="stack">
              {groups.map((s) => (
                <StageGroup
                  key={s}
                  stage={s}
                  orgs={ORGS.filter((o) => o.stage === s)}
                  openId={openId}
                  selId={selId}
                  settled={settled}
                  onSettle={onSettle}
                  onToggle={toggleRow}
                  forceMore={stage === s}
                />
              ))}
              {early.map((s) => (
                <section className="sgroup early" aria-label={BY_STAGE[s].name} key={s}>
                  <div className="head">
                    <span className="title" title={BY_STAGE[s].tip}>
                      {BY_STAGE[s].name}
                    </span>
                    <Link
                      className="act"
                      to="/app/orgs"
                      title={`${BY_STAGE[s].n} ${BY_STAGE[s].name} · the list, as a filtered ledger${
                        s === 'qualified' ? ' · Tory keeps it warm and reports once a week' : ' · straight from the trade registry, read by nobody yet'
                      }`}
                    >
                      {BY_STAGE[s].n} more
                    </Link>
                  </div>
                </section>
              ))}
              {groups.length === 0 && early.length === 0 && (
                <div className="ledger-empty">Nothing at this stage.</div>
              )}
            </div>
          ) : (
            <div className="board" id="board" aria-label="board">
              <div className="pcols">
                {BOARD_STAGES.map((s) => (
                  <div className="pcol" key={s}>
                    <span className="label" title={BY_STAGE[s].tip}>
                      {BY_STAGE[s].name}
                    </span>
                    {ORGS.filter((o) => o.stage === s).map((o) => (
                      <button
                        type="button"
                        className={isParked(o.id) ? 'ochip parked' : 'ochip'}
                        key={o.id}
                        title={`${o.name} · ${isParked(o.id) ? 'parked' : o.next} · opens the row in the ledger`}
                        onClick={() => selectFromBoard(o)}
                      >
                        {o.name}
                      </button>
                    ))}
                  </div>
                ))}
              </div>
              {/* the early stages: a count line at the foot, each a door back to the ledger */}
              <div className="pcounts" role="group" aria-label="the early stages">
                {EARLY.map((s) => (
                  <button
                    type="button"
                    className="act"
                    key={s}
                    title={`${BY_STAGE[s].n} ${BY_STAGE[s].name} · back to the ledger, this stage only`}
                    onClick={() => {
                      setStage(s)
                      setProj('ledger')
                    }}
                  >
                    {BY_STAGE[s].name} {BY_STAGE[s].n}
                  </button>
                ))}
              </div>
            </div>
          )}
        </section>
      </div>
    </main>
  )
}
