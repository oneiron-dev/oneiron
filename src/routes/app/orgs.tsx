import * as React from 'react'
import { Link, createFileRoute } from '@tanstack/react-router'
import { cue, markCued, useEscape } from '~/components/safelight/hooks'
import { ChanLine, ChanLinkedin, ChanMail, ChanSlack } from '~/components/safelight/icons'
import orgsCss from '~/styles/orgs.css?url'

export const Route = createFileRoute('/app/orgs')({
  head: () => ({
    links: [{ rel: 'stylesheet', href: orgsCss }],
  }),
  component: Orgs,
})

/* ══ fixtures · the orgs the vault knows (JP-consulting register, stages
   from the pipeline). Hokuei is the pilot client; its record is the
   full one, the others carry lighter ones. today = 08-15. ══ */

const STAGES = ['sourced', 'qualified', 'outreach', 'replied', 'call booked', 'audit', 'proposal', 'deposit'] as const
type Stage = (typeof STAGES)[number]

type Owner = 'o' | 'y'
type Chan = 'line' | 'mail' | 'linkedin' | 'slack' | 'meeting' | 'research'
type Conf = 1 | 2 | 3 | 4

type Person = {
  seal: string
  line: string
  conf: Conf
  tip: string
  chans: Chan[]
  door?: { text: string; href: string; tip: string }
}

type Claim = {
  text: string
  conf: Conf
  score: string
  source: string
  state: 'approved' | 'auto' | 'proposed'
  tip: string
}

type Entry =
  | { kind: 'human'; seal: string; cls?: boolean; tip: string; msg: string; lang?: string; conf: Conf }
  | { kind: 'agent'; agent: 'eiri' | 'tory' | 'antevon'; name: string; tip: string; msg: string; conf: Conf }

type Who = { seal: string; tip: string; cls?: boolean } | { agent: 'eiri' | 'tory' | 'antevon'; tip: string }

type Touch = { when: string; chan: Chan; who: Who; what: string; lang?: string }
type ThreadRow = { chan: Chan; with: string; last: string; when: string; lang?: string }
type BriefRow = { title: string; by: Who; when: string }
type TaskRow = { id: string; text: string; who: Who; due: string }
type Note = { title: string; tip: string }

type Org = {
  id: string
  name: string
  stage: Stage
  owner: Owner
  touch: { date: string; time: string; tip: string }
  claims: number
  byline: string
  money: string
  moneyTip: string
  people: Person[]
  know: Claim[]
  thread: Entry[]
  next: { line: string; when: string; draft?: string; book?: boolean }
  notes: Note[]
  timeline: Touch[]
  threads: ThreadRow[]
  briefs: BriefRow[]
  tasks: TaskRow[]
}

const OWNER_TIP: Record<Owner, string> = {
  o: 'o · Owen · owner',
  y: 'y · Yuki',
}
const O: Who = { seal: 'o', tip: 'o · Owen' }
const Y: Who = { seal: 'y', tip: 'y · Yuki' }
const EIRI: Who = { agent: 'eiri', tip: 'Eiri · outbound' }
const TORY: Who = { agent: 'tory', tip: 'Tory · research · reads only' }
const ANTEVON: Who = { agent: 'antevon', tip: 'Antevon · the house mind' }

const TODAY = '08-15'
const AS_OF = 'Antevon · as of 14:07'

const ORGS: Org[] = [
  {
    id: 'hokuei-foods',
    name: 'Hokuei Foods',
    stage: 'audit',
    owner: 'y',
    touch: { date: '08-15', time: '14:02', tip: '2026-08-15 14:02 · linkedin · Yuki' },
    claims: 42,
    byline: 'pilot client · supplier-consolidation storyline · Yuki owns it',
    money: '¥1.8M · pilot, 12 weeks',
    moneyTip: 'the pilot as scoped 08-15 · not yet signed',
    people: [
      {
        seal: 'm',
        line: 'Mika Tanaka · procurement',
        conf: 2,
        tip: 'm · Mika Tanaka · contact · imported via LINE OA · prefers LINE for quick questions',
        chans: ['line', 'mail'],
      },
      {
        seal: 'k',
        line: 'the COO · budget owner, not yet met',
        conf: 3,
        tip: 'k · the COO · contact · budget owner · not yet met',
        chans: ['linkedin'],
        door: {
          text: 'reach through Yuki’s account',
          href: '/app/inbox',
          tip: 'Eiri asks before it reaches · the consent waits in your inbox',
        },
      },
    ],
    know: [
      { text: 'Pilot decision expected by July 18', conf: 1, score: '.94', source: 'call 08-10', state: 'approved', tip: 'confidence 0.94 · approved · occurred 08-10' },
      { text: 'Mika Tanaka leads procurement; prefers LINE for quick questions', conf: 2, score: '.86', source: 'LINE 08-05', state: 'auto', tip: 'confidence 0.86 · auto · occurred 08-05' },
      { text: 'Chilled line waste sits near 8% in summer months', conf: 2, score: '.83', source: 'call 07-29', state: 'auto', tip: 'confidence 0.83 · auto · occurred 07-29' },
      { text: 'May be consolidating suppliers this fiscal year', conf: 3, score: '.58', source: 'Tory · filings', state: 'proposed', tip: 'confidence 0.58 · proposed by Tory from public filings · learned 08-14 · waits in your inbox' },
    ],
    thread: [
      { kind: 'human', seal: 'y', tip: 'y · Yuki · 08-15 14:02 · linkedin · sent from his account, his click · verifying', msg: 'Thanks for the call. Sending the pilot one-pager over email now.', conf: 1 },
      { kind: 'agent', agent: 'eiri', name: 'Eiri', tip: 'Eiri · outbound · 08-15 11:48 · email · draft approved by Yuki 11:46 · verified in thread', msg: 'Pilot scope summary: 12-week chilled-line forecast, weekly re-fit, waste target under 5%.', conf: 2 },
      { kind: 'human', seal: 'm', cls: true, tip: 'm · Mika Tanaka · 08-12 09:15 · LINE', msg: '見積もりの件、来週の火曜までにお願いできますか。', lang: 'ja', conf: 2 },
    ],
    next: { line: 'Send Mika the quote by Tuesday. Follow up on the one-pager if no reply by 08-19.', when: '08-19', draft: 'draft the follow-up', book: true },
    notes: [
      { title: 'Pilot scope note', tip: 'note · Yuki · 08-11' },
      { title: 'Their reply pace changed after 08-09', tip: 'note · Tory · 08-14 · a competitor quote is likely on the table' },
    ],
    timeline: [
      { when: '08-15 14:02', chan: 'linkedin', who: Y, what: 'Thanks for the call. Sending the pilot one-pager over email now.' },
      { when: '08-15 11:48', chan: 'mail', who: EIRI, what: 'Pilot scope summary: 12-week chilled-line forecast, weekly re-fit, waste target under 5%.' },
      { when: '08-14 09:30', chan: 'research', who: TORY, what: 'Filings suggest a supplier consolidation this fiscal year. Proposed as a claim.' },
      { when: '08-12 09:15', chan: 'line', who: { seal: 'm', cls: true, tip: 'm · Mika Tanaka' }, what: '見積もりの件、来週の火曜までにお願いできますか。', lang: 'ja' },
      { when: '08-11 18:02', chan: 'line', who: Y, what: 'Thursday 10:00 works. I will bring the summer numbers.' },
      { when: '08-10 15:30', chan: 'meeting', who: ANTEVON, what: 'Transcribed the pilot call. 41 minutes, nine claims.' },
      { when: '08-05 10:10', chan: 'line', who: { seal: 'm', cls: true, tip: 'm · Mika Tanaka' }, what: 'LINEのほうが早いです。急ぎはこちらでお願いします。', lang: 'ja' },
      { when: '07-29 16:40', chan: 'meeting', who: Y, what: 'First call. Summer waste near 8% on the chilled line.' },
    ],
    threads: [
      { chan: 'line', with: 'Mika Tanaka', last: '見積もりの件、来週の火曜までにお願いできますか。', when: '08-12', lang: 'ja' },
      { chan: 'mail', with: 'Mika Tanaka · the COO in copy', last: 'Pilot scope summary: 12-week chilled-line forecast.', when: '08-15' },
    ],
    briefs: [
      { title: 'Call prep · Hokuei, Thursday 10:00', by: ANTEVON, when: '08-14' },
      { title: 'Their reply pace changed after 08-09', by: TORY, when: '08-14' },
    ],
    tasks: [
      { id: 'hk-1', text: 'Send Mika the quote', who: Y, due: '08-19' },
      { id: 'hk-2', text: 'Follow up on the one-pager if no reply', who: Y, due: '08-19' },
      { id: 'hk-3', text: 'Name the pilot in the scope note', who: O, due: '08-21' },
    ],
  },
  {
    id: 'fuji-kitchens',
    name: 'Fuji Kitchens',
    stage: 'outreach',
    owner: 'y',
    touch: { date: '08-15', time: '09:40', tip: '2026-08-15 09:40 · email · Yuki' },
    claims: 31,
    byline: 'client · frozen-line forecast, 12 weeks · Yuki owns it',
    money: '¥2.4M · 12 weeks, deposit paid',
    moneyTip: 'deposit ¥600k received 08-10 · balance on delivery',
    people: [
      { seal: 'r', line: 'Rina Sato · operations lead', conf: 1, tip: 'r · Rina Sato · contact · imported via email', chans: ['mail', 'line'] },
    ],
    know: [
      { text: 'Deposit paid 08-10; kickoff set for 08-22', conf: 1, score: '.96', source: 'mail 08-10', state: 'approved', tip: 'confidence 0.96 · approved · occurred 08-10' },
      { text: 'Frozen line runs three SKUs with weekly overs above 6%', conf: 2, score: '.84', source: 'call 08-08', state: 'auto', tip: 'confidence 0.84 · auto · occurred 08-08' },
      { text: 'Their ERP exports CSV weekly, no API', conf: 2, score: '.81', source: 'LINE 08-14', state: 'auto', tip: 'confidence 0.81 · auto · occurred 08-14' },
    ],
    thread: [
      { kind: 'human', seal: 'y', tip: 'y · Yuki · 08-15 09:40 · email', msg: 'Kickoff deck sent. Asked for the sales export by Friday.', conf: 1 },
      { kind: 'human', seal: 'r', cls: true, tip: 'r · Rina Sato · 08-14 17:10 · LINE', msg: 'データは金曜までにお送りします。', lang: 'ja', conf: 2 },
    ],
    next: { line: 'Confirm the export lands by Friday. Prepare the kickoff brief for 08-22.', when: '08-22', draft: 'draft the follow-up' },
    notes: [{ title: 'Kickoff brief, 08-22', tip: 'brief · Antevon · compiles the day before' }],
    timeline: [
      { when: '08-15 09:40', chan: 'mail', who: Y, what: 'Kickoff deck sent. Asked for the sales export by Friday.' },
      { when: '08-14 17:10', chan: 'line', who: { seal: 'r', cls: true, tip: 'r · Rina Sato' }, what: 'データは金曜までにお送りします。', lang: 'ja' },
      { when: '08-10 11:05', chan: 'mail', who: { seal: 'r', cls: true, tip: 'r · Rina Sato' }, what: 'Deposit sent. Kickoff on the 22nd works for us.' },
      { when: '08-08 14:00', chan: 'meeting', who: ANTEVON, what: 'Transcribed the scoping call. 38 minutes, seven claims.' },
      { when: '08-05 22:10', chan: 'research', who: TORY, what: 'Their planning lead is listed publicly. Reachable by name.' },
    ],
    threads: [
      { chan: 'mail', with: 'Rina Sato', last: 'Kickoff deck sent. Asked for the sales export by Friday.', when: '08-15' },
      { chan: 'line', with: 'Rina Sato', last: 'データは金曜までにお送りします。', when: '08-14', lang: 'ja' },
    ],
    briefs: [{ title: 'Kickoff brief · Fuji, 08-22', by: ANTEVON, when: 'compiles 08-21' }],
    tasks: [
      { id: 'fk-1', text: 'Confirm the export lands', who: Y, due: '08-15' },
      { id: 'fk-2', text: 'Read the kickoff brief before the call', who: Y, due: '08-22' },
    ],
  },
  {
    id: 'kanto-logistics',
    name: 'Kanto Logistics',
    stage: 'call booked',
    owner: 'o',
    touch: { date: '08-14', time: '16:20', tip: '2026-08-14 16:20 · linkedin · Owen' },
    claims: 18,
    byline: 'prospect · cold-chain routing waste · you own it',
    money: '¥1.2M · estimate',
    moneyTip: 'a first estimate from the routing profile · not quoted',
    people: [
      { seal: 'h', line: 'Hiroshi Kondo · head of planning', conf: 2, tip: 'h · Hiroshi Kondo · contact · imported via linkedin', chans: ['linkedin', 'mail'] },
    ],
    know: [
      { text: 'Call booked for 08-18 15:00 with the head of planning', conf: 1, score: '.95', source: 'linkedin 08-14', state: 'approved', tip: 'confidence 0.95 · approved · occurred 08-14' },
      { text: 'Runs 40 chilled trucks across Kanto; spoilage is tracked by hand', conf: 2, score: '.79', source: 'linkedin 08-08', state: 'auto', tip: 'confidence 0.79 · auto · occurred 08-08' },
      { text: 'May be tendering a routing tool this autumn', conf: 3, score: '.55', source: 'Tory · trade note', state: 'proposed', tip: 'confidence 0.55 · proposed by Tory from a trade note · learned 08-13' },
    ],
    thread: [
      { kind: 'human', seal: 'o', tip: 'o · Owen · 08-14 16:20 · linkedin', msg: 'Confirmed Thursday 15:00. Sending an agenda tomorrow.', conf: 1 },
      { kind: 'human', seal: 'h', cls: true, tip: 'h · Hiroshi Kondo · 08-14 11:02 · linkedin', msg: '来週木曜15時でお願いします。', lang: 'ja', conf: 2 },
    ],
    next: { line: 'Send the agenda for 08-18. Ask for one month of route data before the call.', when: '08-16', draft: 'draft the follow-up' },
    notes: [{ title: 'Call prep, 08-18', tip: 'brief · Antevon · compiles the day before' }],
    timeline: [
      { when: '08-14 16:20', chan: 'linkedin', who: O, what: 'Confirmed Thursday 15:00. Sending an agenda tomorrow.' },
      { when: '08-14 11:02', chan: 'linkedin', who: { seal: 'h', cls: true, tip: 'h · Hiroshi Kondo' }, what: '来週木曜15時でお願いします。', lang: 'ja' },
      { when: '08-13 08:20', chan: 'research', who: TORY, what: 'A trade note hints at a routing tender this autumn. Proposed as a claim.' },
      { when: '08-08 09:14', chan: 'linkedin', who: EIRI, what: 'First touch: cold-chain routing waste, one question about spoilage.' },
    ],
    threads: [
      { chan: 'linkedin', with: 'Hiroshi Kondo', last: 'Confirmed Thursday 15:00. Sending an agenda tomorrow.', when: '08-14' },
    ],
    briefs: [{ title: 'Call prep · Kanto, 08-18 15:00', by: ANTEVON, when: 'compiles 08-17' }],
    tasks: [
      { id: 'kl-1', text: 'Send the agenda for Thursday', who: O, due: '08-16' },
      { id: 'kl-2', text: 'Ask for one month of route data', who: O, due: '08-16' },
    ],
  },
  {
    id: 'sakura-retail',
    name: 'Sakura Retail',
    stage: 'proposal',
    owner: 'y',
    touch: { date: '08-13', time: '10:15', tip: '2026-08-13 10:15 · email · Aya Mori' },
    claims: 11,
    byline: 'prospect · store-level replenishment · Yuki owns it',
    money: '¥3.0M · proposal, 8 weeks',
    moneyTip: 'proposal as sent 08-11 · store level, weekly re-fit',
    people: [
      { seal: 'a', line: 'Aya Mori · merchandising', conf: 2, tip: 'a · Aya Mori · contact · imported via email', chans: ['mail'] },
    ],
    know: [
      { text: 'Replied 08-13; wants a one-page case before any call', conf: 1, score: '.92', source: 'mail 08-13', state: 'approved', tip: 'confidence 0.92 · approved · occurred 08-13' },
      { text: 'Runs 120 stores; replenishment is a weekly spreadsheet', conf: 2, score: '.77', source: 'mail 08-13', state: 'auto', tip: 'confidence 0.77 · auto · occurred 08-13' },
    ],
    thread: [
      { kind: 'human', seal: 'a', cls: true, tip: 'a · Aya Mori · 08-13 10:15 · email', msg: 'まず事例を1枚いただけますか。その後で相談させてください。', lang: 'ja', conf: 2 },
      { kind: 'agent', agent: 'eiri', name: 'Eiri', tip: 'Eiri · outbound · 08-11 09:30 · email · draft approved by Yuki · verified in thread', msg: 'Intro: demand forecasting for store replenishment, three lines.', conf: 2 },
    ],
    next: { line: 'Send the one-page case. Offer two call slots once it lands.', when: '08-18', draft: 'draft the follow-up', book: true },
    notes: [],
    timeline: [
      { when: '08-13 10:15', chan: 'mail', who: { seal: 'a', cls: true, tip: 'a · Aya Mori' }, what: 'まず事例を1枚いただけますか。その後で相談させてください。', lang: 'ja' },
      { when: '08-11 09:30', chan: 'mail', who: EIRI, what: 'Intro: demand forecasting for store replenishment, three lines.' },
      { when: '08-09 20:05', chan: 'research', who: TORY, what: '120 stores, replenishment on a weekly spreadsheet. Merchandising lead named.' },
    ],
    threads: [{ chan: 'mail', with: 'Aya Mori', last: 'まず事例を1枚いただけますか。', when: '08-13', lang: 'ja' }],
    briefs: [{ title: 'One-page case · store replenishment', by: Y, when: 'draft 08-14' }],
    tasks: [
      { id: 'sr-1', text: 'Send the one-page case', who: Y, due: '08-18' },
      { id: 'sr-2', text: 'Offer two call slots once it lands', who: Y, due: '08-20' },
    ],
  },
  {
    id: 'nishi-trading',
    name: 'Nishi Trading',
    stage: 'deposit',
    owner: 'o',
    touch: { date: '08-11', time: '13:00', tip: '2026-08-11 13:00 · meeting · Owen' },
    claims: 27,
    byline: 'prospect · import demand audit · you own it',
    money: '¥900k · audit, deposit paid',
    moneyTip: 'deposit ¥300k received 08-08 · read-out due 08-28',
    people: [
      { seal: 't', line: 'Takeshi Nishi · managing director', conf: 1, tip: 't · Takeshi Nishi · contact · met 08-11', chans: ['mail', 'meeting'] },
      { seal: 's', line: 'Saki Ueda · finance', conf: 2, tip: 's · Saki Ueda · contact · imported via email', chans: ['mail'] },
    ],
    know: [
      { text: 'Audit under way; two years of import data received 08-09', conf: 1, score: '.97', source: 'mail 08-09', state: 'approved', tip: 'confidence 0.97 · approved · occurred 08-09' },
      { text: 'Overstock on three lines ties up about ¥40M', conf: 2, score: '.82', source: 'meeting 08-11', state: 'auto', tip: 'confidence 0.82 · auto · occurred 08-11' },
      { text: 'Wants the audit read-out before 08-28', conf: 2, score: '.80', source: 'mail 08-09', state: 'auto', tip: 'confidence 0.80 · auto · occurred 08-09' },
    ],
    thread: [
      { kind: 'human', seal: 'o', tip: 'o · Owen · 08-11 13:00 · meeting · 45 min · 9 claims extracted', msg: 'Audit kickoff, 45 minutes. Data in hand, questions sent.', conf: 1 },
      { kind: 'human', seal: 't', cls: true, tip: 't · Takeshi Nishi · 08-09 15:40 · email', msg: '7月20日までに結果を見たいです。', lang: 'ja', conf: 2 },
    ],
    next: { line: 'Finish the read-out by 08-25. Book the read-out call.', when: '08-25', book: true },
    notes: [{ title: 'Audit working notes', tip: 'note · Owen · 08-13' }],
    timeline: [
      { when: '08-11 13:00', chan: 'meeting', who: O, what: 'Audit kickoff, 45 minutes. Data in hand, questions sent.' },
      { when: '08-11 14:10', chan: 'meeting', who: ANTEVON, what: 'Transcribed the kickoff. 45 minutes, nine claims.' },
      { when: '08-09 15:40', chan: 'mail', who: { seal: 't', cls: true, tip: 't · Takeshi Nishi' }, what: '7月20日までに結果を見たいです。', lang: 'ja' },
      { when: '08-09 09:02', chan: 'mail', who: { seal: 's', cls: true, tip: 's · Saki Ueda' }, what: 'Two years of import data attached, by line and month.' },
      { when: '08-08 10:30', chan: 'mail', who: O, what: 'Deposit received, thank you. The data checklist follows.' },
    ],
    threads: [
      { chan: 'mail', with: 'Takeshi Nishi', last: '7月20日までに結果を見たいです。', when: '08-09', lang: 'ja' },
      { chan: 'mail', with: 'Saki Ueda', last: 'Two years of import data attached, by line and month.', when: '08-09' },
    ],
    briefs: [{ title: 'Audit read-out · Nishi', by: O, when: 'due 08-25' }],
    tasks: [
      { id: 'nt-1', text: 'Finish the read-out', who: O, due: '08-25' },
      { id: 'nt-2', text: 'Book the read-out call', who: O, due: '08-20' },
    ],
  },
  {
    id: 'meiji-bakeries',
    name: 'Meiji Bakeries',
    stage: 'replied',
    owner: 'y',
    touch: { date: '08-09', time: '11:20', tip: '2026-08-09 11:20 · email · Eiri' },
    claims: 6,
    byline: 'prospect · daily bake planning · Yuki owns it',
    money: '¥600k · estimate',
    moneyTip: 'a first estimate from the returns profile · not quoted',
    people: [
      { seal: 'k', line: 'Kenta Ito · plant manager, not yet met', conf: 3, tip: 'k · Kenta Ito · contact · from the company site', chans: ['mail'] },
    ],
    know: [
      { text: 'Intro sent 08-09; no reply yet', conf: 1, score: '.93', source: 'mail 08-09', state: 'approved', tip: 'confidence 0.93 · approved · occurred 08-09' },
      { text: 'Bakes to a fixed daily plan; returns near 10%', conf: 3, score: '.62', source: 'interview 2025', state: 'auto', tip: 'confidence 0.62 · auto · a public interview, 2025' },
    ],
    thread: [
      { kind: 'agent', agent: 'eiri', name: 'Eiri', tip: 'Eiri · outbound · 08-09 11:20 · email · draft approved by Yuki · verified in thread', msg: 'Intro: daily bake planning from POS data, three lines.', conf: 2 },
    ],
    next: { line: 'Follow up on 08-16 if there is no reply.', when: '08-16', draft: 'draft the follow-up' },
    notes: [],
    timeline: [
      { when: '08-09 11:20', chan: 'mail', who: EIRI, what: 'Intro: daily bake planning from POS data, three lines.' },
      { when: '08-07 21:00', chan: 'research', who: TORY, what: 'Fixed daily plan, returns near 10% in a 2025 interview. Plant manager named.' },
    ],
    threads: [{ chan: 'mail', with: 'Kenta Ito', last: 'Intro: daily bake planning from POS data, three lines.', when: '08-09' }],
    briefs: [],
    tasks: [{ id: 'mb-1', text: 'Follow up if there is no reply', who: Y, due: '08-16' }],
  },
  {
    id: 'ohta-metals',
    name: 'Ohta Metals',
    stage: 'replied',
    owner: 'o',
    touch: { date: '08-06', time: '09:12', tip: '2026-08-06 09:12 · research · Tory' },
    claims: 4,
    byline: 'prospect · parts demand for two plants · you own it',
    money: 'not sized',
    moneyTip: 'no estimate yet · two plants, three auto suppliers',
    people: [],
    know: [
      { text: 'Two plants in Gunma; ships to three auto suppliers', conf: 2, score: '.78', source: 'filings', state: 'auto', tip: 'confidence 0.78 · auto · public filings' },
      { text: 'Fits the plant-demand profile; qualified 08-06', conf: 1, score: '.90', source: 'Owen 08-06', state: 'approved', tip: 'confidence 0.90 · approved · occurred 08-06' },
      { text: 'May be opening a third line in 2027', conf: 4, score: '.35', source: 'Tory · trade note', state: 'proposed', tip: 'confidence 0.35 · proposed by Tory from a trade note · learned 08-06' },
    ],
    thread: [
      { kind: 'agent', agent: 'tory', name: 'Tory', tip: 'Tory · research · 08-06 09:12 · reads only', msg: 'Two plants, three auto suppliers, no forecasting vendor named in the filings.', conf: 3 },
    ],
    next: { line: 'Find the planning lead. Then the intro.', when: '08-20', draft: 'draft the intro' },
    notes: [],
    timeline: [
      { when: '08-06 09:12', chan: 'research', who: TORY, what: 'Two plants, three auto suppliers, no forecasting vendor named in the filings.' },
      { when: '08-06 09:40', chan: 'research', who: O, what: 'Qualified. Fits the plant-demand profile.' },
    ],
    threads: [],
    briefs: [],
    tasks: [{ id: 'om-1', text: 'Find the planning lead', who: TORY, due: '08-20' }],
  },
  {
    id: 'aoi-pharma',
    name: 'Aoi Pharma',
    stage: 'sourced',
    owner: 'o',
    touch: { date: '08-02', time: '08:05', tip: '2026-08-02 08:05 · research · Tory' },
    claims: 2,
    byline: 'sourced · OTC lines with seasonal swings · you own it',
    money: 'not sized',
    moneyTip: 'no estimate yet · sourced from a trade list',
    people: [],
    know: [
      { text: 'Sells OTC lines with strong seasonal swings', conf: 3, score: '.60', source: 'filings', state: 'auto', tip: 'confidence 0.60 · auto · public filings' },
      { text: 'Sourced from a trade list 08-02', conf: 1, score: '.90', source: 'Tory 08-02', state: 'approved', tip: 'confidence 0.90 · approved · occurred 08-02' },
    ],
    thread: [
      { kind: 'agent', agent: 'tory', name: 'Tory', tip: 'Tory · research · 08-02 08:05 · reads only', msg: 'Sourced from the JPMA member list. Seasonal OTC lines, no vendor named.', conf: 3 },
    ],
    next: { line: 'Qualify or drop by 08-23.', when: '08-23' },
    notes: [],
    timeline: [{ when: '08-02 08:05', chan: 'research', who: TORY, what: 'Sourced from the JPMA member list. Seasonal OTC lines, no vendor named.' }],
    threads: [],
    briefs: [],
    tasks: [{ id: 'ap-1', text: 'Qualify or drop', who: O, due: '08-23' }],
  },
]

/* watched on load: two orgs already under watch; Hokuei is not, so the
   foot act has something to do */
const WATCHED_AT_LOAD = ['kanto-logistics', 'aoi-pharma']

type Filter = 'all' | 'watched' | 'mine'

const DOT: Record<Claim['state'], { cls: string; tip: string }> = {
  approved: { cls: 'dot dot-approved', tip: 'approved' },
  auto: { cls: 'dot dot-auto', tip: 'auto · trusted, unreviewed' },
  proposed: { cls: 'dot dot-proposed', tip: 'proposed · waits in your inbox' },
}

const CHAN_TIP: Record<Chan, string> = {
  line: 'LINE',
  mail: 'email',
  linkedin: 'linkedin',
  slack: 'slack',
  meeting: 'meeting',
  research: 'research',
}

/* ── the ledger's columns, TanStack-Table shaped so a later swap is cheap ── */
type SortDir = 'asc' | 'desc'
type Col = {
  id: string
  header: string
  cls?: string
  accessor: (o: Org) => string | number
  sortable: boolean
}
const COLS: Col[] = [
  { id: 'org', header: 'org', accessor: (o) => o.name.toLowerCase(), sortable: true },
  { id: 'stage', header: 'stage', cls: 'c-stage', accessor: (o) => STAGES.indexOf(o.stage), sortable: true },
  { id: 'owner', header: 'owner', cls: 'c-owner', accessor: (o) => o.owner, sortable: true },
  { id: 'touch', header: 'last touch', cls: 'c-touch', accessor: (o) => `${o.touch.date} ${o.touch.time}`, sortable: true },
  { id: 'claims', header: 'claims', cls: 'c-claims', accessor: (o) => o.claims, sortable: true },
  { id: 'watch', header: '', cls: 'c-watch', accessor: () => 0, sortable: false },
]

/* ══ the page ══ */
function Orgs() {
  const [sel, setSel] = React.useState<string | null>('hokuei-foods')
  const [page, setPage] = React.useState<string | null>(null)
  const [filter, setFilter] = React.useState<Filter>('all')
  const [stageFilter, setStageFilter] = React.useState<Stage | 'all'>('all')
  const [q, setQ] = React.useState('')
  const [sort, setSort] = React.useState<{ id: string; dir: SortDir } | null>(null)
  const [hintOpen, setHintOpen] = React.useState(false)
  const [watched, setWatched] = React.useState<Set<string>>(() => new Set(WATCHED_AT_LOAD))
  /* the pipeline chooser moves an org: stage overrides live here so the
     ledger, the dossier and the page agree */
  const [stages, setStages] = React.useState<Record<string, Stage>>({})
  /* the next-step acts settle in place, per org: the verb cools into a receipt */
  const [settled, setSettled] = React.useState<Record<string, { drafted?: boolean; booked?: boolean }>>({})
  /* a checked task stays checked after you leave the page and come back */
  const [done, setDone] = React.useState<Set<string>>(() => new Set())
  const rowRefs = React.useRef<Record<string, HTMLTableRowElement | null>>({})

  const stageOf = (o: Org): Stage => stages[o.id] ?? o.stage

  const select = (id: string) => {
    setSel((cur) => (cur === id ? null : id))
    cue('toggle')
  }
  const openPage = (id: string) => {
    setSel(id)
    setPage(id)
    cue('press')
  }
  const back = () => {
    setPage(null)
    cue('toggle')
    /* the row keeps focus so ↑/↓ carries on where it left off */
    requestAnimationFrame(() => rowRefs.current[sel ?? '']?.focus())
  }

  /* closing the dossier hands focus back to its row */
  const closeDossier = () => {
    const id = sel
    setSel(null)
    requestAnimationFrame(() => rowRefs.current[id ?? '']?.focus())
  }

  /* esc closes what you opened, innermost first: the page, then the
     search, then the selection (the chooser handles its own esc) */
  useEscape(() => {
    if (page) {
      back()
      return
    }
    if (q) {
      setQ('')
      return
    }
    closeDossier()
  })

  const onRowClick = (id: string) => (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest('a, button')) return
    select(id)
  }
  const toggleWatch = (id: string) => (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    markCued(e)
    setWatched((cur) => {
      const next = new Set(cur)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
    cue(watched.has(id) ? 'press' : 'success')
  }
  const settle = (id: string, key: 'drafted' | 'booked') => (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setSettled((cur) => ({ ...cur, [id]: { ...cur[id], [key]: true } }))
    cue('success')
  }
  const toggleTask = (id: string) => (e: React.MouseEvent) => {
    markCued(e)
    const was = done.has(id)
    setDone((cur) => {
      const next = new Set(cur)
      if (was) next.delete(id)
      else next.add(id)
      return next
    })
    cue(was ? 'toggle' : 'success')
  }
  const move = (id: string, to: Stage) => {
    setStages((cur) => ({ ...cur, [id]: to }))
    cue('success')
  }
  const pick = (f: Filter) => () => {
    setFilter(f)
    cue('toggle')
  }
  const pickStage = (s: Stage | 'all') => () => {
    setStageFilter(s)
    cue('toggle')
  }
  const cycleSort = (id: string) => () => {
    setSort((cur) => {
      if (!cur || cur.id !== id) return { id, dir: 'asc' }
      if (cur.dir === 'asc') return { id, dir: 'desc' }
      return null
    })
    cue('toggle')
  }

  const needle = q.trim().toLowerCase()
  let rows = ORGS.filter((o) =>
    filter === 'all' ? true : filter === 'watched' ? watched.has(o.id) : o.owner === 'o',
  )
  if (stageFilter !== 'all') rows = rows.filter((o) => stageOf(o) === stageFilter)
  if (needle) rows = rows.filter((o) => `${o.name} ${o.byline} ${stageOf(o)}`.toLowerCase().includes(needle))
  if (sort) {
    const col = COLS.find((c) => c.id === sort.id)
    if (col) {
      const acc = col.id === 'stage' ? (o: Org) => STAGES.indexOf(stageOf(o)) : col.accessor
      rows = [...rows].sort((a, b) => {
        const av = acc(a)
        const bv = acc(b)
        const r = av < bv ? -1 : av > bv ? 1 : 0
        return sort.dir === 'asc' ? r : -r
      })
    }
  }

  /* ↑/↓ moves the selection along the visible rows; Enter opens the page */
  const onRowKey = (id: string) => (e: React.KeyboardEvent) => {
    if ((e.target as HTMLElement).closest('a, button')) return
    const step = e.key === 'ArrowDown' ? 1 : e.key === 'ArrowUp' ? -1 : 0
    if (step || e.key === 'Home' || e.key === 'End') {
      e.preventDefault()
      const i = rows.findIndex((o) => o.id === id)
      const at =
        e.key === 'Home' ? 0 : e.key === 'End' ? rows.length - 1 : Math.min(Math.max(i + step, 0), rows.length - 1)
      const n = rows[at]
      if (n && n.id !== id) {
        setSel(n.id)
        rowRefs.current[n.id]?.focus()
        cue('toggle')
      }
    } else if (e.key === 'Enter') {
      e.preventDefault()
      openPage(id)
    } else if (e.key === ' ') {
      e.preventDefault()
      select(id)
    }
  }
  const onSearchKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown' && rows[0]) {
      e.preventDefault()
      setSel(rows[0].id)
      rowRefs.current[rows[0].id]?.focus()
    } else if (e.key === 'Enter' && rows[0]) {
      e.preventDefault()
      openPage(rows[0].id)
    }
  }

  const org = sel ? ORGS.find((o) => o.id === sel) ?? null : null
  const pageOrg = page ? ORGS.find((o) => o.id === page) ?? null : null
  /* only the stages in use get a chip; the one you picked stays, so a move
     never leaves you filtered by a chip that is gone */
  const stagesUsed = STAGES.filter((s) => s === stageFilter || ORGS.some((o) => stageOf(o) === s))

  return (
    <main className="pane orgs" id="pane">
      <div className="pane-body">
        {pageOrg ? (
          <OrgPage
            key={pageOrg.id}
            org={pageOrg}
            stage={stageOf(pageOrg)}
            watched={watched.has(pageOrg.id)}
            done={done}
            onWatch={toggleWatch(pageOrg.id)}
            onToggleTask={toggleTask}
            onMove={(s) => move(pageOrg.id, s)}
            onBack={back}
          />
        ) : (
          <>
            <div className="pane-head">
              <h1>Orgs</h1>
              <span className="pane-tools">
                <span className="meta-line" title="Antevon compiles the ledger from the vault · it re-renders when evidence changes">
                  {AS_OF}
                </span>
                <input
                  className="quick"
                  type="search"
                  value={q}
                  placeholder="search"
                  aria-label="search orgs"
                  title="type to filter · ↓ into the ledger · esc clears"
                  onChange={(e) => setQ(e.target.value)}
                  onKeyDown={onSearchKey}
                />
                <button
                  className="hint-btn"
                  aria-expanded={hintOpen}
                  aria-controls="orgs-why"
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
            <div className="dial-why" id="orgs-why" hidden={!hintOpen}>
              <span className="why-voice">
                Every org the vault knows, one line each. Click a row for the dossier. Enter opens the full record. Watch an org
                and its changes land in your inbox.
              </span>
            </div>

            {/* chrome: view filters, never a policy */}
            <div className="filters">
              <span className="set" role="group" aria-label="show">
                <span className="label">show</span>
                <button className={filter === 'all' ? 'chip on' : 'chip'} onClick={pick('all')} aria-pressed={filter === 'all'}>
                  all
                </button>
                <button
                  className={filter === 'watched' ? 'chip on' : 'chip'}
                  onClick={pick('watched')}
                  aria-pressed={filter === 'watched'}
                  title="orgs under watch · their changes land in your inbox"
                >
                  watched
                </button>
                <button className={filter === 'mine' ? 'chip on' : 'chip'} onClick={pick('mine')} aria-pressed={filter === 'mine'} title="orgs you own">
                  mine
                </button>
              </span>
              <span className="set" role="group" aria-label="stage">
                <span className="label">stage</span>
                <button className={stageFilter === 'all' ? 'chip on' : 'chip'} onClick={pickStage('all')} aria-pressed={stageFilter === 'all'}>
                  any
                </button>
                {stagesUsed.map((s) => (
                  <button key={s} className={stageFilter === s ? 'chip on' : 'chip'} onClick={pickStage(s)} aria-pressed={stageFilter === s}>
                    {s}
                  </button>
                ))}
              </span>
            </div>

            {/* ══ the ledger · a real table: sort, filter, keys ══ */}
            <div className="ledger-wrap">
              {/* role=grid: the rows take focus, carry a selected state and
                  unfold, which a plain table role cannot say */}
              <table className="ledger" role="grid" aria-label="orgs">
                <thead>
                  <tr>
                    {COLS.map((c) => {
                      const on = sort?.id === c.id
                      const dir = on ? sort!.dir : null
                      return (
                        <th
                          key={c.id}
                          className={c.cls}
                          aria-sort={!c.sortable ? undefined : on ? (dir === 'asc' ? 'ascending' : 'descending') : 'none'}
                        >
                          {c.sortable ? (
                            <button
                              className={on ? 'sort on' : 'sort'}
                              type="button"
                              onClick={cycleSort(c.id)}
                              title={on ? (dir === 'asc' ? 'sorted ↑ · click for ↓' : 'sorted ↓ · click to clear') : `sort by ${c.header}`}
                            >
                              {c.header}
                              <span className="arrow" aria-hidden="true">
                                {dir === 'asc' ? '↑' : dir === 'desc' ? '↓' : ''}
                              </span>
                            </button>
                          ) : (
                            <span className="sr">watch</span>
                          )}
                        </th>
                      )
                    })}
                  </tr>
                </thead>
                <tbody>
                  {rows.map((o) => {
                    const on = watched.has(o.id)
                    const isSel = sel === o.id
                    const st = stageOf(o)
                    return (
                      <React.Fragment key={o.id}>
                        <tr
                          ref={(el) => {
                            rowRefs.current[o.id] = el
                          }}
                          className={isSel ? 'selected' : undefined}
                          tabIndex={0}
                          aria-selected={isSel}
                          aria-expanded={isSel}
                          aria-controls={isSel ? `glance-${o.id}` : undefined}
                          onClick={onRowClick(o.id)}
                          onKeyDown={onRowKey(o.id)}
                        >
                          <td>
                            <span className="org-name">{o.name}</span>
                          </td>
                          <td className="c-stage">
                            <Link className="stage" to="/app/pipeline" title={`pipeline · ${st}`}>
                              {st}
                            </Link>
                          </td>
                          <td className="c-owner">
                            <span className="seal seal-human" title={OWNER_TIP[o.owner]}>
                              {o.owner}
                            </span>
                          </td>
                          <td className="c-touch">
                            <span className={o.touch.date === TODAY ? 'touch today' : 'touch'} title={o.touch.tip}>
                              {o.touch.date}
                            </span>
                          </td>
                          <td className="c-claims">
                            <Link className="count" to="/app/vault" title={`the vault, filtered to ${o.name}`}>
                              {o.claims}
                            </Link>
                          </td>
                          <td className="c-watch">
                            <button
                              className={on ? 'watch on' : 'watch'}
                              aria-pressed={on}
                              aria-label={on ? `stop watching ${o.name}` : `watch ${o.name}`}
                              title={on ? 'watching · click to stop' : 'watch this org · its changes land in your inbox'}
                              onClick={toggleWatch(o.id)}
                            />
                          </td>
                        </tr>
                        {/* the under-glance (rule 7): the next step + doors, under the row */}
                        {isSel && (
                          <tr className="glance-row" id={`glance-${o.id}`} aria-label={`${o.name} · glance`}>
                            <td colSpan={COLS.length}>
                              <div className="glance">
                                <span className="glance-line">{o.next.line}</span>
                                <span className="glance-acts">
                                  <button className="act" type="button" title="the full record · enter" onClick={() => openPage(o.id)}>
                                    page
                                  </button>
                                  <Link className="act" to="/app/threads" title={`threads · ${o.name}`}>
                                    thread
                                  </Link>
                                  <Link className="act" to="/app/pipeline" title={`pipeline · ${st} · ${o.name}`}>
                                    pipeline
                                  </Link>
                                </span>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    )
                  })}
                </tbody>
              </table>
              {rows.length === 0 && (
                <div className="ledger-empty">
                  {needle
                    ? 'No org matches that.'
                    : stageFilter !== 'all'
                      ? 'No org at that stage.'
                      : filter === 'watched'
                        ? 'No org under watch yet.'
                        : 'No org of yours yet.'}
                </div>
              )}
            </div>
          </>
        )}
      </div>

      {/* ── the dossier: the glance you READ, in the column; the page is the record ── */}
      <aside className="context" hidden={!org || !!pageOrg} aria-label="the dossier">
        {org && !pageOrg ? (
          <Dossier
            key={org.id}
            org={org}
            stage={stageOf(org)}
            watched={watched.has(org.id)}
            settled={settled[org.id] ?? {}}
            onWatch={toggleWatch(org.id)}
            onSettle={(k) => settle(org.id, k)}
            onPage={() => openPage(org.id)}
            onClose={() => {
              closeDossier()
              cue('toggle')
            }}
          />
        ) : null}
      </aside>
    </main>
  )
}

/* ── small atoms shared by the dossier and the page ── */
function ChanGlyph({ chan }: { chan: Chan }) {
  const tip = CHAN_TIP[chan]
  return (
    <span className={`w-chan chan-${chan}`} title={tip} role="img" aria-label={tip}>
      {chan === 'line' && <ChanLine />}
      {chan === 'mail' && <ChanMail />}
      {chan === 'linkedin' && <ChanLinkedin />}
      {chan === 'slack' && <ChanSlack />}
      {chan === 'meeting' && (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <rect x="3" y="5" width="18" height="16" rx="2" />
          <path d="M3 10h18M8 3v4M16 3v4" />
        </svg>
      )}
      {chan === 'research' && (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <circle cx="11" cy="11" r="6" />
          <path d="m20 20-4.5-4.5" />
        </svg>
      )}
    </span>
  )
}

const AGENT_NAME = { eiri: 'Eiri', tory: 'Tory', antevon: 'Antevon' } as const

function WhoMark({ who }: { who: Who }) {
  if ('agent' in who) {
    return (
      <span className="aname" data-agent={who.agent} title={who.tip}>
        {AGENT_NAME[who.agent]}
      </span>
    )
  }
  return (
    <span className={who.cls ? 'seal seal-human seal-class' : 'seal seal-human'} title={who.tip}>
      {who.seal}
    </span>
  )
}

/* ══ the org page · the record. replaces the ledger inside the sheet ══ */
function OrgPage({
  org,
  stage,
  watched,
  done,
  onWatch,
  onToggleTask,
  onMove,
  onBack,
}: {
  org: Org
  stage: Stage
  watched: boolean
  done: Set<string>
  onWatch: (e: React.MouseEvent) => void
  onToggleTask: (id: string) => (e: React.MouseEvent) => void
  onMove: (s: Stage) => void
  onBack: () => void
}) {
  const [choosing, setChoosing] = React.useState(false)
  const [moved, setMoved] = React.useState<{ from: Stage; to: Stage } | null>(null)
  const chooserRef = React.useRef<HTMLSpanElement | null>(null)
  const popRef = React.useRef<HTMLDivElement | null>(null)
  const triggerRef = React.useRef<HTMLButtonElement | null>(null)

  /* the chooser closes on a click outside it */
  React.useEffect(() => {
    if (!choosing) return
    const onDown = (e: MouseEvent) => {
      if (!chooserRef.current?.contains(e.target as Node)) setChoosing(false)
    }
    addEventListener('mousedown', onDown)
    return () => removeEventListener('mousedown', onDown)
  }, [choosing])

  /* opening lands you on the stage it holds now */
  React.useEffect(() => {
    if (!choosing) return
    const opts = popRef.current?.querySelectorAll<HTMLButtonElement>('.opt')
    opts?.[STAGES.indexOf(stage)]?.focus()
  }, [choosing, stage])

  const shut = () => {
    setChoosing(false)
    triggerRef.current?.focus()
  }
  /* esc closes the chooser, not the page: it is the thing you opened last */
  const onChooserKey = (e: React.KeyboardEvent) => {
    if (!choosing) return
    if (e.key === 'Escape') {
      e.stopPropagation()
      e.preventDefault()
      shut()
      cue('toggle')
      return
    }
    const opts = Array.from(popRef.current?.querySelectorAll<HTMLButtonElement>('.opt') ?? [])
    if (opts.length === 0) return
    const i = opts.indexOf(document.activeElement as HTMLButtonElement)
    const step = e.key === 'ArrowDown' ? 1 : e.key === 'ArrowUp' ? -1 : 0
    if (!step && e.key !== 'Home' && e.key !== 'End') return
    e.preventDefault()
    const at =
      e.key === 'Home' ? 0 : e.key === 'End' ? opts.length - 1 : Math.min(Math.max(i + step, 0), opts.length - 1)
    opts[at]?.focus()
  }

  const choose = (s: Stage) => (e: React.MouseEvent) => {
    markCued(e)
    shut()
    if (s === stage) return
    setMoved({ from: stage, to: s })
    onMove(s)
  }
  const holder = org.owner === 'o' ? 'you' : 'Yuki'
  const touches = org.timeline.slice(0, 8)

  /* the record takes focus when it lands, so tab and esc carry on here */
  const pageRef = React.useRef<HTMLElement | null>(null)
  React.useEffect(() => {
    pageRef.current?.focus()
  }, [])

  return (
    <article className="opage" ref={pageRef} tabIndex={-1} aria-label={`${org.name} · the record`}>
      <div className="opage-nav">
        <button className="act back" type="button" title="the ledger · esc" onClick={onBack}>
          back
        </button>
      </div>
      <header className="opage-head">
        <div className="opage-title">
          <h1 className="opage-name">{org.name}</h1>
          <Link className="stage-chip" to="/app/pipeline" title={`pipeline · ${stage}`}>
            {stage}
          </Link>
          <span className="money" title={org.moneyTip}>
            {org.money}
          </span>
        </div>
        <span className="meta-line" title="Antevon compiles the record from the vault · it re-renders when evidence changes">
          {AS_OF}
        </span>
        <span className="opage-byline">{org.byline}</span>
      </header>

      <div className="opage-grid">
        {/* people */}
        <section className="osec" aria-label="people">
          <span className="label">people</span>
          {org.people.length === 0 && <span className="oline quiet">No one on record yet.</span>}
          {org.people.map((p) => {
            const [name, role] = p.line.split(' · ')
            return (
              <div className="prow" key={p.seal + p.line}>
                <span className="seal seal-human seal-class" title={p.tip}>
                  {p.seal}
                </span>
                <span className={`pname conf-${p.conf}`}>{name}</span>
                <span className="prole">{role}</span>
                <span className="pchans">
                  {p.chans.map((c) => (
                    <ChanGlyph key={c} chan={c} />
                  ))}
                </span>
                {p.door && (
                  <Link className="act quiet" to={p.door.href} title={p.door.tip}>
                    {p.door.text}
                  </Link>
                )}
              </div>
            )
          })}
        </section>

        {/* pipeline */}
        <section className="osec" aria-label="pipeline">
          <span className="label">pipeline</span>
          <div className="pipe">
            <div className="pipe-row">
              <span className="pipe-k">stage</span>
              <span className="pipe-v">
                {/* the head chip is the door to the board; here the stage is
                    only the fact the chooser moves */}
                <span className="stage-chip">{stage}</span>
                <span className="chooser" ref={chooserRef} onKeyDown={onChooserKey}>
                  <button
                    className="act"
                    type="button"
                    ref={triggerRef}
                    aria-expanded={choosing}
                    aria-haspopup="listbox"
                    title="move this org to another stage"
                    onClick={(e) => {
                      markCued(e)
                      setChoosing((c) => !c)
                      cue('toggle')
                    }}
                  >
                    move to …
                  </button>
                  {choosing && (
                    <div className="chooser-pop" role="listbox" aria-label="stage" ref={popRef}>
                      {STAGES.map((s) => (
                        <button
                          key={s}
                          type="button"
                          role="option"
                          aria-selected={s === stage}
                          className={s === stage ? 'opt on' : 'opt'}
                          onClick={choose(s)}
                        >
                          {s}
                        </button>
                      ))}
                    </div>
                  )}
                </span>
              </span>
            </div>
            <div className="pipe-row">
              <span className="pipe-k">next step</span>
              <span className="pipe-v">
                <span className="oline">{org.next.line}</span>
                <span className="when" title={`due ${org.next.when}`}>
                  {org.next.when}
                </span>
              </span>
            </div>
            <div className="pipe-row">
              <span className="pipe-k">holder</span>
              <span className="pipe-v">
                <span className="seal seal-human" title={OWNER_TIP[org.owner]}>
                  {org.owner}
                </span>
                <span className="oline">{holder}</span>
              </span>
            </div>
            {moved && (
              <span className="receipt" title="the pipeline board moved it too">
                moved · {moved.from} → {moved.to}
              </span>
            )}
          </div>
        </section>

        {/* timeline · the last 8 touches */}
        <section className="osec wide" aria-label="timeline">
          <span className="label">timeline</span>
          <ol className="tl">
            {touches.map((t, i) => (
              <li className="tl-row" key={i}>
                <span className="when">{t.when}</span>
                <ChanGlyph chan={t.chan} />
                <span className="tl-who">
                  <WhoMark who={t.who} />
                </span>
                <span className="oline" lang={t.lang}>
                  {t.what}
                </span>
              </li>
            ))}
          </ol>
        </section>

        {/* claims · the ledger rows the vault holds about this org */}
        <section className="osec wide" aria-label="claims about this org">
          <span className="label">claims about this org</span>
          <div className="claims">
            {org.know.map((c) => (
              <div className="crow" key={c.text}>
                <span className={DOT[c.state].cls} title={DOT[c.state].tip}></span>
                <Link className={`oline conf-${c.conf}`} to="/app/vault" title={c.tip}>
                  {c.text}
                </Link>
                <span className="cconf" title={`confidence ${c.score}`}>
                  {c.score}
                </span>
                <span className="csrc" title="the source">
                  {c.source}
                </span>
              </div>
            ))}
          </div>
          <Link className="act" to="/app/vault" title={`the vault, filtered to ${org.name} · ${org.claims} claims`}>
            open in vault
          </Link>
        </section>

        {/* threads */}
        <section className="osec" aria-label="threads">
          <span className="label">threads</span>
          {org.threads.length === 0 && <span className="oline quiet">No thread yet.</span>}
          {org.threads.map((t, i) => (
            <Link className="trow" to="/app/threads" key={i} title={`threads · ${org.name} · ${CHAN_TIP[t.chan]} · ${t.when}`}>
              <ChanGlyph chan={t.chan} />
              <span className="twith">{t.with}</span>
              <span className="tlast" lang={t.lang}>
                {t.last}
              </span>
              <span className="when">{t.when}</span>
            </Link>
          ))}
        </section>

        {/* briefs */}
        <section className="osec" aria-label="briefs">
          <span className="label">briefs</span>
          {org.briefs.length === 0 && <span className="oline quiet">No brief yet.</span>}
          {org.briefs.map((b, i) => (
            <Link className="bfrow" to="/app/briefs" key={i} title={`briefs · ${b.title} · ${b.when}`}>
              <span className="oline">{b.title}</span>
              <span className="bby">
                <WhoMark who={b.by} />
              </span>
              <span className="when">{b.when}</span>
            </Link>
          ))}
        </section>

        {/* tasks · bullets as the tasks page draws them */}
        <section className="osec wide" aria-label="tasks">
          <span className="label">tasks</span>
          {org.tasks.map((t) => {
            const isDone = done.has(t.id)
            const proposed = 'agent' in t.who
            return (
              <div className={isDone ? 'task-row done' : 'task-row'} key={t.id}>
                <button
                  className={isDone ? 'tbul done' : proposed ? 'tbul proposed' : 'tbul mine'}
                  type="button"
                  aria-pressed={isDone}
                  aria-label={isDone ? `done · ${t.text}` : `mark done · ${t.text}`}
                  title={isDone ? 'done · click to reopen' : proposed ? 'proposed by an agent · click when done' : 'yours · click when done'}
                  onClick={onToggleTask(t.id)}
                >
                  {isDone && (
                    <svg viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <path d="M2 6.5 4.8 9.2 10 3.4" />
                    </svg>
                  )}
                </button>
                <span className="task">{t.text}</span>
                <span className="twho">
                  <WhoMark who={t.who} />
                </span>
                <span className="when">{t.due}</span>
              </div>
            )
          })}
          <Link className="act" to="/app/tasks" title={`tasks · ${org.name}`}>
            all tasks
          </Link>
        </section>
      </div>

      <div className="opage-foot">
        {watched ? (
          <>
            <span className="receipt">watching · changes land in your inbox</span>
            <button className="act" type="button" title="stop watching this org" onClick={onWatch}>
              stop
            </button>
          </>
        ) : (
          <button className="act" type="button" title="verb: watch_org · a saved query · changes land in your inbox" onClick={onWatch}>
            watch this org
          </button>
        )}
      </div>
    </article>
  )
}

/* ══ the dossier · a calm printed record, the glance ══ */
function Dossier({
  org,
  stage,
  watched,
  settled,
  onWatch,
  onSettle,
  onPage,
  onClose,
}: {
  org: Org
  stage: Stage
  watched: boolean
  settled: { drafted?: boolean; booked?: boolean }
  onWatch: (e: React.MouseEvent) => void
  onSettle: (k: 'drafted' | 'booked') => (e: React.MouseEvent) => void
  onPage: () => void
  onClose: () => void
}) {
  const crumb = `orgs · ${org.name.toLowerCase()}`
  return (
    <>
      <div className="ctx-head">
        <span className="ctx-crumb" title={`${AS_OF} · compiled from the vault`}>
          {crumb}
        </span>
        <button className="act" type="button" title="the full record · enter" onClick={onPage}>
          page
        </button>
        <button className="chat-close" aria-label="close the dossier" title="close · esc" onClick={onClose}>
          ×
        </button>
      </div>
      <div className="dhead">
        <div className="ctx-title">{org.name}</div>
        <div className="ctx-byline">{org.byline}</div>
      </div>

      {/* people */}
      <section className="dsec" aria-label="people">
        <span className="label">people</span>
        {org.people.length === 0 && <span className="dline quiet">No one on record yet.</span>}
        {org.people.map((p) => (
          <div className="drow" key={p.seal + p.line}>
            <span className="seal seal-human seal-class" title={p.tip}>
              {p.seal}
            </span>
            <span className="dstack">
              <span className={`dline conf-${p.conf}`}>{p.line}</span>
              {p.door && (
                <Link className="act quiet" to={p.door.href} title={p.door.tip}>
                  {p.door.text}
                </Link>
              )}
            </span>
          </div>
        ))}
      </section>

      {/* what we know · every claim is a door to the vault */}
      <section className="dsec" aria-label="what we know">
        <span className="label">what we know</span>
        {org.know.map((c) => (
          <div className="drow" key={c.text}>
            <span className={DOT[c.state].cls} title={DOT[c.state].tip}></span>
            <Link className={`dline conf-${c.conf}`} to="/app/vault" title={c.tip}>
              {c.text}
            </Link>
          </div>
        ))}
        <Link className="act" to="/app/vault" title={`the vault, filtered to ${org.name}`}>
          all {org.claims} claims
        </Link>
      </section>

      {/* the thread · seal or name, the line; time and channel ride the tooltip */}
      <section className="dsec" aria-label="the thread">
        <span className="label">the thread</span>
        {org.thread.map((t, i) => (
          <div className="drow" key={i}>
            {t.kind === 'human' ? (
              <span className={t.cls ? 'seal seal-human seal-class' : 'seal seal-human'} title={t.tip}>
                {t.seal}
              </span>
            ) : (
              <span className="aname" data-agent={t.agent} title={t.tip}>
                {t.name}
              </span>
            )}
            <span className={`dline conf-${t.conf}`} lang={t.kind === 'human' ? t.lang : undefined}>
              {t.msg}
            </span>
          </div>
        ))}
        <Link className="act" to="/app/threads" title={`threads · ${org.name} · every channel`}>
          the thread
        </Link>
      </section>

      {/* next step · the acts settle in place */}
      <section className="dsec" aria-label="next step">
        <span className="label">next step</span>
        <span className="dnext">{org.next.line}</span>
        <div className="dacts">
          {org.next.draft && !settled.drafted && (
            <button
              className="act"
              type="button"
              title="verb: draft_message · Eiri drafts · the send stays your click"
              onClick={onSettle('drafted')}
            >
              {org.next.draft}
            </button>
          )}
          {org.next.book && !settled.booked && (
            <button className="act" type="button" title="verb: book_call · Eiri offers slots on the thread" onClick={onSettle('booked')}>
              book the call
            </button>
          )}
          <Link className="act" to="/app/pipeline" title={`pipeline · ${stage} · ${org.name}`}>
            open in pipeline
          </Link>
        </div>
        {(settled.drafted || settled.booked) && (
          <div className="receipts">
            {settled.drafted && (
              <span className="receipt">
                <span className="aname" data-agent="eiri" title="Eiri · outbound · the draft waits for your click">
                  Eiri
                </span>
                <span>is drafting · lands in your inbox</span>
              </span>
            )}
            {settled.booked && (
              <span className="receipt">
                <span className="aname" data-agent="eiri" title="Eiri · outbound · two slots go out on the thread">
                  Eiri
                </span>
                <span>is booking · slots go out on the thread</span>
              </span>
            )}
          </div>
        )}
      </section>

      {/* notes · doors to the notes lens */}
      {org.notes.length > 0 && (
        <section className="dsec" aria-label="notes">
          <span className="label">notes</span>
          {org.notes.map((n) => (
            <div className="drow" key={n.title}>
              <Link className="dline conf-2" to="/app/notes" title={n.tip}>
                {n.title}
              </Link>
            </div>
          ))}
        </section>
      )}

      {/* the foot act cools into its state */}
      <div className="dfoot">
        {watched ? (
          <>
            <span className="receipt">watching · changes land in your inbox</span>
            <button className="act" type="button" title="stop watching this org" onClick={onWatch}>
              stop
            </button>
          </>
        ) : (
          <button className="act" type="button" title="verb: watch_org · a saved query · changes land in your inbox" onClick={onWatch}>
            watch this org
          </button>
        )}
      </div>
    </>
  )
}
