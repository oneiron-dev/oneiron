/* Inbox-only local previews. No engine receipts, wall clock, or persistence. */
export const FIXTURE_CLOCK = 'fixture 14:09'

const OUTCOMES = {
  accept: { ok: true, word: 'accepted locally' },
  reject: { ok: false, word: 'rejected locally' },
  send: { ok: true, word: 'previewed · not sent' },
  allow: { ok: true, word: 'allowed locally · not sent' },
  grant: { ok: true, word: 'previewed · no grant created' },
  deny: { ok: false, word: 'denied locally' },
  discard: { ok: false, word: 'discarded locally · run unchanged' },
} as const

export type FixtureAction = keyof typeof OUTCOMES
export type FixtureReceipt = {
  action: FixtureAction
  ok: boolean
  word: string
  clock: typeof FIXTURE_CLOCK
}

export function settleFixture(
  current: FixtureReceipt | null,
  action: FixtureAction,
): FixtureReceipt {
  return current ?? { action, ...OUTCOMES[action], clock: FIXTURE_CLOCK }
}

export type ReplyPreview = { text: string; clock: typeof FIXTURE_CLOCK }
export type ReplyKey = {
  key: string
  isComposing?: boolean
  keyCode?: number
  repeat?: boolean
  metaKey?: boolean
  ctrlKey?: boolean
  altKey?: boolean
  shiftKey?: boolean
}

export function previewReply(
  current: ReplyPreview | null,
  value: string,
  event: ReplyKey,
): ReplyPreview | null {
  const text = value.trim()
  if (
    event.key !== 'Enter' || event.isComposing || event.keyCode === 229 || event.repeat ||
    event.metaKey || event.ctrlKey || event.altKey || event.shiftKey ||
    !text || current?.text === text
  ) return current
  return { text, clock: FIXTURE_CLOCK }
}
