import * as React from 'react'
import { Figure } from '../primitives/Figure'
import { Icon } from '../primitives/Icon'
import { IconAction } from '../primitives/IconAction'
import { InfoMark } from '../primitives/InfoMark'
import { Verb } from '../primitives/Verb'
import { Tooltip } from '../overlays/Tooltip'
import { PickDiamond } from '../marks/PickDiamond'
import { soundPress } from '../lib/press'
import { cx, mergeRefs, useControllableState, useIsomorphicLayoutEffect, useSafeId } from '../lib/react-utils'
import { pushPendingUndo } from '../lib/pending-undo'
import { SETTLE_OPEN, settleReducer } from './settle-reducer'
import { formatAnswerTime } from './answer-time'

/* How long an answer can be undone before it stands. */
export const NEEDS_YOU_UNDO_MS = 5000
/* Outside a block, how long a settled answer takes to fold away (matches
   the CSS of the part around it). */
const FOLD_MS = 260

const prefersReducedMotion = () =>
  typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches

/* The mark an answer leaves in its record: a filled diamond for a pick or
   an own answer, a check or a cross for yes or no, a clock for later. */
export type NeedsYouAnswerMark = 'pick' | 'check' | 'cross' | 'later'

/* How the answers are drawn: tone chips, or plain marks and words. */
export type NeedsYouAnswers = 'chips' | 'plain'

/* One answer, as its record line shows it. */
export interface NeedsYouAnswerRecord {
  value: string
  /* The answer's word in the record: `promo weeks`, `approved`. */
  word: string
  mark: NeedsYouAnswerMark
  /* When it was given, as a figure: `09:14`. */
  time: string
}

/* ── the answer scope: what the answers line reads ───────────────────────── */

type AnswerStatus = 'open' | 'pending' | 'settled'

interface AnswerScopeValue {
  status: AnswerStatus
  record: NeedsYouAnswerRecord | null
  answerWith: (value: string, word: string, mark: NeedsYouAnswerMark) => void
  later: () => void
  undo: () => void
  answers: NeedsYouAnswers
  /* Outside an ask the answers line draws the answered state itself; in
     an ask the whole row becomes the record line. */
  drawsRecord: boolean
}

const AnswerScope = React.createContext<AnswerScopeValue | null>(null)

function useAnswerScope(part: string): AnswerScopeValue {
  const ctx = React.useContext(AnswerScope)
  if (!ctx) throw new Error(`${part} must be inside NeedsYou.Ask or NeedsYou.Answer`)
  return ctx
}

/* The state of the answer around a part: null outside an ask or answer. */
export function useNeedsYouAnswerStatus(): AnswerStatus | null {
  return React.useContext(AnswerScope)?.status ?? null
}

/* ── the block ──────────────────────────────────────────────────────────── */

interface BlockValue {
  answers: NeedsYouAnswers
  undoWindowMs: number
  /* The latest callbacks of the block. */
  latest: React.RefObject<Pick<NeedsYouProps, 'onAnswerChange' | 'onSettle' | 'onLater'>>
}

const BlockContext = React.createContext<BlockValue | null>(null)

export interface NeedsYouProps extends Omit<React.ComponentPropsWithRef<'section'>, 'onChange'> {
  /* `chips` draws each answer as a tone chip; `plain` as a mark and a word. */
  answers?: NeedsYouAnswers
  /* An ask was answered (a record) or its answer undone (null), in the
     same frame: whatever asked changes at once. */
  onAnswerChange?: (id: string, answer: NeedsYouAnswerRecord | null) => void
  /* An answer stood through its undo window. */
  onSettle?: (id: string, value: string) => void
  /* An ask was set aside with `later`. */
  onLater?: (id: string) => void
  undoWindowMs?: number
  /* `well` is the raised block in a room; `bare` sits on a popover or a desk. */
  ground?: 'well' | 'bare'
}

/* Everything that waits on the person, in one block: NeedsYou.Group per
   room, NeedsYou.Ask per ask. Every ask shows its answers; an answer turns
   its row into one record line that stays in the block, with `undo` for
   the undo window. Nothing else in the block moves when a row changes
   state except the rows under it. The block is what an InfoMark in it
   measures against. */
function NeedsYouRoot({
  answers = 'chips',
  onAnswerChange,
  onSettle,
  onLater,
  undoWindowMs = NEEDS_YOU_UNDO_MS,
  ground = 'well',
  className,
  children,
  'aria-label': ariaLabel = 'needs you',
  ...props
}: NeedsYouProps) {
  const latest = React.useRef({ onAnswerChange, onSettle, onLater })
  useIsomorphicLayoutEffect(() => {
    latest.current = { onAnswerChange, onSettle, onLater }
  })
  const ctx = React.useMemo(() => ({ answers, undoWindowMs, latest }), [answers, undoWindowMs])
  return (
    <BlockContext.Provider value={ctx}>
      <section
        aria-label={ariaLabel}
        className={cx('sl-needs-you', className)}
        data-ground={ground}
        data-answers={answers}
        data-info-block=""
        {...props}
      >
        {children}
      </section>
    </BlockContext.Provider>
  )
}

export interface NeedsYouGroupProps extends React.ComponentPropsWithRef<'div'> {
  /* The room the asks come from, without the hash symbol. */
  room: React.ReactNode
}

/* The asks from one room, under a quiet label naming it. A hairline
   separates one group from the next. */
function NeedsYouGroup({ room, className, children, ...props }: NeedsYouGroupProps) {
  const labelId = useSafeId('sl-needs-you-group')
  return (
    <div role="group" aria-labelledby={labelId} className={cx('sl-needs-you-group', className)} {...props}>
      <p id={labelId} className="sl-needs-you-group-label">
        # {room}
      </p>
      {children}
    </div>
  )
}

/* ── one ask ────────────────────────────────────────────────────────────── */

export interface NeedsYouAskProps extends Omit<React.ComponentPropsWithRef<'div'>, 'id'> {
  id: string
  /* The asker's portrait: a Glyph at 20 px. */
  asker?: React.ReactNode
  /* The ask, one serif line; it wraps when it must. */
  question: React.ReactNode
  /* The short note of the information mark at the right of the first
     line. Without a note the mark does not show. */
  note?: React.ReactNode
  /* Pressing the information mark: the caller opens the ask beside the
     room. */
  onOpen?: () => void
  noteLabel?: string
  /* The answer given, or null. A given answer shows as the record line;
     one answered here can be undone for the undo window. */
  answer?: NeedsYouAnswerRecord | null
  defaultAnswer?: NeedsYouAnswerRecord | null
  onAnswerChange?: (answer: NeedsYouAnswerRecord | null) => void
  /* Set aside with `later`: one line with the ask, `set aside` and
     `answer now`. */
  setAside?: boolean
  defaultSetAside?: boolean
  onSetAsideChange?: (setAside: boolean) => void
}

/* One ask, one skeleton. Line 1: the asker's portrait, the ask, and at the
   right `later` (a clock) and the information mark. Line 2: the answers
   (NeedsYou.Picks or NeedsYou.YesNo). */
function NeedsYouAsk({
  ref,
  id,
  asker,
  question,
  note,
  onOpen,
  noteLabel,
  answer: answerProp,
  defaultAnswer = null,
  onAnswerChange,
  setAside: setAsideProp,
  defaultSetAside = false,
  onSetAsideChange,
  className,
  children,
  ...props
}: NeedsYouAskProps) {
  const block = React.useContext(BlockContext)
  const [record, setRecord] = useControllableState<NeedsYouAnswerRecord | null>(answerProp, defaultAnswer, onAnswerChange)
  const [aside, setAside] = useControllableState(setAsideProp, defaultSetAside, onSetAsideChange)
  /* The answer was given here and its undo window is open. */
  const [pending, setPending] = React.useState(false)
  const undoWindowMs = block?.undoWindowMs ?? NEEDS_YOU_UNDO_MS
  const rowRef = React.useRef<HTMLDivElement | null>(null)
  /* Where focus goes once the row has changed form. */
  const focusAfter = React.useRef<'undo' | 'first-answer' | 'answer-now' | 'next' | null>(null)

  const focusWasHere = () => {
    const active = document.activeElement
    return !active || active === document.body || !!rowRef.current?.contains(active)
  }

  const answerWith = React.useCallback(
    (value: string, word: string, mark: NeedsYouAnswerMark) => {
      const next = { value, word, mark, time: formatAnswerTime(new Date()) }
      if (focusWasHere()) focusAfter.current = 'undo'
      setRecord(next)
      setPending(true)
      block?.latest.current.onAnswerChange?.(id, next)
    },
    [block, id, setRecord],
  )
  const undo = React.useCallback(() => {
    if (focusWasHere()) focusAfter.current = 'first-answer'
    setPending(false)
    setRecord(null)
    block?.latest.current.onAnswerChange?.(id, null)
  }, [block, id, setRecord])
  const later = React.useCallback(() => {
    if (focusWasHere()) focusAfter.current = 'answer-now'
    setAside(true)
    block?.latest.current.onLater?.(id)
  }, [block, id, setAside])

  /* The undo window: Escape or `undo` restores; when it ends the answer
     stands and the block hears of it. */
  React.useEffect(() => {
    if (!pending || !record) return
    const release = pushPendingUndo(undo)
    const value = record.value
    const timer = setTimeout(() => {
      if (rowRef.current?.contains(document.activeElement)) focusAfter.current = 'next'
      setPending(false)
      block?.latest.current.onSettle?.(id, value)
    }, undoWindowMs)
    return () => {
      clearTimeout(timer)
      release()
    }
  }, [pending, record, undo, undoWindowMs, block, id])

  /* An answer that arrives from outside (controlled) is not undoable. */
  React.useEffect(() => {
    if (!record) setPending(false)
  }, [record])

  React.useEffect(() => {
    const target = focusAfter.current
    if (!target) return
    focusAfter.current = null
    const row = rowRef.current
    requestAnimationFrame(() => {
      if (!row) return
      let el: HTMLElement | null = null
      if (target === 'undo') el = row.querySelector<HTMLElement>('.sl-needs-you-undo')
      else if (target === 'first-answer') el = row.querySelector<HTMLElement>('.sl-needs-you-answer')
      else if (target === 'answer-now') el = row.querySelector<HTMLElement>('.sl-needs-you-answer-now')
      else {
        /* The next ask in the block that still waits, else this row's record. */
        const rows = [...(row.closest('.sl-needs-you')?.querySelectorAll<HTMLElement>('.sl-needs-you-ask') ?? [])]
        const after = rows.slice(rows.indexOf(row) + 1).concat(rows.slice(0, rows.indexOf(row)))
        el = after.filter((r) => r.dataset.state === 'open').map((r) => r.querySelector<HTMLElement>('.sl-needs-you-answer')).find(Boolean) ?? null
      }
      el?.focus({ preventScroll: true })
    })
  }, [record, aside, pending])

  const status: AnswerStatus = record ? (pending ? 'pending' : 'settled') : 'open'
  const scope = React.useMemo<AnswerScopeValue>(
    () => ({ status, record, answerWith, later, undo, answers: block?.answers ?? 'chips', drawsRecord: false }),
    [status, record, answerWith, later, undo, block],
  )

  const state = aside ? 'aside' : record ? 'answered' : 'open'

  let body: React.ReactNode
  if (aside) {
    body = (
      <div className="sl-needs-you-aside">
        <span className="sl-needs-you-record-ask">{question}</span>
        <span className="sl-needs-you-aside-state">set aside</span>
        <Verb
          className="sl-needs-you-answer-now"
          onClick={() => {
            focusAfter.current = 'first-answer'
            setAside(false)
          }}
        >
          answer now
        </Verb>
      </div>
    )
  } else if (record) {
    body = (
      <div className="sl-needs-you-record" role="status">
        {asker !== undefined ? <span className="sl-needs-you-asker">{asker}</span> : null}
        <span className="sl-needs-you-record-ask">{question}</span>
        <RecordWords record={record} />
        {pending ? (
          <Verb className="sl-needs-you-undo" onClick={undo}>
            undo
          </Verb>
        ) : null}
      </div>
    )
  } else {
    body = (
      <>
        <div className="sl-needs-you-line">
          {asker !== undefined ? <span className="sl-needs-you-asker">{asker}</span> : null}
          <span className="sl-needs-you-question">{question}</span>
          <IconAction label="Later" className="sl-needs-you-later" onClick={later}>
            <Icon name="clock" />
          </IconAction>
          {note !== undefined ? <InfoMark note={note} onOpen={onOpen} label={noteLabel} /> : null}
        </div>
        {children}
      </>
    )
  }

  return (
    <AnswerScope.Provider value={scope}>
      <div
        ref={mergeRefs(ref, rowRef)}
        className={cx('sl-needs-you-ask', className)}
        data-needs-you-id={id}
        data-state={state}
        data-asker={asker !== undefined ? '' : undefined}
        {...props}
      >
        {body}
      </div>
    </AnswerScope.Provider>
  )
}

/* The mark of the answer, the answer's word and its time. */
function RecordWords({ record }: { record: NeedsYouAnswerRecord }) {
  return (
    <>
      <span className="sl-needs-you-record-mark" data-mark={record.mark} aria-hidden="true">
        {record.mark === 'check' ? (
          <Icon name="check" size={15} />
        ) : record.mark === 'cross' ? (
          <Icon name="x" size={14} />
        ) : record.mark === 'later' ? (
          <Icon name="clock" size={14} />
        ) : (
          <PickDiamond chosen />
        )}
      </span>
      <span className="sl-needs-you-record-word">{record.word}</span>
      <Figure className="sl-needs-you-record-time">{record.time}</Figure>
    </>
  )
}

/* ── one answer outside a block ─────────────────────────────────────────── */

export interface NeedsYouAnswerProps {
  id: string
  /* The answer stood through its undo window (after the fold). */
  onSettle?: (id: string, value: string) => void
  /* `later` stood through its undo window. */
  onLater?: (id: string) => void
  undoWindowMs?: number
  answers?: NeedsYouAnswers
  children?: React.ReactNode
}

/* One answers line outside a block (under an activity row, in a task):
   the same answers, undo window and Escape as an ask. The line itself
   shows the answer with `undo` while the window is open. Renders no
   element. */
function NeedsYouAnswer({ id, onSettle, onLater, undoWindowMs = NEEDS_YOU_UNDO_MS, answers = 'chips', children }: NeedsYouAnswerProps) {
  const [state, dispatch] = React.useReducer(settleReducer, SETTLE_OPEN)
  const [record, setRecord] = React.useState<NeedsYouAnswerRecord | null>(null)
  const latest = React.useRef({ onSettle, onLater })
  useIsomorphicLayoutEffect(() => {
    latest.current = { onSettle, onLater }
  })

  const answerWith = React.useCallback((value: string, word: string, mark: NeedsYouAnswerMark) => {
    setRecord({ value, word, mark, time: formatAnswerTime(new Date()) })
    dispatch({ type: 'pick', value, kind: mark === 'later' ? 'later' : 'answer' })
  }, [])
  const later = React.useCallback(() => answerWith('later', 'later', 'later'), [answerWith])
  const undo = React.useCallback(() => {
    setRecord(null)
    dispatch({ type: 'undo' })
  }, [])

  React.useEffect(() => {
    if (state.status !== 'pending') return
    const release = pushPendingUndo(undo)
    const timer = setTimeout(() => dispatch({ type: 'commit' }), undoWindowMs)
    return () => {
      clearTimeout(timer)
      release()
    }
  }, [state.status, undo, undoWindowMs])

  React.useEffect(() => {
    if (state.status !== 'settled') return
    const { value, kind } = state
    const timer = setTimeout(
      () => {
        if (kind === 'later') latest.current.onLater?.(id)
        else latest.current.onSettle?.(id, value)
      },
      prefersReducedMotion() ? 0 : FOLD_MS,
    )
    return () => clearTimeout(timer)
  }, [state, id])

  const scope = React.useMemo<AnswerScopeValue>(
    () => ({ status: state.status, record, answerWith, later, undo, answers, drawsRecord: true }),
    [state.status, record, answerWith, later, undo, answers],
  )
  return <AnswerScope.Provider value={scope}>{children}</AnswerScope.Provider>
}

/* ── the answers ────────────────────────────────────────────────────────── */

interface AnswersLineProps extends React.ComponentPropsWithRef<'div'> {
  kind: 'picks' | 'yes-no'
  ownPlaceholder?: string
  own?: boolean
  onOwnChange?: (own: boolean) => void
}

/* The second line of an ask: the answers, or (outside an ask) the answer
   given with `undo`, or the field of an own answer. */
function AnswersLine({ ref, kind, ownPlaceholder = 'Your own answer', own = false, onOwnChange, className, children, ...props }: AnswersLineProps) {
  const scope = useAnswerScope(kind === 'picks' ? 'NeedsYou.Picks' : 'NeedsYou.YesNo')
  const ownField = React.useRef<HTMLInputElement | null>(null)
  const lineRef = React.useRef<HTMLDivElement | null>(null)
  const undoRef = React.useRef<HTMLButtonElement | null>(null)

  React.useEffect(() => {
    if (own) ownField.current?.focus()
  }, [own])

  /* Outside an ask: focus follows the line's change of form. */
  const previous = React.useRef(scope.status)
  React.useEffect(() => {
    if (!scope.drawsRecord) return
    const active = document.activeElement
    const focusWasHere = !active || active === document.body || !!lineRef.current?.contains(active)
    if (previous.current === 'open' && scope.status === 'pending' && focusWasHere) {
      requestAnimationFrame(() => undoRef.current?.focus({ preventScroll: true }))
    }
    if (previous.current === 'pending' && scope.status === 'open' && focusWasHere) {
      requestAnimationFrame(() => lineRef.current?.querySelector<HTMLElement>('.sl-needs-you-answer')?.focus({ preventScroll: true }))
    }
    previous.current = scope.status
  }, [scope.status, scope.drawsRecord])

  let line: React.ReactNode
  let mode: 'answers' | 'own' | 'record' = 'answers'
  if (scope.drawsRecord && scope.status !== 'open' && scope.record) {
    mode = 'record'
    line = (
      <span className="sl-needs-you-record" role="status">
        <RecordWords record={scope.record} />
        <Verb ref={undoRef} className="sl-needs-you-undo" onClick={scope.undo} disabled={scope.status === 'settled'}>
          undo
        </Verb>
      </span>
    )
  } else if (own) {
    mode = 'own'
    line = (
      <>
        <input
          ref={ownField}
          className="sl-needs-you-own"
          aria-label="your own answer"
          placeholder={ownPlaceholder}
          onKeyDown={(event) => {
            if (event.nativeEvent.isComposing) return
            const text = event.currentTarget.value.trim()
            if (event.key === 'Enter' && text) {
              event.preventDefault()
              onOwnChange?.(false)
              scope.answerWith(text, `“${text}”`, 'pick')
            } else if (event.key === 'Escape') {
              event.preventDefault()
              onOwnChange?.(false)
            }
          }}
        />
        <Verb className="sl-needs-you-own-cancel" onClick={() => onOwnChange?.(false)}>
          cancel
        </Verb>
      </>
    )
  } else {
    line = children
  }

  return (
    <div
      ref={mergeRefs(ref, lineRef)}
      role="group"
      className={cx('sl-needs-you-answers', className)}
      data-kind={kind}
      data-answers={scope.answers}
      data-mode={mode}
      {...props}
    >
      {line}
    </div>
  )
}

interface PicksValue {
  openOwn: () => void
  setOwnPlaceholder: (placeholder: string) => void
}

const PicksContext = React.createContext<PicksValue | null>(null)

export interface NeedsYouPicksProps extends React.ComponentPropsWithRef<'div'> {}

/* The options of an ask (NeedsYou.Pick), then NeedsYou.OwnAnswer. A pick
   answers at once. */
function NeedsYouPicks({ children, ...props }: NeedsYouPicksProps) {
  const [own, setOwn] = React.useState(false)
  const [ownPlaceholder, setOwnPlaceholder] = React.useState('Your own answer')
  const ctx = React.useMemo(() => ({ openOwn: () => setOwn(true), setOwnPlaceholder }), [])
  return (
    <PicksContext.Provider value={ctx}>
      <AnswersLine kind="picks" own={own} onOwnChange={setOwn} ownPlaceholder={ownPlaceholder} {...props}>
        {children}
      </AnswersLine>
    </PicksContext.Provider>
  )
}

export interface NeedsYouPickProps extends Omit<React.ComponentPropsWithRef<'button'>, 'value'> {
  value: string
  /* The answer's word in the record; the option's own words by default. */
  word?: string
}

/* One option: a tone chip, or a diamond and a word when the answers are
   plain. */
function NeedsYouPick({ value, word, className, onClick, children, type = 'button', ...props }: NeedsYouPickProps) {
  const scope = useAnswerScope('NeedsYou.Pick')
  return (
    <button
      type={type}
      className={cx('sl-needs-you-answer', className)}
      data-kind="pick"
      onClick={(event) => {
        onClick?.(event)
        if (event.defaultPrevented) return
        soundPress(event)
        scope.answerWith(value, word ?? (typeof children === 'string' ? children : value), 'pick')
      }}
      {...props}
    >
      <PickDiamond className="sl-needs-you-diamond" />
      <span>{children}</span>
    </button>
  )
}

export interface NeedsYouOwnAnswerProps extends Omit<React.ComponentPropsWithRef<'button'>, 'children'> {
  /* The field's placeholder once the pencil opens it. */
  placeholder?: string
  label?: string
}

/* The pencil chip: turns the line into a field for the person's own
   answer. Enter answers with it; Escape or `cancel` brings the options
   back. */
function NeedsYouOwnAnswer({ placeholder = 'Your own answer', label = 'Your own answer', className, onClick, type = 'button', ...props }: NeedsYouOwnAnswerProps) {
  const picks = React.useContext(PicksContext)
  if (!picks) throw new Error('NeedsYou.OwnAnswer must be inside NeedsYou.Picks')
  const { setOwnPlaceholder } = picks
  React.useEffect(() => setOwnPlaceholder(placeholder), [placeholder, setOwnPlaceholder])
  return (
    <Tooltip label={label} side="top">
      <button
        type={type}
        aria-label={label}
        className={cx('sl-needs-you-answer', className)}
        data-kind="own"
        onClick={(event) => {
          onClick?.(event)
          if (event.defaultPrevented) return
          soundPress(event)
          picks.openOwn()
        }}
        {...props}
      >
        <Icon name="pen" size={15} />
      </button>
    </Tooltip>
  )
}

export interface NeedsYouYesNoProps extends React.ComponentPropsWithRef<'div'> {
  /* What a yes costs, set as a figure on the check: `¥2,400`. */
  figure?: string
  /* The answer's word in the record for each. */
  yesWord?: string
  noWord?: string
  /* The accessible names, and the tooltips. */
  yesLabel?: string
  noLabel?: string
}

/* The answers of a yes-or-no ask: a chip with a check (it carries the
   figure when money is involved) and a chip with a cross. */
function NeedsYouYesNo({
  figure,
  yesWord = 'approved',
  noWord = 'denied',
  yesLabel = 'Approve',
  noLabel = 'Do not',
  ...props
}: NeedsYouYesNoProps) {
  const scope = useAnswerScope('NeedsYou.YesNo')
  return (
    <AnswersLine kind="yes-no" {...props}>
      <Tooltip label={yesLabel} side="top">
        <button
          type="button"
          aria-label={figure ? `${yesLabel}, ${figure}` : yesLabel}
          className="sl-needs-you-answer"
          data-kind="yes"
          onClick={(event) => {
            soundPress(event)
            scope.answerWith('yes', yesWord, 'check')
          }}
        >
          <Icon name="check" size={16} />
          {figure ? <Figure>{figure}</Figure> : null}
        </button>
      </Tooltip>
      <Tooltip label={noLabel} side="top">
        <button
          type="button"
          aria-label={noLabel}
          className="sl-needs-you-answer"
          data-kind="no"
          onClick={(event) => {
            soundPress(event)
            scope.answerWith('no', noWord, 'cross')
          }}
        >
          <Icon name="x" size={15} />
        </button>
      </Tooltip>
    </AnswersLine>
  )
}

export interface NeedsYouLaterProps extends Omit<React.ComponentPropsWithRef<'button'>, 'children'> {}

/* `later` as a clock, for an answers line outside a block (an ask's own
   clock sits on its first line). It sets the answer aside with the same
   undo window as a pick. */
function NeedsYouLater({ className, onClick, ...props }: NeedsYouLaterProps) {
  const scope = useAnswerScope('NeedsYou.Later')
  return (
    <IconAction
      label="Later"
      className={cx('sl-needs-you-later', className)}
      onClick={(event) => {
        onClick?.(event)
        if (!event.defaultPrevented) scope.later()
      }}
      {...props}
    >
      <Icon name="clock" />
    </IconAction>
  )
}

/* Compound parts: NeedsYou, .Group, .Ask, .Picks, .Pick, .OwnAnswer,
   .YesNo, .Answer, .Later. */
export const NeedsYou = Object.assign(NeedsYouRoot, {
  Group: NeedsYouGroup,
  Ask: NeedsYouAsk,
  Picks: NeedsYouPicks,
  Pick: NeedsYouPick,
  OwnAnswer: NeedsYouOwnAnswer,
  YesNo: NeedsYouYesNo,
  Answer: NeedsYouAnswer,
  Later: NeedsYouLater,
})
