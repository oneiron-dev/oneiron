import * as React from 'react'
import { Figure } from '../primitives/Figure'
import { Icon } from '../primitives/Icon'
import { IconAction } from '../primitives/IconAction'
import { Unfold } from '../primitives/Unfold'
import { Verb } from '../primitives/Verb'
import { PickDiamond } from '../marks/PickDiamond'
import { UrgencyMark } from '../marks/UrgencyMark'
import { soundPress } from '../lib/press'
import { cx, mergeRefs, useControllableState, useIsomorphicLayoutEffect, useSafeId } from '../lib/react-utils'
import { SETTLE_OPEN, settleReducer, type SettleKind, type SettleState } from './settle-reducer'

/* How long an answer can be undone before it stands. */
export const NEEDS_YOU_UNDO_MS = 5000
/* How long a settled item takes to fold away (matches the CSS). */
const FOLD_MS = 260

const prefersReducedMotion = () =>
  typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches

/* ── Escape undoes the newest pending answer, wherever focus is ─────────── */

const pendingUndos: Array<() => void> = []

function onEscapeUndo(event: KeyboardEvent) {
  if (event.key !== 'Escape' || event.defaultPrevented) return
  const undo = pendingUndos[pendingUndos.length - 1]
  if (!undo) return
  event.preventDefault()
  undo()
}

function pushPendingUndo(undo: () => void): () => void {
  if (!pendingUndos.length) document.addEventListener('keydown', onEscapeUndo, true)
  pendingUndos.push(undo)
  return () => {
    const i = pendingUndos.lastIndexOf(undo)
    if (i >= 0) pendingUndos.splice(i, 1)
    if (!pendingUndos.length) document.removeEventListener('keydown', onEscapeUndo, true)
  }
}

/* ── the root ───────────────────────────────────────────────────────────── */

interface NeedsYouContextValue {
  openId: string | null
  open: (id: string) => void
  /* The item finished its undo window: fold it and open the next. */
  markSettled: (id: string, value: string, kind: SettleKind) => void
  undoWindowMs: number
}

const NeedsYouContext = React.createContext<NeedsYouContextValue | null>(null)

function useNeedsYou(part: string): NeedsYouContextValue {
  const ctx = React.useContext(NeedsYouContext)
  if (!ctx) throw new Error(`${part} must be inside NeedsYou`)
  return ctx
}

/* Item ids in the order they are written, found by walking the JSX given
   to the root (through fragments and wrapping elements). */
function itemIds(children: React.ReactNode, out: string[] = []): string[] {
  React.Children.forEach(children, (child) => {
    if (!React.isValidElement(child)) return
    const props = child.props as { id?: unknown; children?: React.ReactNode }
    if (child.type === NeedsYouItem && typeof props.id === 'string') out.push(props.id)
    else if (props.children !== undefined) itemIds(props.children, out)
  })
  return out
}

export interface NeedsYouProps extends Omit<React.ComponentPropsWithRef<'section'>, 'onChange'> {
  /* The open item. Exactly one is open: the first by default. */
  openId?: string | null
  defaultOpenId?: string
  onOpenChange?: (id: string | null) => void
  /* An answer stood through its undo window; called as the item folds away. */
  onSettle?: (id: string, value: string) => void
  /* The item was set aside with `later`. */
  onLater?: (id: string) => void
  undoWindowMs?: number
  /* `well` is the sunk block of a room; `bare` sits on a popover or a desk. */
  ground?: 'well' | 'bare'
}

/* The things waiting on a person: an accordion with one item open. When the
   open item settles it folds away and the next one opens. */
function NeedsYouRoot({
  ref,
  openId: openIdProp,
  defaultOpenId,
  onOpenChange,
  onSettle,
  onLater,
  undoWindowMs = NEEDS_YOU_UNDO_MS,
  ground = 'well',
  className,
  children,
  'aria-label': ariaLabel = 'needs you',
  ...props
}: NeedsYouProps) {
  const [chosen, setChosen] = useControllableState<string | null | undefined>(
    openIdProp,
    defaultOpenId,
    onOpenChange ? (next) => onOpenChange(next ?? null) : undefined,
  )
  const [settled, setSettled] = React.useState<ReadonlySet<string>>(() => new Set())
  const ids = itemIds(children)
  const live = ids.filter((id) => !settled.has(id))
  const openId = chosen && live.includes(chosen) ? chosen : (live[0] ?? null)

  const rootRef = React.useRef<HTMLElement | null>(null)
  const latest = React.useRef({ ids, settled, openId, onSettle, onLater })
  useIsomorphicLayoutEffect(() => {
    latest.current = { ids, settled, openId, onSettle, onLater }
  })

  const open = React.useCallback((id: string) => setChosen(id), [setChosen])

  const markSettled = React.useCallback(
    (id: string, value: string, kind: SettleKind) => {
      const { ids: order, settled: done, openId: current } = latest.current
      const nextSettled = new Set(done).add(id)
      setSettled(nextSettled)
      if (current === id) {
        const rest = order.filter((x) => !nextSettled.has(x))
        const after = rest.find((x) => order.indexOf(x) > order.indexOf(id))
        const next = after ?? rest[0] ?? null
        setChosen(next)
        /* Keyboard flow: focus that was in the settled item moves to the next. */
        const root = rootRef.current
        const item = root?.querySelector<HTMLElement>(`[data-needs-you-id="${CSS.escape(id)}"]`)
        if (next && root && item?.contains(document.activeElement)) {
          requestAnimationFrame(() => {
            const nextItem = root.querySelector<HTMLElement>(`[data-needs-you-id="${CSS.escape(next)}"]`)
            const target =
              nextItem?.querySelector<HTMLElement>('.sl-needs-you-pick:not(:disabled)') ??
              nextItem?.querySelector<HTMLElement>('.sl-needs-you-head')
            target?.focus({ preventScroll: true })
          })
        }
      }
      setTimeout(
        () => {
          const { onSettle: settleCb, onLater: laterCb } = latest.current
          if (kind === 'later') laterCb?.(id)
          else settleCb?.(id, value)
        },
        prefersReducedMotion() ? 0 : FOLD_MS,
      )
    },
    [setChosen],
  )

  const ctx = React.useMemo(
    () => ({ openId, open, markSettled, undoWindowMs }),
    [openId, open, markSettled, undoWindowMs],
  )

  return (
    <NeedsYouContext.Provider value={ctx}>
      <section
        ref={mergeRefs(ref, rootRef)}
        aria-label={ariaLabel}
        className={cx('sl-needs-you', className)}
        data-ground={ground}
        {...props}
      >
        {children}
      </section>
    </NeedsYouContext.Provider>
  )
}

/* ── one item ───────────────────────────────────────────────────────────── */

interface ItemContextValue {
  state: SettleState
  /* The words of the pending answer, shown with a filled diamond. */
  pendingLabel: React.ReactNode
  pendingWord: string
  pick: (value: string, label: React.ReactNode, word?: string) => void
  later: () => void
  undo: () => void
}

const ItemContext = React.createContext<ItemContextValue | null>(null)

function useItem(part: string): ItemContextValue {
  const ctx = React.useContext(ItemContext)
  if (!ctx) throw new Error(`${part} must be inside NeedsYou.Item`)
  return ctx
}

export interface NeedsYouUrgency {
  /* One serif reason: `blocks the fit`, `due Friday`. */
  reason: React.ReactNode
  /* A time that ends the reason, set as a figure. */
  deadline?: React.ReactNode
}

export interface NeedsYouItemProps extends Omit<React.ComponentPropsWithRef<'div'>, 'id'> {
  id: string
  /* The asker's mark: a Glyph. */
  asker?: React.ReactNode
  /* The question, one serif line; it wraps when the item is open. */
  question: React.ReactNode
  urgency?: NeedsYouUrgency
}

/* Closed: one line. Open: the question line and its body (a shape, then the
   picks). */
function NeedsYouItem({ id, asker, question, urgency, className, children, ...props }: NeedsYouItemProps) {
  const root = useNeedsYou('NeedsYou.Item')
  const [state, dispatch] = React.useReducer(settleReducer, SETTLE_OPEN)
  const [pending, setPending] = React.useState<{ label: React.ReactNode; word: string }>({ label: null, word: '' })
  const isOpen = root.openId === id

  const pick = React.useCallback((value: string, label: React.ReactNode, word = 'answered') => {
    setPending({ label, word })
    dispatch({ type: 'pick', value })
  }, [])
  const later = React.useCallback(() => {
    setPending({ label: null, word: 'parked' })
    dispatch({ type: 'pick', value: 'later', kind: 'later' })
  }, [])
  const undo = React.useCallback(() => dispatch({ type: 'undo' }), [])

  /* The undo window: Escape or `undo` restores; otherwise the answer stands. */
  React.useEffect(() => {
    if (state.status !== 'pending') return
    const release = pushPendingUndo(undo)
    const timer = setTimeout(() => dispatch({ type: 'commit' }), root.undoWindowMs)
    return () => {
      clearTimeout(timer)
      release()
    }
  }, [state.status, undo, root.undoWindowMs])

  const { markSettled } = root
  React.useEffect(() => {
    if (state.status === 'settled') markSettled(id, state.value, state.kind)
  }, [state, id, markSettled])

  const ctx = React.useMemo(
    () => ({ state, pendingLabel: pending.label, pendingWord: pending.word, pick, later, undo }),
    [state, pending, pick, later, undo],
  )
  const settled = state.status === 'settled'

  return (
    <ItemContext.Provider value={ctx}>
      <div
        className={cx('sl-needs-you-item', className)}
        data-needs-you-id={id}
        data-state={isOpen ? 'open' : 'closed'}
        data-settle={state.status}
        inert={settled}
        {...props}
      >
        <Unfold
          className="sl-needs-you-item-inner"
          open={isOpen}
          onOpenChange={(next) => {
            if (next) root.open(id)
          }}
        >
          <Unfold.Trigger className="sl-needs-you-head">
            <span className="sl-needs-you-asker">{asker}</span>
            <span className="sl-needs-you-question">{question}</span>
            {urgency ? (
              <span className="sl-needs-you-meta">
                <UrgencyMark>
                  {urgency.reason}
                  {urgency.deadline !== undefined ? <Figure>{urgency.deadline}</Figure> : null}
                </UrgencyMark>
              </span>
            ) : null}
          </Unfold.Trigger>
          <Unfold.Content>
            <div className="sl-needs-you-body">{children}</div>
          </Unfold.Content>
        </Unfold>
      </div>
    </ItemContext.Provider>
  )
}

/* ── the picks line ─────────────────────────────────────────────────────── */

interface PicksContextValue {
  value: string | null
  choose: (value: string, label: React.ReactNode, word?: string) => void
  openOwn: () => void
  ownPlaceholder: React.RefObject<string>
}

const PicksContext = React.createContext<PicksContextValue | null>(null)

function usePicks(part: string): PicksContextValue {
  const ctx = React.useContext(PicksContext)
  if (!ctx) throw new Error(`${part} must be inside NeedsYou.Picks`)
  return ctx
}

export interface NeedsYouPicksProps extends Omit<React.ComponentPropsWithRef<'div'>, 'defaultValue'> {
  value?: string | null
  defaultValue?: string | null
  onValueChange?: (value: string | null) => void
}

/* The second line of an open item: the picks as diamonds, the pencil, and
   `later` at the right. A pick applies at once; the line then shows the
   pick, what happened and `undo` until the window closes. */
function NeedsYouPicks({ ref, value: valueProp, defaultValue = null, onValueChange, className, children, ...props }: NeedsYouPicksProps) {
  const item = useItem('NeedsYou.Picks')
  const [value, setValue] = useControllableState<string | null>(valueProp, defaultValue, onValueChange)
  const [own, setOwn] = React.useState(false)
  const ownPlaceholder = React.useRef('Your own answer')
  const ownField = React.useRef<HTMLInputElement | null>(null)
  const undoRef = React.useRef<HTMLButtonElement | null>(null)
  const lineRef = React.useRef<HTMLDivElement | null>(null)
  const status = item.state.status

  /* A pick moves focus to `undo`; undo clears the pick and returns focus to
     the first pick. Focus moves only when it was on the line (the control
     that held it has just been replaced, which leaves it on the body). */
  const previous = React.useRef(status)
  React.useEffect(() => {
    const active = document.activeElement
    const focusWasHere = !active || active === document.body || !!lineRef.current?.contains(active)
    if (previous.current === 'pending' && status === 'open') {
      setValue(null)
      if (focusWasHere) {
        requestAnimationFrame(() => lineRef.current?.querySelector<HTMLElement>('.sl-needs-you-pick')?.focus({ preventScroll: true }))
      }
    }
    if (previous.current === 'open' && status === 'pending' && focusWasHere) {
      requestAnimationFrame(() => undoRef.current?.focus({ preventScroll: true }))
    }
    previous.current = status
  }, [status, setValue])

  React.useEffect(() => {
    if (own) ownField.current?.focus()
  }, [own])

  const choose = React.useCallback(
    (next: string, label: React.ReactNode, word?: string) => {
      setValue(next)
      item.pick(next, label, word)
    },
    [setValue, item],
  )
  const ctx = React.useMemo(
    () => ({ value, choose, openOwn: () => setOwn(true), ownPlaceholder }),
    [value, choose],
  )

  let line: React.ReactNode
  if (status === 'pending' || status === 'settled') {
    line = (
      <>
        {item.pendingLabel !== null ? (
          <button type="button" className="sl-needs-you-pick" aria-pressed="true" disabled>
            <PickDiamond />
            {item.pendingLabel}
          </button>
        ) : null}
        <span className="sl-needs-you-pending" role="status">
          {item.pendingWord}
          <span aria-hidden="true"> · </span>
          <Verb ref={undoRef} className="sl-needs-you-undo" onClick={item.undo} disabled={status === 'settled'}>
            undo
          </Verb>
        </span>
      </>
    )
  } else if (own) {
    line = (
      <>
        <input
          ref={ownField}
          className="sl-needs-you-own"
          aria-label="your own answer"
          placeholder={ownPlaceholder.current}
          onKeyDown={(event) => {
            if (event.nativeEvent.isComposing) return
            const text = event.currentTarget.value.trim()
            if (event.key === 'Enter' && text) {
              event.preventDefault()
              setOwn(false)
              choose(text, `“${text}”`)
            } else if (event.key === 'Escape') {
              event.preventDefault()
              setOwn(false)
            }
          }}
        />
        <Verb className="sl-needs-you-later" onClick={() => setOwn(false)}>
          cancel
        </Verb>
      </>
    )
  } else {
    line = children
  }

  return (
    <PicksContext.Provider value={ctx}>
      <div
        ref={mergeRefs(ref, lineRef)}
        role="group"
        className={cx('sl-needs-you-picks', className)}
        data-mode={status !== 'open' ? 'pending' : own ? 'own' : 'picks'}
        {...props}
      >
        {line}
      </div>
    </PicksContext.Provider>
  )
}

export interface NeedsYouPickProps extends Omit<React.ComponentPropsWithRef<'button'>, 'value'> {
  value: string
  /* What the line says once picked; `answered` by default. */
  word?: string
  /* `consent` arms the red on hover: the pick refuses or removes. */
  tone?: 'plain' | 'consent'
}

/* One option: the diamond and a word. */
function NeedsYouPick({ value, word, tone = 'plain', className, onClick, children, type = 'button', ...props }: NeedsYouPickProps) {
  const picks = usePicks('NeedsYou.Pick')
  const chosen = picks.value === value
  return (
    <button
      type={type}
      className={cx('sl-needs-you-pick', className)}
      aria-pressed={chosen}
      data-tone={tone}
      onClick={(event) => {
        onClick?.(event)
        if (event.defaultPrevented) return
        soundPress(event)
        picks.choose(value, children, word)
      }}
      {...props}
    >
      <PickDiamond />
      {children}
    </button>
  )
}

export interface NeedsYouOwnAnswerProps extends Omit<React.ComponentPropsWithRef<'button'>, 'children'> {
  /* The field's placeholder once the pencil opens it. */
  placeholder?: string
  label?: string
}

/* The pencil: turns the picks line into a field for your own answer. Enter
   commits it like a pick; Escape or `cancel` brings the picks back. */
function NeedsYouOwnAnswer({ placeholder = 'Your own answer', label = 'Your own answer', onClick, ...props }: NeedsYouOwnAnswerProps) {
  const picks = usePicks('NeedsYou.OwnAnswer')
  picks.ownPlaceholder.current = placeholder
  return (
    <IconAction
      label={label}
      size="sm"
      tooltipSide="top"
      onClick={(event) => {
        onClick?.(event)
        if (!event.defaultPrevented) picks.openOwn()
      }}
      {...props}
    >
      <Icon name="pen" />
    </IconAction>
  )
}

export interface NeedsYouLaterProps extends React.ComponentPropsWithRef<'button'> {}

/* `later`, at the right end of the line: sets the item aside, with the same
   undo window as a pick. */
function NeedsYouLater({ className, onClick, children = 'later', ...props }: NeedsYouLaterProps) {
  const item = useItem('NeedsYou.Later')
  return (
    <Verb
      className={cx('sl-needs-you-later', className)}
      onClick={(event) => {
        onClick?.(event)
        if (!event.defaultPrevented) item.later()
      }}
      {...props}
    >
      {children}
    </Verb>
  )
}

/* ── body shapes ────────────────────────────────────────────────────────── */

export interface NeedsYouCommandProps extends React.ComponentPropsWithRef<'p'> {}

/* What will run, said once as one plain sentence. */
function NeedsYouCommand({ className, ...props }: NeedsYouCommandProps) {
  return <p className={cx('sl-needs-you-command', className)} {...props} />
}

export interface NeedsYouPlanProps extends React.ComponentPropsWithRef<'div'> {
  /* Steps shown before `show all`. */
  visible?: number
  defaultOpen?: boolean
}

/* A plan: its first three steps, the rest behind `show all`. Children are
   NeedsYou.Step. */
function NeedsYouPlan({ visible = 3, defaultOpen = false, className, children, ...props }: NeedsYouPlanProps) {
  const [open, setOpen] = React.useState(defaultOpen)
  const steps = React.Children.toArray(children)
  const head = steps.slice(0, visible)
  const rest = steps.slice(visible)
  const restId = useSafeId('sl-plan-rest')
  return (
    <div className={cx('sl-needs-you-plan', className)} {...props}>
      <ol className="sl-needs-you-steps">{head}</ol>
      {rest.length ? (
        <Unfold open={open} onOpenChange={setOpen} className="sl-needs-you-plan-rest">
          <Unfold.Content id={restId}>
            <ol className="sl-needs-you-steps" start={visible + 1}>
              {rest}
            </ol>
          </Unfold.Content>
          <Unfold.Trigger asChild>
            <Verb>{open ? 'show fewer' : 'show all'}</Verb>
          </Unfold.Trigger>
        </Unfold>
      ) : null}
    </div>
  )
}

export interface NeedsYouStepProps extends React.ComponentPropsWithRef<'li'> {}

/* One step of a plan; its number is a figure. */
function NeedsYouStep({ className, children, ...props }: NeedsYouStepProps) {
  return (
    <li className={cx('sl-needs-you-step', className)} {...props}>
      <span>{children}</span>
    </li>
  )
}

export interface NeedsYouContextProps extends React.ComponentPropsWithRef<'div'> {}

/* One picture of the thing the question touches. */
function NeedsYouContextPicture({ className, ...props }: NeedsYouContextProps) {
  return <div className={cx('sl-needs-you-context', className)} {...props} />
}

/* Compound parts: NeedsYou, .Item, .Picks, .Pick, .OwnAnswer, .Later,
   .Command, .Plan, .Step, .Context. */
export const NeedsYou = Object.assign(NeedsYouRoot, {
  Item: NeedsYouItem,
  Picks: NeedsYouPicks,
  Pick: NeedsYouPick,
  OwnAnswer: NeedsYouOwnAnswer,
  Later: NeedsYouLater,
  Command: NeedsYouCommand,
  Plan: NeedsYouPlan,
  Step: NeedsYouStep,
  Context: NeedsYouContextPicture,
})
