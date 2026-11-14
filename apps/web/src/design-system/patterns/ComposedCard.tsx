import * as React from 'react'
import { Icon } from '../primitives/Icon'
import { InfoMark } from '../primitives/InfoMark'
import { Verb } from '../primitives/Verb'
import { PickDiamond } from '../marks/PickDiamond'
import { StatusDot } from '../marks/StatusDot'
import type { AffordanceAttributes } from '../lib/affordance'
import { soundPress } from '../lib/press'
import { cx, useControllableState, useSafeId } from '../lib/react-utils'

export interface ComposedCardProps extends Omit<React.ComponentPropsWithRef<'section'>, 'title'> {
  /* The card's title: one serif line, the claim the card makes. */
  title: React.ReactNode
  /* The short note: on the information mark in a framed card, as text
     under the body in a bare one. */
  note?: React.ReactNode
  /* Pressing the information mark: the caller opens the card beside the
     room. */
  onOpen?: () => void
  noteLabel?: string
  /* No frame: for the pane and for a view. The title shows at the section
     size and the note shows as text under the body. */
  bare?: boolean
  /* The card is still arriving: the live mark stands where the
     information mark is (the mark keeps its place, hidden, so nothing
     moves when the card is whole), and the card says it is busy. */
  pending?: boolean
  /* The live mark's accessible name while pending. */
  pendingLabel?: string
}

/* A card an agent composed from the app's own parts. Framed, it has the
   look of the asks block (the sunk tone, the card ring, at most the
   messages column wide) and the same grammar: a title line with the
   information mark at its right, then the body (ComposedCard.Table, a
   BarChart, ComposedCard.Picks, ComposedCard.Figures), then an optional
   ComposedCard.Foot. */
function ComposedCardRoot({
  title,
  note,
  onOpen,
  noteLabel,
  bare = false,
  pending = false,
  pendingLabel = 'still arriving',
  className,
  children,
  ...props
}: ComposedCardProps) {
  const titleId = useSafeId('sl-composed-card')
  return (
    <section
      aria-labelledby={titleId}
      aria-busy={pending || undefined}
      className={cx('sl-composed-card', className)}
      data-ground={bare ? 'bare' : 'well'}
      data-pending={pending ? '' : undefined}
      data-info-block=""
      {...props}
    >
      <div className="sl-composed-card-head">
        <span id={titleId} className="sl-composed-card-title">
          {title}
        </span>
        {!bare && note !== undefined ? <InfoMark note={note} onOpen={onOpen} label={noteLabel} /> : null}
        {pending ? <StatusDot state="live" label={pendingLabel} className="sl-composed-card-live" /> : null}
      </div>
      {children}
      {bare && note !== undefined ? <div className="sl-composed-card-note">{note}</div> : null}
    </section>
  )
}

/* ── the table ──────────────────────────────────────────────────────────── */

interface TableValue {
  onToggle?: (row: string, picked: boolean) => void
}

const TableContext = React.createContext<TableValue | null>(null)
/* Cells inside the head render as column headers. */
const InHead = React.createContext(false)

export interface ComposedCardTableProps extends Omit<React.ComponentPropsWithRef<'table'>, 'onToggle'> {
  /* A pick in the table was toggled: the row's id and whether it is now in. */
  onToggle?: (row: string, picked: boolean) => void
}

/* A small table: one ComposedCard.Head, then ComposedCard.Rows. Column
   heads in the quiet ink at the figure size, cells at the do size. The
   first cell of a row names it; the others are quieter. */
function ComposedCardTable({ onToggle, className, children, ...props }: ComposedCardTableProps) {
  const parts = React.Children.toArray(children)
  const heads = parts.filter((c) => React.isValidElement(c) && c.type === ComposedCardHead)
  const rows = parts.filter((c) => !heads.includes(c))
  const ctx = React.useMemo(() => ({ onToggle }), [onToggle])
  return (
    <TableContext.Provider value={ctx}>
      <table className={cx('sl-composed-table', className)} {...props}>
        {heads}
        <tbody>{rows}</tbody>
      </table>
    </TableContext.Provider>
  )
}

export interface ComposedCardHeadProps extends React.ComponentPropsWithRef<'thead'> {}

/* The head row; its cells are column headers. */
function ComposedCardHead({ className, children, ...props }: ComposedCardHeadProps) {
  return (
    <thead className={cx('sl-composed-table-head', className)} {...props}>
      <InHead.Provider value={true}>
        <tr>{children}</tr>
      </InHead.Provider>
    </thead>
  )
}

const RowHead = React.createContext(false)

export interface ComposedCardRowProps extends React.ComponentPropsWithRef<'tr'> {}

/* A row; its first cell is the row's header. */
function ComposedCardRow({ className, children, ...props }: ComposedCardRowProps) {
  const cells = React.Children.toArray(children)
  return (
    <tr className={cx('sl-composed-table-row', className)} {...props}>
      {cells.map((cell, i) => (
        <RowHead.Provider key={React.isValidElement(cell) && cell.key != null ? cell.key : i} value={i === 0}>
          {cell}
        </RowHead.Provider>
      ))}
    </tr>
  )
}

export type ComposedCardCellProps = React.ComponentPropsWithRef<'td'> & {
  /* A figure column: mono, tabular. */
  figure?: boolean
  /* The head of a pick column: centred over the diamonds. */
  pick?: boolean
}

/* A cell: a column header in the head, the row's header when first in a
   row, else a data cell. */
function ComposedCardCell({ figure = false, pick = false, className, ...props }: ComposedCardCellProps) {
  const head = React.useContext(InHead)
  const rowHead = React.useContext(RowHead)
  const shared = {
    className: cx('sl-composed-cell', className),
    'data-figure': figure ? '' : undefined,
    'data-pick': pick ? '' : undefined,
  }
  if (head) return <th scope="col" {...shared} {...(props as React.ComponentPropsWithRef<'th'>)} />
  if (rowHead) return <th scope="row" {...shared} {...(props as React.ComponentPropsWithRef<'th'>)} />
  return <td {...shared} {...props} />
}

export interface ComposedCardPickCellProps extends Omit<React.ComponentPropsWithRef<'button'>, 'children' | 'value'> {
  /* The row's id, reported to the table's onToggle. */
  row: string
  /* What the row is, for the accessible name: `Kobe Sannomiya`. */
  label: string
  /* In (a filled diamond) or out (an outlined one). */
  picked?: boolean
  defaultPicked?: boolean
  onPickedChange?: (picked: boolean) => void
}

/* The pick cell of a row: a diamond, filled when the row is in. Pressing
   it toggles the row. */
function ComposedCardPickCell({
  row,
  label,
  picked: pickedProp,
  defaultPicked = false,
  onPickedChange,
  className,
  onClick,
  type = 'button',
  ...props
}: ComposedCardPickCellProps) {
  const table = React.useContext(TableContext)
  const [picked, setPicked] = useControllableState(pickedProp, defaultPicked, onPickedChange)
  return (
    <td className="sl-composed-cell" data-pick="">
      <button
        type={type}
        role="checkbox"
        aria-checked={picked}
        aria-label={label}
        className={cx('sl-composed-pick', className)}
        onClick={(event) => {
          onClick?.(event)
          if (event.defaultPrevented) return
          soundPress(event)
          setPicked(!picked)
          table?.onToggle?.(row, !picked)
        }}
        {...props}
      >
        <PickDiamond />
      </button>
    </td>
  )
}

/* ── the foot ───────────────────────────────────────────────────────────── */

export interface ComposedCardFootProps extends React.ComponentPropsWithRef<'div'> {
  /* How many, in the quiet ink: `12 of 14 in`. */
  count?: React.ReactNode
  /* The verb that shows more rows: `show 10 more`. */
  more?: string
  onMore?: (event: React.MouseEvent<HTMLButtonElement>) => void
  /* The card's one action, on a tone chip with a check: `use this list`. */
  action?: string
  onAction?: (event: React.MouseEvent<HTMLButtonElement>) => void
  /* The action cannot run yet (the card is still arriving, or waits on an
     answer): the chip shows and does not press. */
  actionDisabled?: boolean
  /* The verbs `more` and the action run (see affordance()). */
  affordances?: Partial<Record<'more' | 'action', AffordanceAttributes>>
}

/* The foot line: a count, a verb that shows more, then at the right one
   tone chip with a check and a word. */
function ComposedCardFoot({ count, more, onMore, action, onAction, actionDisabled = false, affordances = {}, className, children, ...props }: ComposedCardFootProps) {
  return (
    <div className={cx('sl-composed-foot', className)} {...props}>
      {count !== undefined ? <span className="sl-composed-foot-count">{count}</span> : null}
      {more ? (
        <Verb className="sl-composed-foot-more" onClick={onMore} {...affordances.more}>
          {more}
        </Verb>
      ) : null}
      {children}
      {action ? (
        <button
          type="button"
          className="sl-composed-chip sl-composed-foot-action"
          disabled={actionDisabled}
          {...affordances.action}
          onClick={(event) => {
            soundPress(event)
            onAction?.(event)
          }}
        >
          <Icon name="check" size={16} />
          <span>{action}</span>
        </button>
      ) : null}
    </div>
  )
}

/* ── the readings ───────────────────────────────────────────────────────── */

interface PicksValue {
  value: string
  setValue: (value: string) => void
}

const PicksContext = React.createContext<PicksValue | null>(null)

type PicksValueProps =
  | { value: string; defaultValue?: never; onValueChange?: (value: string) => void }
  | { value?: never; defaultValue: string; onValueChange?: (value: string) => void }

export type ComposedCardPicksProps = PicksValueProps & Omit<React.ComponentPropsWithRef<'div'>, 'defaultValue' | 'onChange'>

/* Tone chips that switch the reading of the card (ComposedCard.Reading); the
   chosen one carries an inset line in the first ink. Left and Right move
   the choice. */
function ComposedCardPicks({ value: valueProp, defaultValue, onValueChange, className, onKeyDown, ...props }: ComposedCardPicksProps) {
  const [value, setValue] = useControllableState(valueProp, defaultValue ?? '', onValueChange)
  const ctx = React.useMemo(() => ({ value, setValue }), [value, setValue])
  return (
    <PicksContext.Provider value={ctx}>
      <div
        role="radiogroup"
        className={cx('sl-composed-picks', className)}
        onKeyDown={(event) => {
          onKeyDown?.(event)
          if (event.defaultPrevented || !['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(event.key)) return
          const picks = [...event.currentTarget.querySelectorAll<HTMLButtonElement>('[role="radio"]:not(:disabled)')]
          const i = picks.indexOf(document.activeElement as HTMLButtonElement)
          if (i < 0) return
          event.preventDefault()
          const step = event.key === 'ArrowLeft' || event.key === 'ArrowUp' ? -1 : 1
          const next = picks[(i + step + picks.length) % picks.length]
          next.focus()
          if (next.dataset.value !== undefined) setValue(next.dataset.value)
        }}
        {...props}
      />
    </PicksContext.Provider>
  )
}

export interface ComposedCardReadingProps extends Omit<React.ComponentPropsWithRef<'button'>, 'value'> {
  value: string
}

/* One reading of the card. */
function ComposedCardReading({ value, className, onClick, type = 'button', ...props }: ComposedCardReadingProps) {
  const picks = React.useContext(PicksContext)
  if (!picks) throw new Error('ComposedCard.Reading must be inside ComposedCard.Picks')
  const chosen = picks.value === value
  return (
    <button
      type={type}
      role="radio"
      aria-checked={chosen}
      tabIndex={chosen ? 0 : -1}
      data-value={value}
      data-chosen={chosen ? '' : undefined}
      className={cx('sl-composed-chip sl-composed-reading', className)}
      onClick={(event) => {
        onClick?.(event)
        if (event.defaultPrevented) return
        soundPress(event)
        picks.setValue(value)
      }}
      {...props}
    />
  )
}

/* ── the figures ────────────────────────────────────────────────────────── */

export interface ComposedCardFiguresProps extends React.ComponentPropsWithRef<'p'> {}

/* One line of text with mono figures (Figure); the leading figure is in
   the first ink. */
function ComposedCardFigures({ className, ...props }: ComposedCardFiguresProps) {
  return <p className={cx('sl-composed-figures', className)} {...props} />
}

/* Compound parts: ComposedCard, .Table, .Head, .Row, .Cell, .PickCell,
   .Foot, .Picks, .Reading, .Figures. */
export const ComposedCard = Object.assign(ComposedCardRoot, {
  Table: ComposedCardTable,
  Head: ComposedCardHead,
  Row: ComposedCardRow,
  Cell: ComposedCardCell,
  PickCell: ComposedCardPickCell,
  Foot: ComposedCardFoot,
  Picks: ComposedCardPicks,
  Reading: ComposedCardReading,
  Figures: ComposedCardFigures,
})
