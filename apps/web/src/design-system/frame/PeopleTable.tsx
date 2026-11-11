import * as React from 'react'
import { LedgerTable, type LedgerTableProps } from '../patterns/LedgerTable'
import { Icon } from '../primitives/Icon'
import { cx, useControllableState } from '../lib/react-utils'

/* Rows nested inside a row sit one step deeper. */
const DepthContext = React.createContext(0)

export interface PeopleTableProps extends LedgerTableProps {}

/* The people of a vault as flat rows (the ledger's grammar: horizontal
   rules only). Children: an optional PeopleTable.Head, then rows; a row
   that holds rows folds, which makes the table a tree (lead, team,
   agents). */
function PeopleTableRoot({ className, ...props }: PeopleTableProps) {
  return <LedgerTable className={cx('sl-people', className)} {...props} />
}

export interface PeopleTableRowProps extends Omit<React.ComponentPropsWithRef<'tr'>, 'children'> {
  /* Their Glyph. */
  glyph: React.ReactNode
  name: React.ReactNode
  /* For a guest: where they come from (`from Acme's vault`). */
  origin?: React.ReactNode
  /* The role as a plain word: a RoleWord. */
  roleWord?: React.ReactNode
  /* Nesting; by default one deeper than the row that holds this one. */
  depth?: 0 | 1 | 2
  /* Rows under this one, shown while it is open. */
  children?: React.ReactNode
  open?: boolean
  defaultOpen?: boolean
  onOpenChange?: (open: boolean) => void
}

function PeopleTableRow({
  glyph,
  name,
  origin,
  roleWord,
  depth,
  children,
  open: openProp,
  defaultOpen = true,
  onOpenChange,
  className,
  ...props
}: PeopleTableRowProps) {
  const parentDepth = React.useContext(DepthContext)
  const level = Math.min(2, depth ?? parentDepth)
  const [open, setOpen] = useControllableState(openProp, defaultOpen, onOpenChange)
  const hasRows = React.Children.toArray(children).length > 0
  return (
    <>
      <LedgerTable.Row
        className={cx('sl-people-row', className)}
        data-depth={level}
        data-state={hasRows ? (open ? 'open' : 'closed') : undefined}
        {...props}
      >
        <LedgerTable.Cell className="sl-people-who">
          <span className="sl-people-who-line">
            {hasRows ? (
              <button
                type="button"
                className="sl-people-fold"
                aria-expanded={open}
                aria-label={typeof name === 'string' ? `${name}, the rows under it` : 'the rows under it'}
                onClick={() => setOpen(!open)}
              >
                <Icon name="chevron" size={12} />
              </button>
            ) : (
              <span className="sl-people-fold" aria-hidden="true" />
            )}
            <span className="sl-people-glyph">{glyph}</span>
            <span className="sl-people-name">{name}</span>
            {origin !== undefined ? <span className="sl-people-origin">{origin}</span> : null}
          </span>
        </LedgerTable.Cell>
        <LedgerTable.Cell className="sl-people-role">{roleWord}</LedgerTable.Cell>
      </LedgerTable.Row>
      {hasRows && open ? <DepthContext.Provider value={level + 1}>{children}</DepthContext.Provider> : null}
    </>
  )
}

/* Compound parts: PeopleTable, .Head, .Cell (for the head), .Row. */
export const PeopleTable = Object.assign(PeopleTableRoot, {
  Head: LedgerTable.Head,
  Cell: LedgerTable.Cell,
  Row: PeopleTableRow,
})
