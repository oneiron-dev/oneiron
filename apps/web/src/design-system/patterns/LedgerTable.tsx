import * as React from 'react'
import { cx } from '../lib/react-utils'

/* Cells inside the head render as column headers. */
const InHead = React.createContext(false)

export interface LedgerTableProps extends React.ComponentPropsWithRef<'table'> {}

/* A flat table: horizontal rules only, no outer box, no vertical lines.
   Children are one LedgerTable.Head and LedgerTable.Rows; the rows are
   gathered into the table body. */
function LedgerTableRoot({ className, children, ...props }: LedgerTableProps) {
  const parts = React.Children.toArray(children)
  const heads = parts.filter((c) => React.isValidElement(c) && c.type === LedgerTableHead)
  const rows = parts.filter((c) => !heads.includes(c))
  return (
    <table className={cx('sl-ledger', className)} {...props}>
      {heads}
      <tbody>{rows}</tbody>
    </table>
  )
}

export interface LedgerTableHeadProps extends React.ComponentPropsWithRef<'thead'> {}

/* The head row; its cells are column headers. */
function LedgerTableHead({ className, children, ...props }: LedgerTableHeadProps) {
  return (
    <thead className={cx('sl-ledger-head', className)} {...props}>
      <InHead.Provider value={true}>
        <tr>{children}</tr>
      </InHead.Provider>
    </thead>
  )
}

export interface LedgerTableRowProps extends React.ComponentPropsWithRef<'tr'> {}

/* A row. With a click handler it takes focus and Enter or Space act. */
function LedgerTableRow({ className, onClick, onKeyDown, tabIndex, ...props }: LedgerTableRowProps) {
  const interactive = !!onClick
  return (
    <tr
      className={cx('sl-ledger-row', className)}
      data-interactive={interactive ? '' : undefined}
      tabIndex={tabIndex ?? (interactive ? 0 : undefined)}
      onClick={onClick}
      onKeyDown={(event) => {
        onKeyDown?.(event)
        if (!interactive || event.defaultPrevented || event.target !== event.currentTarget) return
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault()
          event.currentTarget.click()
        }
      }}
      {...props}
    />
  )
}

export type LedgerTableCellProps = React.ComponentPropsWithRef<'td'> & {
  /* A figure column: mono, tabular, aligned right. */
  numeric?: boolean
}

/* A cell; a column header inside the head. */
function LedgerTableCell({ numeric = false, className, ...props }: LedgerTableCellProps) {
  const head = React.useContext(InHead)
  const shared = { className: cx('sl-ledger-cell', className), 'data-numeric': numeric ? '' : undefined }
  if (head) return <th scope="col" {...shared} {...(props as React.ComponentPropsWithRef<'th'>)} />
  return <td {...shared} {...props} />
}

/* Compound parts: LedgerTable, .Head, .Row, .Cell. */
export const LedgerTable = Object.assign(LedgerTableRoot, {
  Head: LedgerTableHead,
  Row: LedgerTableRow,
  Cell: LedgerTableCell,
})
