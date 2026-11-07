# Held-out receipt sources

`held_out_receipts_sourced` returns the same receipts, order, and errors as the
native held-out reader. It reads outcome side tables, not ENTITY rows.
An `attempt:<hex>` suffix identifies a queue attempt in the separate
`attempt_records` database; it is not a physical ENTITY source witness.

The source-row field is `None`: unknown provenance, not an empty evidence set.
It grants no read authority and does not reject receipts. Upkeep continues to
keep `reserve_rows=None`. Physical source tracking needs a witness from the
actual outcome-row producer and reader.
