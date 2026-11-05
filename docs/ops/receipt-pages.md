# Receipt pages

`vault.receipts` accepts the full positive requested `limit` on both the gate
ledger and the unified receipt family. The existing default is 100. A zero
limit, an unknown receipt kind, or an invalid cursor is still an error.

Both paths measure the requested count once against
`[limits].requested_result_rows` (default 1,048,576). Crossing that row asks
through the vault's installed limit port and serves the count; it does not
clamp the page or require the caller to request smaller pages. The measurement
runs after cursor and kind validation, outside a held store transaction.

`effective_limit` is the requested count and `limit_clamped` is false. A page
can contain fewer receipts when no more admitted receipts remain. It returns
`next_after` only when an additional admitted receipt was found. The cursor is
a position, not a snapshot: later writes can appear ahead of an earlier page.

## Unified-family progress

The family reads raw receipt windows using the existing 100,000-row source
window. That window is not a response limit. Each subsequent read uses the
last raw receipt's full `(occurred_at, kind, receipt_id)` position through the
existing `ReceiptQuery.after` filter, before source top-N selection. Receipts
sharing a timestamp therefore still move the scan forward.

The destination's existing whole-reference off-device screen and the handle's
existing credential screen run before a receipt occupies a result position.
A fully withheld window still advances by its last raw position. The walk
continues until the requested page and one admitted lookahead are found, or
a raw window proves exhaustion. The response cursor names the last returned
receipt, not a withheld row or the lookahead.

Gate-ledger ordering, receipt-family ordering, owner share-notice screening,
and undecodable outbound receipt counts are unchanged. Nonpaged receipt
queries and the older lower-level off-device walk are unchanged. No new
setting, storage format, migration, or deployment step is required.
