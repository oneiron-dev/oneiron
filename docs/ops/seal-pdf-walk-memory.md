# Seal PDF walk working containers

FIX 8452 / FIX 12780 remain PART. This pack (FIX 14203) admits the
page-tree walk's working containers before they grow: `walk::pages`
holds its output vector, open-level stack, and walked set on the
operation's existing ledger via `admitted::push` / `btree_insert`, and
`revision_ends` holds its ends vector via `admitted::push`. No new
ledger, cap, default, policy, or numeric constant; unknown counts are
admitted per growth, and existing operation holds persist as before.

All three `walk::pages` callers and all three production
`analyze_security` callers carry the operation's limits and stage. Seal
paths refuse at `InputValidation` / `PdfIncrementalUpdate`; the verify
path returns a refusal as its typed verification error, never as an
invalid-revision verdict. Ordinary malformed or policy-rejected input
keeps its existing invalid outcome on every path.

Not covered here: per-chain `seen` sets, the lexer, CMap and decoder
heaps, third-party heaps, allocator slack, and retained outputs. No
whole-heap, compile, or runtime closure is claimed. FIX 14217: these
walk containers return their own credits when they drop. `walk::pages`
yields its output held (`Held`) until the caller drops it, and its open
levels and walked set return their net bytes on the success path;
`revision_ends` yields its ends held, and returns their net bytes on
its ordinary no-proof exits. Refusal exits are unchanged: the operation
ends and every reservation returns with it.
