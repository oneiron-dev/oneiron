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
whole-heap, compile, or runtime closure is claimed. Credits for these
containers follow the existing admitted-allocation model and remain on
the operation ledger until the operation ends, even after a local
container drops. Scoped credit return for repeated walks remains open.
