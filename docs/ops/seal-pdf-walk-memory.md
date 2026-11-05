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

FIX 14264 also admits the per-reference chain's `seen` set before
its initial entry and each new link. It drops the set before returning its
charged bytes, including cyclic, dangling and resource-error exits. Every
production reference helper carries the same operation limits. Missing or
cyclic links keep their existing absence/invalid outcome; resource refusals
stay typed errors, never invalid-PDF verdicts or shorter results.

FIX 14306 admits the trailer lexer's skipped-value nesting stack before
both dictionary and array pushes. It returns the exact successfully charged
net growth after dropping the stack on every exit; allocator capacity is not
used to invent credit. Malformed trailers still mean no structural proof,
while a memory refusal stays typed through classic-xref linkage and revision
analysis. Xref-stream linkage and existing token/depth counts are unchanged.

Not covered here: CMap and decoder heaps, third-party heaps,
allocator slack, and retained outputs. No
whole-heap, compile, or runtime closure is claimed. FIX 14217: these
walk containers return their own credits when they drop. `walk::pages`
yields its output held (`Held`) until the caller drops it, and its open
levels and walked set return their net bytes on the success path;
`revision_ends` yields its ends held, and returns their net bytes on
its ordinary no-proof exits. Refusal exits are unchanged: the operation
ends and every reservation returns with it.

Issuer checks use the same operation ledger. The certificate's TBS DER is
reserved before encoding, and all four production callers preserve a typed
memory refusal instead of treating it as a non-issuer. The original issuer-name,
algorithm, signature and first-match order are unchanged.

OCSP CertID matching reserves the subject encoding before `to_der`. It computes
the existing SHA-1 or SHA-256 digest on the stack, then reserves its actual length
before making the comparison vector. The returned vector drops before its hold.
Responder-signature verification also reserves its response TBS encoding first.
These scratch reservations are separate from the existing retained CRL/DSS and
outer response-list admissions; the same bytes are not charged as both owners.
Unrecognized algorithms keep their previous non-match outcome.
