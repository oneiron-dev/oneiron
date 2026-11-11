# Native CMS parser memory

The native CMS parser takes the current seal operation's `MemoryLedger`.
It returns its ordinary parsed fields inside `Held<ParsedCms>`. One aggregate
`LedgerHold` owns the retained parser allocations. The parser reserves each
known input slice before copying it, including the raw signed-attribute content
kept for signature-input reconstruction.

The digest-algorithm, certificate, signed-attribute and unsigned-attribute lists
also reserve their replacement slots before growth. If the current aggregate
hold is H, the old slots were charged C, and the full replacement needs T bytes:

- Reserve T while C is still held. The replacement peak is H + T.
- After the reallocation succeeds, return only C, the old charge actually taken.
- The resulting aggregate is H + T - C. Record T as this list's new charge.

Allocator capacity is not a refund. The slot counters track charged requests,
not capacity observations. Allocator rounding beyond the requested capacity is
not an exact-heap measurement or a whole-parser memory guarantee.

On success, the fields drop before their aggregate hold. On malformed input or
memory refusal, the parse closure and nested parser release partial buffers
before the outer hold returns its charge to the ledger's spare room. These are
held allocations, not decoder-live bytes, so a surrounding `LedgerPass` cannot
refund them early. Refunding does not clear an operation's recorded refusal.

## Error routes

The existing `TokenError` type lives at the shared CMS parse layer; its timestamp
module path remains a re-export. Its variants and conversions are unchanged:

- `Invalid` retains the old malformed-CMS and invalid-token handling.
- `Memory(SealMemoryRefusal)` retains the actual floor, deadline, cancellation
  or unavailable-service result.

Both timestamp parsing paths pass the same operation ledger into `parse_cms`.
They no longer add a post-parse hold. CAdES verification handles invalid input
as before, but returns a parser memory refusal directly instead of converting
it to an invalid-envelope verdict. Timestamp failover must not consume a
resource failure as an invalid response.

## Signature input

`signed_attrs_signature_input` rebuilds the same universal SET tag and content
with the existing canonical short/long DER length formula. Length bytes use only
the native word's stack representation. The function holds the exact complete
output length before one fallible vector allocation, then returns the bytes with
their hold. It allocates no separate length buffer or intermediate content copy.

Both timestamp callers keep this output held through their signature checks.
CAdES verification builds it only inside the existing permitted-algorithm
short-circuit. A memory refusal returns before the crypto-result `is_ok()`; it
never becomes an invalid-signature verdict or a timestamp failover.

## Scope

This covers retained owned buffers built directly by `parse_cms` and its private
SignerInfo parser. It does not claim all native or third-party heaps are admitted.
Policy-field copies, certificate backend decodes and chain-copy internals have
their own accounting or follow-up work.
The separate borrowed-policy-field change does not need to be imported to use
this parser change. DER checks, field order, version rules, signature algorithms
and ordinary invalid-input behavior remain unchanged.

No memory quota, size bound, timeout, algorithm policy, public API or deployment
setting is added. A matching engine/server rebuild picks up the implementation;
there is no worker, guest, SDK or vault-format change.
