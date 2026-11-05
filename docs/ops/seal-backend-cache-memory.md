# Seal backend identity cache memory

The process organ creates a fresh private backend for each call. Native assembly
asks for the signing identity once, before its capacity attempts, and owns that
identity across signing and validation-material gathering. The backend now keeps
only the `Copy` signature algorithm. The decoded identity moves directly to
assembly; no second retained DER identity or returned deep clone is created.
Signing attempts reuse the cached algorithm without copying certificate vectors.

The two production factory consumers are sealing and verification. Sealing asks
for the identity once per call; verification never asks for it. The backend does
not escape that call. A cold signing-algorithm lookup still asks for the identity
before signing, with its mutex guard dropped before that fallback. Public
`SealBackend` and `SigningIdentity` types are unchanged.

## Previous full-identity cache

The previous design retained a separate signing-certificate vector,
certificate-chain vector and the chain's certificate vectors. It reserved their
actual retained capacities from the configured `SealMemoryProvider` before
publishing the cache entry. The decoded identity moved into that entry, and the
entry dropped its identity before its service lease. Cache hits reused that
entry; the process host conservatively kept its reservation until call end.
That separate owner no longer exists, so it needs no lease or duplicate charge.
Assembly's returned-identity hold remains on the native operation ledger.

The native `BackendError::Memory` variant and mapper remain available. They keep
the original typed refusal at `BackendSign`: memory-floor, resource-deadline,
cancellation, service failure or missing service. They do not turn a memory
failure into an invalid identity, a backend rejection or a profile downgrade.
Other backend failures keep their previous mapping.

The identity answer and its decoding still exist before assembly takes the
returned identity. Reply/codec allocation, chain conversion, allocator overhead
and all backend memory are not covered by this narrow removal of an unnecessary
DER owner and copy. It is not a whole-heap or pre-admitted-reply claim.

Identity bytes, algorithm, production identity-ask count, signing requests,
certificate validation and the moving call clock are unchanged. No size bound,
timeout, configuration option, protocol change or migration is added.

## Initial identity reply decoding

Before decoding the initial identity answer, the process backend reserves the
protocol codec's `read_cost` for its encoded byte vector and typed decoded
identity through the same call's `AskedMemory` service. This is before signing
starts. It creates no new provider, operation ledger or retained DER cache.
The existing argument-decoding leniency for an unavailable service is retained;
other resource refusals take the existing typed `BackendError::Memory` route at
`BackendSign`, not invalid identity, backend rejection or profile downgrade.
Ordinary codec errors still report an invalid response.

The reservation follows the process host's existing conservative lifetime:
granted bytes stay reserved until call end, even after temporary buffers drop.
The decoded identity still moves to native assembly, where its existing retained
hold remains. This does not establish peak-exact accounting or replace that hold.
The codec's own `Value` measurement/encoding traversal stack, possible chain
conversion allocation, allocator capacity slack, the original reply envelope and
other backend replies remain outside this slice. In particular it adds no
memory wait or refusal after `seal.sign` may have issued a signature.

## Initial identity codec traversal scratch

The initial identity path also supplies the protocol value serializer with the
same call's `AskedMemory` service for its traversal stack. This covers the
`read_cost` measurement pass and both count/write passes of the identity's
`to_vec` conversion. The wrapper preserves the codec's existing bytes and shape
count; decoding still uses `from_slice` on those bytes. That temporary encoded
vector drops immediately after decoding, before the returned identity is built.

The codec admits the full replacement stack capacity before each growth, while
the old stack is still alive. Actual capacity above that request takes a further
grant. If that grant fails, the adapter keeps the typed refusal and the value
wrapper ends that serialization pass with an error, including a pass that had
otherwise finished successfully. This prevents a failed measurement from
starting the subsequent encoded-buffer allocation. Missing-service leniency
and all other typed resource errors keep the initial identity path's semantics.

The host still holds every grant until call end. Freed traversal stacks do not
return grants through a nonexistent release API. Accounting is conservative
across all three passes, not an exact peak or a guarantee that allocator excess
was known before allocation. Chain conversion, the original reply envelope,
other argument/reply/report paths and total heap use remain outside this slice.
No signing request, signing retry, call clock, provider, ledger or limit changes.

## Argument codec traversal scratch

The four process verbs (`seal.pdf`, `seal.verify`, `seal.inspect`, and
`seal.prepare`) now use the same private admitted-value decoder for their
arguments. Each reads its arguments before resolving inputs or starting native
work. The decoder borrows the call's existing memory service, measures the
value with admitted traversal scratch, reserves its encoded/decoded cost, and
uses the admitted wrapper for both encoding passes before typed decoding.
Temporary encoded bytes stay inside that helper and drop before it returns.

The identity caller still maps typed resource refusals to `BackendError::Memory`
and ordinary codec errors to `InvalidResponse`. Argument callers keep their
existing `what`-qualified bad-request errors for codec failures, `Cancelled` for
cancellation, and `Budget` for other resource refusals. The original zero-byte
shortcut remains in `ReplyMemory::reserve`; missing-service leniency is unchanged.
The helper accepts a protocol `Value`, not an arbitrary serde input.

Both callers retain the per-pass refusal check for actual-capacity settlement.
They share neither a new provider nor a second operation ledger. Host grants
remain conservative until call end. This covers only these initial reads, not
signature/fetch reply decoding, report conversion, chain conversion, allocator
overhead, the original reply envelope or total heap use. No wait or retry is
added after a signature request can have issued a signature.
