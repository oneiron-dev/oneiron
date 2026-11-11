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
