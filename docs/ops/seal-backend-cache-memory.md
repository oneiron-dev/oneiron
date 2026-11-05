# Seal backend identity cache memory

The process organ asks for the signing identity once per call. Its backend cache
owns a separate signing-certificate vector, certificate-chain vector and the
chain's certificate vectors. It now reserves their actual retained capacities
from the call's configured `SealMemoryProvider` before publishing the cache entry.
The decoded identity moves into that entry; no extra copy fills the cache.

The reservation belongs to the cached identity, not the native operation's
ledger. The cache can survive an operation, so an operation finishing cannot
release its reservation early. The entry drops its identity before its lease.
Cache hits reuse that entry and do not reserve its bytes again. In the process
organ, the host conservatively keeps memory reservations until the call ends.

A refused reservation is `BackendError::Memory`, available with the native
feature. The native backend-error mapper keeps the original typed refusal at
`BackendSign`: memory-floor, resource-deadline, cancellation, service failure or
missing service. It does not turn a memory failure into an invalid identity, a
backend rejection or a profile downgrade. Existing backend failures keep their
previous mapping.

The identity answer and its decoding already exist when this reservation is
taken. This change does not establish pre-admission of reply/codec allocations,
the returned identity clone, allocator overhead or all backend memory. The native
assembly's returned identity is a separate allocation owner. Its accounting must
not be mistaken for this retained cache lease.

Identity bytes, algorithm, identity-ask count, cache-hit behavior, signing
requests, certificate validation and the moving call clock are unchanged. No
size bound, timeout, configuration option, protocol change or migration is added.
