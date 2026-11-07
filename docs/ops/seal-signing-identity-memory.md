# Native-retained signing identity

The native profile assembler keeps a backend-returned `SigningIdentity`
across all signature-capacity attempts and validation-material gathering.
After the backend hands it over, the assembler takes a hold on the same
seal-operation ledger for the retained signer-certificate capacity, the
chain vector's allocated slots, and every chain certificate's capacity.

A `Held<SigningIdentity>` owns these buffers and their ledger guard. The
buffers drop before the guard returns its credit. Per-attempt CMS working
copies and validation-material clones have separate, unchanged admissions;
they do not account for this longer-lived original. Memory refusals use
the existing `BackendSign` resource-error path before certificate checking,
not an invalid-identity verdict, short-capacity retry or TSA failover.

The organ's backend also reads the cached algorithm directly when signing
a revision, instead of cloning the entire cached certificate identity only
to discard its buffers. This is a `Copy` read under the existing cache
mutex. The lock drops before the old cache-miss identity request and before
any signing ask. The cache-miss path, algorithm, ask order, authorization,
signature validation and error mapping remain unchanged.

This is a local retained-ownership slice of FIX8452 / FIX12780. The hold is
post-handoff accounting, not pre-admission of backend allocation. It does
not cover the backend's separate cache, identity reply/codec transients,
engine key storage, allocator slack or third-party parsing. It changes no
public API, format, policy, default, cap or configuration.
