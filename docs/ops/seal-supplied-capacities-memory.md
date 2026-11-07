# Supplied signature-revision capacity list

`native/profile/assembly.rs` reserves the supplied-revision capacity list on
the same seal-operation memory ledger before it allocates the list. The
reservation is the source revision count times `size_of::<usize>()`. A
fallible exact reservation makes room for at most one capacity per source
revision, so filtering, sorting and deduplication need no list growth.

The original ByteRange filter, ascending order, duplicate removal and retry
rung selection are unchanged. The engine-written revision path has an empty
source list and allocates no list buffer. No count limit or policy is added.

The resulting `Held<Vec<usize>>` stays alive across every capacity attempt.
Its vector drops before its ledger guard. Per-attempt CMS, issuer/serial,
signature and timestamp holds remain separate and unchanged; this hold
accounts only for the capacity list. A ledger refusal or allocation failure
returns the existing typed memory error at `PdfIncrementalUpdate`, not an
invalid-document result, short-capacity retry or timestamp failover.

This is a retained-list slice of FIX8452 / FIX12780, not whole-heap closure.
Allocator capacity rounding, backend-owned buffers and third-party parse
heaps remain outside this claim. It changes no external format, API,
configuration, default, dependency or deployment requirement.
