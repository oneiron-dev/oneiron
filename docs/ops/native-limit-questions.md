# Native limit questions (raw host vaults)

A vault the low-level `NapiVault` binding opens itself keeps its engine `[limits]`
questions where the host that opened it can read them. The open installs a
per-vault collector on the existing `LimitAsk` port after the open stands and its
keystore is installed, then the opened embedding width asks once against the
`limits.embedding_dimensions` row. The work is served either way; a question never
refuses, caps, or truncates.

The collector keeps the last crossing per actual engine row: the row's key plus
what the row stood at and what the work measured. No actor, query, value,
credential, or timestamp is kept. Storage is bounded by the row enum itself.
Recording takes a short mutex and returns; it touches no storage, waits on no
notified work, and holds no vault handle.

The host’s `nativeLimitQuestions()` method serves the kept crossings with both counts exact: `u64` values
cross napi-rs as BigInt, never through `f64`. A bound view
shares the vault and its sink but exposes no whole-vault crossing metadata. An
origin host receives an empty list where no row crossed yet.

This covers raw host vaults opened outside the SDK registry only. The facade
`OneironClient` path, other native bindings, the Q/machine-derived memory floor,
and runtime behavior remain unproved here. This is not a whole-request coverage
claim, a no-hang result, or a speed improvement.
