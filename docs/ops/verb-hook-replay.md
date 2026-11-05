# Verb-hook callback reads during replay

A live verb hook reads through its caller's lane, narrowed by the hook's grant.
Each successful callback pins the exact request, the response hash and the rows
returned, in response order. An empty row list records a null claim result or an
empty `claims_about` result. It does not authorize a new search.

Replay reconstructs a verb hook's successful callback responses from those row
pins. Each row resolves to the exact live or retained revision with the recorded
full body hash. A pinned point read still passes the hook's current grant-reader
lane and the current grant. Replay renders only those admitted rows, in their
recorded order, then checks the original response hash. It never adds rows from
a broader grant reader or substitutes newer content for a missing revision.

A removed revision, denied row or different response remains `missing_history`.
Storage and callback errors keep their existing error path. A callback request
that does not match its next pin cannot receive a reconstructed response.

The saved input's existing dependency, grant-change and erasure checks still run
before the body. Fact-hook replay is unchanged. No caller credential, read key,
room turn, new response payload or new authority is persisted. Room-kept runs
are not added to the vault's replay index by this change.
