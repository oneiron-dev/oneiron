# Reaction signal read deadlines

`POST /v1/core/context-pack` can carry a reaction feed beside its context pack.
The existing `signals_since`, `signals_person`, `signals_after` and
`signals_limit` controls keep their meaning. Signals are globally ordered by
recorded time, reaction id and put/removal, then filtered by the caller's scope,
disclosure and optional room before output pagination. A cursor never names a
signal withheld from that caller.

## Explicit caller budget

An optional `signals_deadline_ms` names the milliseconds the caller will spend
on the signal read, filters and page construction. It uses the existing native
request-deadline range, 1 through 60000. The server validates the value and
requires `signals_since` before it starts paid pack work. The budget itself
starts when the signal read begins, **after** context-pack assembly. It is not
the context pack's internal retrieval deadline.

Omitting the field keeps the original complete signal read with no signal
budget. A supplied budget that completes returns the same feed and page as an
unbudgeted read of the same snapshot. Native callers can use
`Vault::reactions_since_with_deadline` with a caller-owned `RetrievalDeadline`;
`Vault::reactions_since` and `Vault::reactions_since_page` retain their existing
signatures and behavior.

The native scan keeps one read transaction for its complete reaction snapshot.
It checks the same monotonic deadline and explicit cancellation before the
scan, between records and returned reaction rows, and around sorting. The
server checks that deadline again during scope/room filtering and around page
and signal DTO construction. Checks are cooperative: an operation already in
progress, such as one record's native reaction fold or sorting, can finish
before expiry is noticed. This is not a hard preemption or wall-time bound.

## Expiry and retry

Expiry discards all collected signals. HTTP returns **408** with the normal
core error envelope and code **`DEADLINE_EXCEEDED`**. Its details name
`field: "signals_deadline_ms"`. No context-pack success, partial signal page or
advanced `signals_next` is published. Retry from the last successfully saved
cursor, increasing or omitting the explicit deadline if needed.

The native error is `Error::Io` with `std::io::ErrorKind::TimedOut` and the typed
source `reaction::ReactionSignalDeadlineExceeded`. Only that typed source maps
to this HTTP response. Other native I/O failures keep their original mapping.
The same native `reaction::check_reaction_signal_deadline` checkpoint is
available to a caller that filters the complete feed before pagination.

A signal deadline does not set the context pack's `deadline_exceeded` statistic
or create a resumable partial scan. Authored-record scan order is not global
signal order. Publishing an early output cursor could skip an older signal on
a record not yet visited. The failed request therefore publishes neither
signals nor a cursor; its retry repeats the complete read.

No new default budget, output count limit, index, table, configuration or
migration is introduced. The existing output page geometry is unchanged.
Deploy only matching engine/server code when authorized; no worker, guest,
image, or vault-format action is needed.
