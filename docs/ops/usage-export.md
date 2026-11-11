# Original usage export over managed ctl

`usage_export` reads complete original stored usage facts for the usage meter bound
to the managed server. It does not enable metering or select a funding owner. The
scope comes from that meter's original owner and native authority vault id, not a
caller-supplied account or the HOST registry UUID. An unbound meter or unreadable,
changed or corrupt event is a read error, not an empty successful result.

The request carries an optional `cursor`. With no cursor it reads the first event.
`After { key }` reads strictly after an original idempotency key. `InEvent { key,
offset, digest }` continues that exact event. The wire keys are the original stored
idempotency keys, never native storage keys or newly generated financial identities.

The response's disjoint `usage_export` field carries an optional `chunk` and `next`.
A chunk includes the original `event_key`, its full serialized-event digest, a UTF-8
byte offset and JSON text. That text is a string containing the existing stored
record's serialization, including original quotes, cost, optional fields, token
counts, allocation reference and source metadata. Integer digits inside this string
must not be converted through JavaScript numbers while forwarding it.

The full response and newline fit the existing control-frame bound. A large event
continues through `InEvent` cursors; no row/count policy or truncation is added.
Full-event completion returns `After` for that event. An offset already at the end
can return no chunk with an `After` continuation; this is not end of the scan. Only
no chunk and no continuation means no further event was found in this scoped read.
Consumers reassemble contiguous offsets under the same key and digest and verify
the complete JSON before mapping its fields. The digest proves source-byte
continuity, not financial acceptance or authority. The frame bound is not a claim
that materializing one stored event has a hard memory bound.

Each page is a fresh read. Idempotency keys are not an append-order sequence, so a
completed scan is not a durable high-water mark: a later event can sort before an
earlier cursor. A later collection pass must account for such arrivals, rather than
permanently resuming after the previous scan's last key. An accepted-event publisher
and its actual source association remain separate integration work.

The read works under the reap freeze without taking the owner-write admission
gate. It writes no producer row, delivery acknowledgment, consumption or retirement
mark. It deletes no original event and changes no grant, balance, rate or price.
Cloud account binding, billing-unit projection, accepted financial effect, serving
retirement and backing release cannot be inferred from a page, digest or empty scan.
The shared contract consumers must be rebuilt together at an authorized deployment;
this source change does not select a deployed native pin or assert runtime activation.
