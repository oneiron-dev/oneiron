# Ask-and-serve read consumers

`POST /api/search/semantic` has an endpoint-local override of stock JSON's
body-byte ceiling. Its existing `[limits].semantic_query_bytes` row measures the
original decoded text and asks while serving the full request. This row is not
a JSON envelope cap: escaping and other fields do not create another quota.
All other routes keep their existing body limits. Authentication, JSON errors,
empty-text validation, deadlines, scope, embedding and projection are unchanged.

This transport change is not a body-memory or embedding-concurrency guarantee.
The JSON body and decoded text are still buffered. Resource admission for that
buffering and the endpoint/one-space embedding paths remains separate work.

`messages.durability` measures `RequestedResultRows` once after a successful
actor-readable MESSAGE projection, when its read transaction has returned.
Missing, hidden or non-MESSAGE rows, absent values and read errors do not ask.
The default of 100, zero-to-one behavior, cursor, receipt/history cohort and
provenance are unchanged. The requested count is served without another clamp.

Neither slice changes a numeric constant, policy default, wire format or stored
row. A normal matching engine/server update is enough; no migration or client
configuration is needed. These are source changes, not runtime/resource proof.
