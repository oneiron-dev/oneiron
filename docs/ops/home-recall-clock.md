# Home recall clock pins

An opened device can ask its home for recall discovery references when a text
recall includes `as_of`. The local items stay first and unchanged. The home hits
remain separate references; they do not fetch or promote bodies.

`as_of` is Unix seconds for the query clock, not a historical storage snapshot.
The home resolves time words and ranks recency at that clock. It also applies
the native claim-standing clock used by local recall. A future clock still
judges claim standing at now. Grants and credentials are always checked at now.

The native `residence.search` request carries the optional `as_of` on every
page. A forwarded request signs that exact value beside the existing scope,
caller locality and cursor. The ranked-list revision binds the effective clock.
An explicit clock wins; without one, a continuation uses its cursor clock and
a first page uses now. A changed list uses the existing restart path.

An omitted clock leaves ordinary home searches unchanged. Zero is a valid
explicit clock. The ingress uses the existing recall calendar-range validator.

Media recall and room-turn recall still keep the existing local-only,
incomplete answer. This change does not supply home media vectors or a room
view. No proof, selector, deadline, count or residence policy is widened.

A rollout needs matching device and home engine/server binaries. No SDK verb,
configuration, worker, guest or image change is needed.
