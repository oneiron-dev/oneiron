# Reader parent caller recovery

A read or summary child's recipient is the caller at its parent's latest actual
host entry, not the recipient at the child's birth (FIX 1837).

The host writes `CODE_RUN_READER_CALLER` on the parent's existing reader route
before it updates its live caller cache. Both steps, and the cache-miss read,
use the same short caller mutex. No mutex is held over an await. Storage errors
use the entry's existing error path before its live entry changes.

A live note for the same route and actor takes priority. After cache eviction or
restart, a durable note is usable only for that same actor and route, with a
present install machine id that equals the handle's loaded signer in the same
store snapshot. Unknown or different hosts keep the existing unproved off-device
destination. An entry without a loaded host overwrites the old note with an
unknown host; it never leaves an older host note as its current entry.

The row keeps the full destination, including every proved machine and exact
connection key, without using the lossy `peers()` projection. The existing read
door still revalidates all recipient keys and world settings in the serving
snapshot. The note is data, not a credential, grant, or owner proof.

Canonical runs use canonical reader rows. Session runs use their existing routed
session view and participant. Route equality prevents a composed session view
from taking a canonical run's caller note. Off-record overlay notes disappear
with their session. Scoped-agent doors and their lease checks are unchanged.

The actor erase hook removes its caller notes and retires their side-row
custody. Writes and reads meet the existing actor-deletion markers. Checkpoint
content carries the row; restoring it on another install does not qualify the
old install's local recipient. No freshness age or child-enqueue comparison is
added: a valid parent entry normally precedes its child's enqueue.

The existing clock, window, listed models, spend, lease, and cache-eviction
values are unchanged. Deployment needs the updated engine and server together;
there is no configuration, compatibility reader, migration, or guest protocol
change.
