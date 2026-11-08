# Root document transfer

The server is authoritative for the sync root document. Clients never publish root writes.
A root export is one immutable Loro snapshot or delta. The transfer preserves its original
bytes, including a shallow snapshot; it does not replay visible historical prefixes.

Root exports with at most the existing 8 MiB decoded payload limit keep their tag-0 frame.
A larger export uses server-to-client tag 6 (`TAG_ROOT_PART`). Each part has a 48-byte header:

| Field | Encoding |
| --- | --- |
| Whole-export digest | 32-byte BLAKE3 |
| Whole-export length | unsigned 64-bit big-endian |
| Byte offset | unsigned 64-bit big-endian |
| Bytes | Nonempty contiguous slice of that export |

The header counts inside the existing physical payload limit. The server creates and sends
one physical frame at a time. The socket keeps its original revocation and stopping checks
for every send. Initial snapshots, root VV replies, lag recovery and broadcasts use the same
release helper. No new logical size cap, timeout, acknowledgment or durable journal is added.

The client retains one incomplete image per connection. Before reserving its byte buffer, it
uses the existing process-wide physical-memory admission line. This synchronous entry point
does not wait for memory: a real current memory-floor refusal or allocation failure follows
the connection's error/reconnect path. The reservation tracks the buffer's actual capacity
and stays alive through the complete image's import and persistence.

All parts must name the same digest and length and have the next exact offset. Only the
complete, digest-verified image reaches the original root import, persistence, lease mirror
and followed-window logic. Incomplete parts do not advance root bootstrap or federation
replay. Errors, replacement, disconnect, reconnect, re-bootstrap and client drop release the
incomplete buffer and its reservation. Reconnect uses the existing root snapshot/VV exchange.
The lease mirror never observes a historical prefix introduced solely by physical framing.
Initial sync counts a large root as one logical opening and does not advance to offline queue
replay while that image is incomplete. A quiet gap during its parts returns to the existing
initial read timeout instead of starting a write-only replay against a server still sending.

Short-lived residence RPC sockets still discard root openings instead of importing them.
Their existing bind-opening count counts one large root image, not each physical part; every
read retains the original absolute RPC deadline. No actor binding or read authority comes
from a root part.

Deploy matching engine and server binaries for large-root transfer. Existing frame layouts
and protocol-version values do not change; tag 6 adds a path for roots the old single-frame
receiver could not accept. No migration, configuration change or service deployment is part
of this source change.
