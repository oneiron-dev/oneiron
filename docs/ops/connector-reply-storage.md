# Connector reply raw-body storage

The first JSON `tools/call` response keeps its raw bytes in an anonymous
vault-owned spool. The complete response is still accepted without a new
size cap. A batch keeps the first response that answers the call and keeps
the original whole-batch bytes for the terminal bridge. The typed batch
reader parses one message at a time. It retains the first answer, wipes
other complete messages, and still validates every remaining element and
trailing byte before returning. A malformed later element or trailing data
still makes the reply unreadable. Each message can still be arbitrarily
large; the credential-clearing pass still parses the whole raw batch.

`RawOutboundBody` owns either an existing byte allocation or that spool.
Clones and ranges retain the same owner. Each reader has a separate logical
position. File seek and read run under one shared lock; cloned file
descriptors are not used as independent cursors. Diagnostics reveal only
the byte count. Byte allocations are zeroized at their final drop; spool
files use the archive factory's owner-only, anonymous, delete-on-close
lifetime. This does not promise physical disk overwriting.

## Clearing inside the credential door

Raw JSON clearing still uses the value released by this send's original
credential callback. Strings and keys are cleared through native
`SentValue::clear_json`, including decoded escapes and the raw-then-trimmed
replacement order. Unchanged JSON keeps its original bytes. Changed JSON
uses the native compact serialization. Inline event and question bodies
still use `SentValue::clear_bytes`.

After that original clear, the first `tools/call` answer moves any byte-backed
raw body into the same anonymous spool before acknowledgement, deferral, or
retry-question handoff. This releases the old allocation when its last owner
drops. An existing spool is kept without another copy. If the storage move
fails, the original byte-backed body is retained without a new send failure.
The typed response remains in memory; this does not stream the event parser.
The initial stream-question handoff uses the same placement after its original
clear, including when a question worker cannot start.

Clearing detects change during the existing string and key walk without
cloning the whole parsed Value when there is at most one effective pass,
both passes can only shrink or only grow strings, or the credential and
replacement have different non-whitespace character sequences. The last
case compares only those two texts with allocation-free iterators; it does
not walk the reply again. A nonempty all-whitespace credential still has
its raw pass. The original full-Value clone and final comparison remain
when the replacement text is longer than the nonempty trimmed credential
but shorter than the raw credential, and both texts have the same
non-whitespace character sequence. This distinction does not change the
returned bytes, replacement order, or handling of malformed bodies.

The raw body is cleared before the reply becomes acknowledged, deferred,
or handed to a question worker. An unreadable spool or failed clear write
uses the existing `connector_reply_unreadable` ambiguous outcome at that
point. It does not turn a recorded ACK into a new send. Typed replies and
failure labels are still cleared before the credential callback ends.

## Transport and program settlement

The transport moves its body into the send's terminal bridge instead of
making a full byte copy. The turn-program bridge hashes the same sequence:
STEP domain, frozen payload hash, then the exact returned bytes. No body
still means the empty byte suffix.

The existing actor-gone check, nested STEP savepoint and side-row admission
wall remain in place. The native inline allocation moves into the wall
instead of being copied again. A body that cannot be admitted keeps its
truthful digest and skeleton. If the digest cannot be read, the existing
best-effort outer bridge logs the failure without failing or retrying the
delivered send or inventing a digest.

## Delivered code-mode replies

A direct `connector.call` answer with outcome `delivered`, or an answered
`self.use` whose native receipt names `connector.call` and whose result is
delivered, crosses the existing 512 KiB result representation threshold
before the write receipt serializes its answer. The recording host lends a call-scoped publisher.
It uses the normal reply spool, admission wall and run-owned occurrence,
with the host's result-memory share when one was lent. No answer is refused
or truncated for its size. An unplaceable secret still gives typed
unavailable content without storing the body.

The admitted body, its run-owned occurrence and the final write receipt
commit in one native writer. The receipt uses the original generation
compare and erase fence; a turn program's answer settles in that writer
too. A failure before commit leaves no published occurrence without its
receipt. Spill reservation retries still happen before the receipt callback.
An inline or unplaceable answer keeps its original receipt-only path.

The same write receipt keeps the native output descriptor and binding name
beside its result card. These are host metadata, not a descriptor recovered
from a guest card. If the receipt commits but the step checkpoint does not,
a replay admitted by the original door adopts that exact occurrence into
the recording host. Door acknowledgement and host adoption happen only
after commit. The receipt does not acquire a second occurrence.
Actor response erasure releases the original run's occurrence using the
native response-owner row, even before the step adopts it.

`self.use` keeps its existing whole-envelope representation: status and
receipt stay inside the same stored bytes as its result. The publisher
does not replace just the inner result. Selection reads only the native
headers without cloning the whole answer. Held and pending calls still
park as before. Question-bearing answers keep their existing path; they
are not selected by this early publisher.

## Remaining whole-body adapters

This is not a bounded-memory implementation of the full connector result
path. The typed JSON response and credential-clearing comparison still
hold whole Values. SSE events, control replies and later retry responses
still use their native in-memory readers. The stored STEP body is still an
admitted Vec. Door-hook publication, settled-wait publication, streamed
JSON clearing, and spool-aware stored replay admission remain separate
work. This transaction repair selects only delivered connector answers,
direct or in the answered native `self.use` envelope, on the canonical
recording-host path. It does not change session or scoped-call publication. The existing 512 KiB result representation
threshold is unchanged.
