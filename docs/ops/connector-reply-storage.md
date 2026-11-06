# Connector reply raw-body storage

The first JSON `tools/call` response keeps its raw bytes in an anonymous
vault-owned spool. The complete response is still accepted without a new
size cap. A batch keeps the first response that answers the call and keeps
the original whole-batch bytes for the terminal bridge.

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

## Remaining whole-body adapters

This is not a bounded-memory implementation of the full connector result
path. The typed JSON response and credential-clearing comparison still
hold whole Values. SSE events, control replies and later retry responses
still use their native in-memory readers. The stored STEP body is still an
admitted Vec. Early publication to `result_body` before hooks, receipts and
wait serialization, streamed JSON clearing, and spool-aware stored replay
admission remain separate work. The existing 512 KiB result representation
threshold is unchanged.
