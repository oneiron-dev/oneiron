# Managed booking-only app socket

A supervisor-attested stale owner sign-in can open `/ws` without the MCP
subprotocol for booking RPCs. The upgrade uses the same stale-holder predicate
as the booking-only MCP carrier. A slip, bearer credential, live owner or
unmanaged request keeps its existing upgrade path.

The carrier negotiates the existing app protocol hello. It then accepts pings
and the verbs returned by `booking_payer_verbs()`. This is the same native
booking-payer list used by MCP, not a second list of tools. Other RPCs require
sign-in again. Sync, root, document, presence, machine, subscription and
`auth.bind` frames do not run on this carrier.

Each booking call resolves the original managed session holder again and runs
through the existing facade RPC dispatcher. The native booking doors recheck
publication, action tokens, admission, grants and payer. The upgrade's verified
locality and machine accompany both the caller and the send-time row release.
No live-query session or subscription is opened. Replies use the existing
`Connection::release_for` and guarded transport.

Call context is captured at arrival. Missing room and session fields retain the
upgrade's placing headers; a supplied call context still goes through the
ordinary facade's context checks. A subscription named on this carrier is not
open here and receives the normal missing-subscription result. The upgrade's
invocation is never reused for a later call. Signing audit observes the actual
upgrade peer and user agent.

An idle socket holds no reap admission. Each admitted asynchronous booking call
holds the existing `OwnerWrite` admission through its dispatcher, result encoding
and receipt. The admitted task runs to completion even if its answer waiter goes
away. When the engine pauses writes for reap, the socket returns the existing
managed pause body in `rpc.err`, without running the verb or writing a receipt.
Pings and protocol-refusal receipts use the existing synchronous receipt gate.
Vault deletion and engine stop use the ordinary transport and upgrade lifetime;
the carrier drains calls it already admitted before ending.

No protocol version, operating limit, timeout, default, configuration or
credential format changes. The existing per-socket verb concurrency limit is
reused. Full replication remains owner-grade and its connection loop is unchanged.
