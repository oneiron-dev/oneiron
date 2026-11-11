# Managed booking-only app socket

A supervisor-attested stale owner sign-in can open `/ws` without the MCP
subprotocol for booking RPCs. The upgrade uses the same stale-holder predicate
as the booking-only MCP carrier. A slip, bearer credential, live owner or
unmanaged request keeps its existing upgrade path.

The carrier negotiates the existing app protocol hello. It then accepts pings
and the verbs returned by `booking_payer_verbs()`. This is the same native
booking-payer list used by MCP, not a second list of tools. Other RPCs and sync,
root, document, presence, machine, subscription and `auth.bind` frames do not run
on this carrier. Its mode is fixed at upgrade; no frame switches it to full
replication.

Each booking call resolves the original managed holder again and runs through
the existing facade RPC dispatcher. The native booking doors recheck
publication, action tokens, admission, grants and payer. The upgrade's verified
locality accompanies the caller; its locality and machine accompany the
send-time row release. No live-query session or subscription is opened. Routed
replies use the existing `Connection::release_for`; unwrapped refusal frames
need no row release. Both paths send through the guarded transport, as the
ordinary app connection does.

Call context is captured at arrival. A supplied call context still goes through
the ordinary facade's context checks. A subscription named on this carrier is
not open here and receives the normal missing-subscription result. The
upgrade's invocation is never reused for a later call. Signing audit observes
the actual upgrade peer and user agent.

An idle socket holds no reap admission. Each admitted asynchronous booking call
holds the existing `OwnerWrite` admission through its dispatcher, result encoding
and receipt. The admitted task runs to completion even if its answer waiter goes
away. When the engine pauses writes for reap, the socket returns the existing
managed pause status and body as `rpc.res` result chunks, without running the verb or
writing a receipt. Pings, protocol-refusal receipts and routed send-time release
use the existing synchronous receipt gate. Release can replace a recorded answer
with a refusal receipt, so it must not run outside admission after the call
completes. If the vault freezes before that release, the socket closes without
running release or writing the replacement receipt; the call's own receipt
stands.

Vault deletion and engine stop use the ordinary transport and upgrade lifetime;
the carrier drains calls it already admitted before ending. A booking call wakes
the vault from slim through the ordinary inbound resume path.

The implementation is `handler/connection/run/booking.rs`, selected by the
upgrade dispatcher in `handler/connection.rs`. It uses the shared
`ManagedCarrierContext::admit_call`; no second booking loop is needed.

No protocol version, operating limit, timeout, default, configuration or
credential format changes. The existing per-socket verb concurrency limit is
reused. Full replication remains owner-grade and its connection loop is unchanged.
