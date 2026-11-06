# Private Human decision delivery

The private policy snapshot takes a request-owned `HumanDecisionQueue`, not the
vault's durable `DecisionAsks`. Its three queue methods preserve the same request,
policy state and consent effect in memory. They create no ASK row, arrival number,
answer waiter, receipt or replay record. A queued ask is not a grant or an answer.

A live socket owns its typed recipient registration. The socket owner refreshes
that registration from its actual bound credential. A producing request selects
only a live holder of the ask's current native role whose credential class and
source lane admit the ask. An owner-grade recipient uses the native owner proof;
Read scope or a configured policy principal alone does not identify a recipient.

An accepted recipient queue owns the payload through send or disconnect. Closing
the producing HTTP request does not discard its only pending copy. Queue success
means a selected endpoint accepted the in-memory payload, not that a person saw it.
No selected receiver means the policy keeps its existing visible unavailable
outcome; the queue does not add a hold or change the configured person rung.

The private send uses the socket's current credential and the original request's
producer credential. A borrowed per-send predicate rechecks role, source lane and
device release at both native handover consults and each drain or flush poll. It
is not stored in a run, provider, lease or global slot. A withdrawn private send
aborts the unsplit socket rather than flushing a queued body during close. The
ordinary send method passes no extra predicate. Whole entity ids and short
references use the native device projection. The event carries the original trusted `AskTo`, not an unsolicited
list of other live holders. Its declared outbound tag is `TAG_PRIVATE_HUMAN` (33),
followed by the request JSON. It is not an RPC response or a made-up subscription.

This is an unactivated source path. The anonymous-chat consumer still uses its
original configuration. The owner-policy factory now constructs its request queue
from the same server's live recipient hub, only after finding configured owner
decisions. Configured None returns before any hub or private run is created. The
factory is not called by the anonymous consumer. The current full-sync socket upgrade admits owner-grade credentials; these
registrations do not establish a general non-owner holder notification route.
Only a socket explicitly advertising the private Human frame kind (`0x81`) is
registered. The native sync client decodes the same typed payload into
`SyncEvent::PrivateHumanAsk`, under the existing decoded-payload bound. That arm
emits no response and skips deferred sync replay. It writes no root, window,
ephemeral state or durable ASK. The application owns the event's request, optional
policy state and consent effect; receiving it does not render or answer it, and
confers no authority or grant. A notification with a different kind, malformed
typed fields or `no_record: false` is a protocol error.

The decoder's build advertises frame kind `0x81` in its hello and
`WireCodecs::OURS`; a peer that lists nothing still has no such support. The two
server-side housekeeping observers ignore non-status, non-error events as before;
they are not a user interface. Rendered delivery, non-owner holder routing and
runtime privacy must not be inferred from the native event or queue's existence.
Ordinary anonymous, Checker, RPC and subscription paths keep their existing
behavior. No stronger model path is enabled by this carrier.
