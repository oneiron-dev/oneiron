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

The native anonymous-chat call now obtains its policy configuration from the
request-owned factory. At server attachment, the existing
`[models.decisions.owner_policy]` revision, wording and `budget_ms` fill an
unbound owner decision slot after the configured model rungs are built, using the
existing embedded-owner principal. An already-bound owner decision slot wins.
An absent section or unavailable owner principal leaves the old configuration in
place. The remaining host policy wording, dials and notices stay unchanged.

The factory constructs its request queue from this same server's live recipient
hub only after finding configured owner decisions. Configured None returns the
old configuration before any hub, queue or private run is created. Configured
Some keeps its snapshot's principal, questions, rungs, paired/person settings and
budget. It binds a separate unrecorded run, its own existing private budget and
the actual request credential guard, not the responder's or Checker's meter. Its
queue pin names `private.human.ask` at the existing host protocol revision, not
the durable ask queue. This identity is neither an answer nor authority.

These run-owned policy reads use the ordinary provider entrypoints with the
unrecorded run; they do not use the captured-generation entrypoint. Captured-only
unsupported results are not proof about this path. Its native unrecorded views,
recording guards and borrowed physical-send guards remain in place. This source
wiring is not proof of a running instance, every provider, rendering or runtime
privacy. The full-sync socket upgrade still admits only owner-grade credentials;
these registrations do not establish a general non-owner holder notification
route.
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
server-side housekeeping observers ignore this private event; their existing
status, error and authority-catch-up handling is unchanged. They are not a user
interface. Rendered delivery, non-owner holder routing and
runtime privacy must not be inferred from the native event or queue's existence.
Ordinary anonymous, Checker, RPC and subscription paths keep their existing
behavior. No stronger model path is enabled by this carrier.
