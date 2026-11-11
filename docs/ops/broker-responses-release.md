# Broker dispatch release

A run with a dispatch release keeps the callback in the daemon. The daemon
checks the original lease after key retrieval, before forwarding the call frame.
Before each physical provider write, the broker asks the daemon again on that
same call socket. HTTP checks cover the initial request, Anthropic's gzip/plain
resend after 400/415, and the shape's checked download redirect. Responses checks
cover the initial create and its optional whole-turn retry on the same provider
WebSocket. Gzip fallback, stored chaining and the existing redirect remain; no
second call is admitted.

Each request and approval carries the original call id, whole-turn/request
digest and the exact dispatch point. The daemon accepts the initial point once,
then only that shape's retry: `plain_retry` for Anthropic Messages, `redirect`
for a download shape, or `whole_retry` for Responses. HTTP points are before the
reply header; the Responses retry is in the body phase. Only a successful
original release check begins that lease's physical attempt and sends approval.
The broker waits for that exact approval before its original provider write.
It never treats a lease id as permission.

A release error stays typed in the daemon. It is not encoded as a broker failure,
upgrade refusal or unsent-call proof. The daemon closes the call socket without
approval, so the broker's pending check ends without another provider write.
Existing call deadlines cover the control exchange and the remaining HTTP
request timeout is refreshed after approval. There is no new timer, budget,
retry, permission, provider switch or configuration option. A call without a
callback keeps the ordinary provider route and does not ask for approvals.

## Deployment

The daemon and broker must be updated together. Broker protocol version changes
from 3 to 4, with no compatibility reader. Every call frame has one release-mode
byte after its key (`0` ordinary, `1` released); the normal Responses whole-turn
segment stays before the key. Both ordinary and released writers, the reader
and the queued-expiry skip reader use this same format.

The reply length word `u32::MAX - 1` introduces a bounded control record, not a
provider chunk or header. Control records use the existing header size bound.
All request bodies, whole-turn checks, key custody and provider retry bytes keep
their existing bindings. A successful approval is an attempt boundary, not a
provider-execution or usage measurement.

Source implementation alone does not demonstrate public-phone activation or
runtime privacy. The public entry still uses the ordinary `None` carrier until
its separate activation work lands.
