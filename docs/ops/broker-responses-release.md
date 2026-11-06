# Responses broker dispatch release

A run with a dispatch release keeps the callback in the daemon. A key-backed
Responses call uses the same broker connection and the same provider WebSocket
for its initial create and its optional whole-turn retry. It does not disable
stored chaining or admit a second call.

The daemon checks the original lease after key retrieval, before forwarding the
call frame. Before each provider create write, the broker asks the daemon again
on that call's existing socket. Each request and approval carries the original
call id, whole-turn digest and the exact `initial` or `whole_retry` point. The
daemon accepts each point once, in order and in its matching header/body phase.
Only a successful original release check begins that lease's physical attempt
and sends an approval. The broker waits for that exact approval before writing
the original create frame. It never treats a lease id as permission.

A release error stays typed in the daemon. It is not encoded as a broker failure,
upgrade refusal or unsent-call proof. The daemon closes the call socket without
approval, so the broker's pending check ends without another provider write.
Existing call deadlines cover the control exchange; there is no new timer,
budget, retry, permission, provider switch or configuration option. A call without
a callback keeps the ordinary provider route and does not ask for approvals.

## Deployment

The daemon and broker must be updated together. Broker protocol version changes
from 3 to 4, with no compatibility reader. A Responses frame has one release-mode
byte after its key (`0` ordinary, `1` released). Other shapes have no mode byte.
The reply length word `u32::MAX - 1` introduces a bounded control record, not a
provider chunk or header. Control records use the existing header size bound.
All request bodies, whole-turn checks, key custody and provider retry bytes keep
their existing bindings. A successful approval is an attempt boundary, not a
provider-execution or usage measurement.

Source implementation alone does not demonstrate public-phone activation or
runtime privacy. The public entry still uses the ordinary `None` carrier until
its separate activation work lands.
