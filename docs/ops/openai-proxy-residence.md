# OpenAI proxy recall on an Opened device

The OpenAI-compatible proxy keeps its local recalled text first. When both
its caller and the selected model are on this device, it also asks the home
through the same authenticated home-recall door used by other recall callers.
A narrower caller uses its own forwarded holder proof, never the device
owner in its place. The original recall deadline still bounds the request.

The prompt carries the home's answer as a separate `residence` JSON object
following the local text. The object keeps the native `source`, `complete`,
`capped` and `hits` fields. A hit carries only an entity id, the home's score
and its month window. It carries no body and does not open or promote the
window. A home-only answer can therefore produce a reference-only memory
block. Local item order is unchanged; home scores are not compared with
local scores.

A call whose caller or model is off this device keeps the existing local-only
recall. The current home-search proof does not attest the full onward model
destination for a remote-only row. The proxy neither fabricates that proof
nor newly refuses the existing local prompt. Local-only and incomplete home
answers keep the native residence status. No memory block is injected when
there is neither rendered local text nor a home reference.

Home references are discovery data, not locally read bodies, current grant
standing or corroboration. The proxy's producer list still names the local
rows actually read. Existing credential, scope, retained-payload and final
answer-release checks are unchanged. Off-device home-reference delivery and
its destination-bound proof remain unbuilt.

## Before the first sync connection

After the server resolves an actual configured or enrolled home, it records
the existing configured residence mode before the connection opens. The
normal residence resolver still applies the vault preference and the elected
home's All mode. A configured Opened device with no attached connection thus
reports local-only, incomplete coverage instead of claiming a whole answer.
An attached connection's live or last mode takes precedence. A vault with no
configured home keeps the existing whole-local behavior.

Recording failure is logged and does not stop the existing sync start. This
record is in-memory only. Invalid configuration before a home is resolved,
or a failed residence-policy read, is not proved complete by this change.
No configuration default, numeric limit, timeout or wire format changes.
