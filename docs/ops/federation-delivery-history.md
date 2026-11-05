# Federation delivery history

A federation import records the native grant, source vault, delivering pact,
consent epoch, landed-row hash and placement when an admitted record image lands.
The hash is BLAKE3 over the full landed row, including its metadata header.
The same facts travel in the durable import intent, so crash rematerialization
records the same admission binding without consulting a newer authority fold.

`Vault::federation_delivery_history(records)` reads these local records. The
owner-bound consolidation evidence door also returns `delivery_history` for its
readable sources and the source refs its existing evidence checks admitted.
This includes the existing consolidation promotion result's input/output views.
`null` means that optional history is unavailable. An empty array means no matching
local records were found; neither result proves a complete history.

These are historical delivery facts. They do not establish current grant
standing, prove that the source's current bytes still match the recorded hash,
change its source/trust tier, or make foreign evidence first-party corroboration.
A later landing at the same pact/consent-epoch/record key replaces that key's
recorded image. Deliveries at other epochs keep separate entries.

`delivering_pact` names the native pact. `consent_epoch` names its consent epoch.
They are not aliases for an otherwise unspecified connection id or grant epoch.
No actor, birth, scope, approval, sync admission or evidence-eligibility rule is
changed. Missing attribution never adds a content-read refusal.

The existing delivery and intent tables hold the facts; there is no second
origin ledger or copied origin payload in claim evidence. Delivery keys and
courtesy-deletion epoch/world selection stay unchanged. All delivery-value
readers use one unconditional codec, including builds without `sync`. Values are
80 bytes plus the existing optional 16-byte world; intent values are 128 bytes.
These are current formats only, with no migration or old-format reader.

This does not complete SYNC-07's typed consolidation input or establish the
canon's unspecified connection/grant-epoch actor attribution. It is not a claim
of runtime, current-content, full-history or first-party-corroboration proof.
