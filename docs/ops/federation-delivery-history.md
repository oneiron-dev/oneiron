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

## Current admitted source image

Each consolidation evidence view also exposes `current_image` for its requested
`source_ref`. It comes from the same scoped-read snapshot as that source's
admission and evidence facts. `learned_at` is the row's write stamp.
`body_hash` is the native domain-separated consolidation hash over the exact live
projected body read by this door, excluding the row metadata header. Its domain
is `oneiron:dreamer-evidence:v1`; it is not the plain BLAKE3 full-row hash in
`delivery_history`, a short-reference byte, or a hash of a cited transcript slice.

The optional `document` pairs the source's own active document id (`doc`) with
its native causal frontier (`at`) in that snapshot. `null` means that this
optional pin is unavailable, including an unmigrated source or a build without
`sync`. A missing pin never withholds the existing evidence result. A document
edit can move this frontier and the projected-body hash without changing the
row's write stamp or its historical landed-row hash.

These facts cover only the requested source itself. They do not refresh frozen
`evidence_refs`, locators, source refs, or MESSAGE pins. A TURN body or its own
document pin does not version its joined MESSAGE transcript. An unchanged row
hash or source image therefore does not prove that all cited text is current.
No freshness boolean, current grant authority, or first-party status is inferred.

This does not complete SYNC-07's typed consolidation input or establish the
canon's unspecified connection/grant-epoch actor attribution. It is not a claim
of runtime, current-content, full-history or first-party-corroboration proof.
