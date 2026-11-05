# UniFFI opaque JSON output

`WireJson` carries compact JSON text inside a typed foreign record. Its owned
`Lift<serde_json::Value>` conversion consumes arrays and objects with explicit
iterator frames. Keys and scalar values use the active `serde_json` serializer;
array order, object insertion order, escaping and number formatting stay native.
The conversion drains its owned frames before returning an encoding error.

Pending proposal results use a direct typed lift for `vault.artifacts.proposals`,
`vault.artifacts.propose_output` and the proposed result of
`vault.artifacts.append`. The shared client call still completes before this
conversion. The public generated records and their `summary: WireJson` field
are unchanged. Made-by metadata keeps the existing record codec.

This removes the extra JSON-tree record round trip for those proposal results
and recursive rendering and ordinary destruction of their summary at this
boundary. It does not remove recursive JSON values from native proposal getters,
the shared client, verb hooks or the general generated-record codec.

Five nested proposal results (`vault.artifacts.propose_deck`,
`vault.artifacts.body.deck.export`, `vault.artifacts.admit`,
`vault.artifacts.review_slides`, `vault.artifacts.ask`) use the same direct
typed lift. Each consumes its nested `proposed` first. Ask-unit JSON and
non-null narrowed `requested_schema` values move owned into their `WireJson`
leaves. A null schema still reads as absent; false `on_device` and empty
`reasons` still read as omitted. Finite siblings keep the existing record
codec. Other generated result types still use that general codec.

Input parsing, input canonicalization, hook masking, admission and receipts
are unchanged. No end-to-end depth, memory, speed or runtime claim follows from
this output conversion alone.
