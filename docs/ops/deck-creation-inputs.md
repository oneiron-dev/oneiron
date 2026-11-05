# Deck creation input receipts

`vault.artifacts.create_deck` returns a `DeckCreationRecord` when creation lands.
The deck, its first version and this receipt commit in the same writer transaction.
An Ask does not create a deck or a receipt.

## Recorded inputs

- `asset_inputs` maps each bound outline asset id to its pinned input.
- `font_inputs` lists the font inputs successfully loaded for layout, in request order.
- Each `CreatedInput` contains `source` (`artifact`, `version`), `content_hash`
  and the stored `provenance_kind`.

These are observed input identities, not claims that every bound image was placed
or every loaded font face measured text. They do not assert a license or permission
for reuse. Held assets retain their existing empty rights list until real rights
evidence is supplied by a producer. The receipt does not add actor ids, claim ids,
raw input bytes or a new authority record.

## Reads and storage

Asset metadata comes from the creation path's existing validated metadata read.
Font metadata comes from the same version record and snapshot that select the
loaded bytes. Observing that metadata adds no claim check, second body read or
new admission requirement. Design-direction reads keep their existing path.

The required fields travel through the existing named creation row, its CONTENT
restore class and generated response mirrors. There is no new side table or
compatibility reader. Erasing a created artifact removes its keyed creation row.
Input references remain historical receipt metadata, as the template and outline
references do; this is not a claim of full erasure or checkpoint closure.

Deploy matching engine, server and generated clients when using the new response
shape. No new setting, threshold, dependency, format migration or organ is needed.
