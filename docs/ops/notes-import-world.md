# Notes import WORLD placement

The owner can select an existing epistemic WORLD for new imported notes.
This does not create a WORLD or infer sharing from a path, folder name,
frontmatter, audience or Files placement.

## One-shot import

`oneiron import notes <folder> --out <batch> --world <world-id>` writes the
selected hex id into the batch. The owner preview, approve and decline
operations use that same batch. The optional JSON field is `world`.
Changing the selected WORLD changes the approval digest and decision slot.
The chosen InWorld edges land in the same transaction as the new notes,
approve-once receipt and decision slot. The existing consent spend remains
part of that transaction.

Omitting `world`, or selecting the reserved base WORLD id, means base
reality: no InWorld edge. Those two choices have the same digest. Batch
hashes bind this normalized choice; no old-format reader is provided.

## Standing Notes folder

`oneiron import folder attach <folder> --world <world-id>` stores the choice
on the standing Notes source. The owner HTTP door
`POST /v1/owner/imports/folders/attach` accepts the same optional hex `world`.
The CLI forwards the selection to that door when the vault's running server
holds its writer lease. Omitted `world` stays omitted in the request.

Each rescan carries the source's selection into new-note landing, including
the existing per-file retry path. Rescan, supersede, retract, pending-link,
partial-scan and original-file handling otherwise keep their behavior.
Existing notes are not moved or backfilled.

## Files sources

A Files source still uses its existing `FilesPlacement.world`. That choice
takes precedence over the independent Notes source field. The Files choice
is selected before base normalization, so a Files base placement cannot fall
through to a different Notes WORLD. Files attachment passes no Notes WORLD.

No additional existence scan, foreign-WORLD refusal, grant, approval layer
or fallback is added. The existing same-transaction birth/write protocol
handles the selected placement and its errors.
