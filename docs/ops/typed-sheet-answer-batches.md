# Typed sheet-answer write batches

Sheet-row and folder questions still decide each selected unit once and prepare
one proposal. The resolved `sheet_answer_limits` value and
`max_count_override` bound edits in each write batch, not the total decisions
retained in that proposal. Vault, artifact, sheet, untrusted and holder minima
are unchanged. An unavailable policy or zero batch size is not unlimited work.

A proposal larger than that value sends ordered chunks of its original edit
plan through the same edit session. Each chunk starts from the preceding
chunk's actual workbook bytes and decomposed package. Applied operations and
warnings are combined in order. The existing outer pipeline checks the combined
report, recalculates once, verifies the resulting workbook and creates one
proposal with the original run reference and answer bundle. The unit decider
is not called during writing or Keep.

The temporary chunk-plan vector uses the host's existing document-resource
reservation and wait. This reservation covers that vector's representation,
not its nested strings, the combined result or the whole workbook heap.
Native reads and projections share the same resource operation. Authenticated
sheet and folder preparation supplies the ask's existing deadline; a direct
proposal or a carry without that deadline adds no new clock. A host without
a registered document-memory port keeps the existing measuring-only behavior.
No separate count queue, timer or default limit is introduced.

Keep does not reject an already-prepared proposal because its total answer
count exceeds the current batch size. Existing authority, source-version,
manifest, consume-once, resource and transaction checks remain. In particular,
folder-answer source changes keep the original held proposal retryable; the
write batch does not repeat any of its decisions.

## Remaining work

This is a source implementation, not a production compile or runtime proof.
The full FIX 9815 retention contract is still partial: a resource or deadline
error during preparation can return before a proposal exists. Durable storage
and retry of decided-but-unstaged answers must preserve the same decisions and
run reference rather than replay the decider. Complete heap accounting,
count-domain admission behavior and hard-time bounds are not established here.
