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

The native recalculation wrapper also reuses an operation exposed by the edit
session. Typed-answer sessions and their batch wrapper expose the original
ask's resource operation, including its existing deadline. A generic session
that exposes none keeps the previous per-call host-resource resolution.
The pipeline's input-workbook copy and its pre-recalc byte copy reserve their
actual vector capacity through that operation before copying. Sessions that
expose no operation keep their original unadmitted byte-copy behavior. Public
`OfficeDoc` and proposal `Clone` implementations are unchanged; this is not
accounting for every copy made by a generic session or a caller.

Resource errors returned by native recalculation or external-link preservation
keep their typed cause; they do not start precision fallback or become an
unreadable-package message. Unsupported workbook features and engine failures
still use the existing host precision fallback. The external-link comparisons
and their non-resource failure messages are unchanged.

Typed-answer validation keeps a temporary vector of cell coordinates. It
reserves the exact element count and any allocator capacity surplus through
the same resource operation before filling it. Sorting only that vector finds
duplicate positions; answer and edit order stay unchanged. The original
per-answer checks run before duplicate detection and keep the same invalid
bundle error, not a first-failing-answer index. The temporary vector drops
before its local hold. Raw stored-bundle decoding and output verification
have no resource operation and keep their unmetered path. This covers only
the duplicate index, not all validation allocations.

The temporary chunk-plan vector and its validated cell text copies use the
host's existing document-resource reservation and wait. The native writer
reserves its returned operation vector and validated text copies before
copying them. Batch aggregation reserves the combined operation and warning
vectors before moving each batch into them. These reservations cover those
vectors and the named native copies, not the whole workbook heap or every
allocation a generic session makes.

Native reads and projections share the same resource operation. The server
hands allocated bytes to live-memory accounting when a local reservation
drops. Where live memory cannot be read, it keeps the dropped reservation in
the operation's allocated lease until that operation ends. This is not a
claim that retained bytes remain leased after the last operation handle ends.
Authenticated sheet and folder preparation supplies the ask's existing
deadline; a direct proposal or a carry without that deadline adds no new
clock. A host without a registered document-memory port keeps the existing
measuring-only behavior. No separate count queue, timer or default limit is
introduced.

The retained OPC exporter keeps its original initial reservation and measured
carry-over. If the output vector needs capacity beyond the output share of
that estimate, it reserves only the additional capacity on the same hold
before growing or copying, then settles any allocator excess before copying.
The ZIP record order, compression, format widths and caller's archive ceiling
are unchanged. The local hold still hands allocated output to the server's
existing accounting on return. This does not establish complete compression
scratch, allocator-reallocation peak or retained-output accounting.

Keep does not reject an already-prepared proposal because its total answer
count exceeds the current batch size. Existing authority, source-version,
manifest, consume-once, resource and transaction checks remain. In particular,
folder-answer source changes keep the original held proposal retryable; the
write batch does not repeat any of its decisions.

## Remaining work

This is a source implementation, not a production compile or runtime proof.
The full FIX 9815 retention contract is still partial. Completed sheet-row and
folder-item decisions now survive a staging or retention error and can be
restaged under the same run reference without replaying the decider; see
[completed typed-sheet answer retry](typed-sheet-answer-retry.md). An error
before the decision loop completes, or failure to commit the completed-answer
row itself, is not covered. Complete heap accounting, count-domain admission
behavior and hard-time bounds are not established here.
