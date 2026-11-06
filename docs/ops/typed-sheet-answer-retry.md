# Typed-sheet answer retry

`vault.artifacts.ask` and `vault.artifacts.admit` preserve sheet-row and
folder-item progress after each completed unit, before the next paid call.
Each validated unit decision is also committed before cell conversion and the
outcome commit. They use the same content row that retains the complete answer
bundle before the native workbook writer stages it. The stored row includes the original
question, principal, reversibility, evidence and selected units, every committed
decision and receipt, the workbook version and content hash, the read rows,
and the abstentions and refusals.

Repeat an interrupted ask with the same artifact, run reference and request.
The engine continues after the committed prefix without calling the unit
decider for those units again. Sheet inputs, headers and answer-cell before
values are captured before the first paid call. A retry uses those original
inputs with their original version, content hash and live pin, not a new live
head relabelled with an old pin. Folder output cells use the original workbook
basis. Remaining files are read as the original loop reads each file; completed
files keep their own source, version and live pins. A saved current-unit decision
also keeps those pins and its original read rows. A retry converts that decision
without rereading the file or calling the decider again. Later edits remain
subject to the existing withdrawal-at-Keep rules, not a new resume gate.

If staging fails after all units complete, the retry restages the stored bundle
without calling any unit decider again. The retry uses the new caller deadline
and resolves the current write batch policy. It does not change the original
decisions, source pins or base. A moved workbook still fails the existing
current-source check; the engine does not silently apply old answers to a new
source. Use a new run reference for a new question or selection. A mismatched
request leaves the original row intact.

The terminal sheet and folder paths move their owned complete bundle and receipt
vectors into staging instead of cloning them. This does not consume or delete
the stored answer-progress row. A staging error can still retry that canonical
row under a new caller deadline. The native staging call also keeps one owned
edit plan through application and the exact applied-operation comparison;
it does not clone a second operation vector just to borrow that plan. Before
allocating the native plan vector, the same caller resource port reserves its
validated operation count, excluding abstentions. Any allocator-reported capacity
surplus is admitted before filling the vector. The same hold covers each copied
sheet name and the text or error strings in validated before and after values.
Their byte lengths are reserved before allocating, and allocator-reported
capacity is settled before copying the text into those fixed-capacity strings.
The hold remains alive until the plan and its payloads are freed. The ordinary
operation builder keeps its existing unadmitted clone path; it creates no new
resource port. Each native batch also reserves its local workbook-change vector
before allocation and admits its actual capacity before filling it. The copied
sheet names and text or error values use that same batch-local hold, which stays
alive until those changes are freed after workbook projection. Validation
compares choice text through the same borrowed answer-to-cell projection used
by the owned converter, instead of cloning a temporary cell string just to
compare it. Abstentions, value kinds and native numeric equality stay unchanged.
Validation sets and other scratch, native workbook parsing and projection
output, applied-operation manifest copies, and transient allocator surplus
remain outside this admission.

The facade rechecks the original read rows through the current credential
before continuing or restaging and before returning or retaining results.
Folder files are still filtered through that credential. Answers based on
stored secret spans cannot be resumed by a caller now seeing only masked spans.
A continuation that reads stored spans records that visibility too. A stored
visibility flag is not a grant or read receipt. Direct Vault callers remain
responsible for the read authority they supply, including `SecretSight::Granted`.

A successful proposal retention atomically deletes the answer-progress row.
The existing held proposal and its Keep, Discard, current-source, withdrawal,
made-by and consume-once checks remain. An existing held proposal or settlement
is detected before deciding again. Direct native settlement also deletes the
same-key answer-progress row in its ledger transaction.

Completed runs with no proposal remain reusable, including their abstentions
and refusals. A stale or unwanted partial or completed row can be released with
`vault.artifacts.release_answers`: use `ProposalSettleRequest`, put the original
run reference in `proposal_ref`, and supply the same consent as Discard. The
response is `released: true` only if an answer-progress row was deleted. This
does not discard a held proposal, fabricate an edit or settlement receipt, or
consume the run reference. The caller may deliberately ask again after release.
A fresh row has a new generation id: an old in-flight unit cannot append its
answer to that later ask. There is no automatic expiry or new count cap.
Artifact deletion purges these rows; checkpoints restore them as content.
They are not part of the archive's consume-once settlement-ledger export.

## Remaining FIX 9815 work

A unit that fails before its validated decision commits can still be called
again. This includes a decider error, decision validation failure, or failure of
the initial decision save itself; earlier committed units remain intact. Once
that save succeeds, conversion or outcome-commit failure leaves the saved
decision available for retry, with no further decider call. A deterministic
conversion error remains an error; the engine does not silently replace the
saved decision. Release the answer-progress row to deliberately ask again.
Concurrent callers are not single-flight and may both call the next unit before
one saves its decision. The first prepared basis wins;
a continuation commits only if the stored row still equals the exact prefix
it read, including original inputs, saved current-unit decision, completed
outcomes, receipts, pins, visibility and generation. A losing writer adopts the canonical row instead of overwriting it.
The first complete row is never extended or overwritten.

The caller's existing absolute deadline is checked at each sheet preparation
row and cell-column, folder selection and before-value item, and canonical
progress-unit boundary. This includes formula, empty-input and other no-call
units. The check returns the existing typed document timeout even without a
registered document-memory host. A later retry uses its new caller deadline
and keeps the stored inputs, current-unit decision and completed prefix.

The encoded CONTENT value buffer uses the same document-memory port and caller
deadline. The engine first counts the exact Named MessagePack output without
allocating that buffer, reserves its bytes, then encodes into a fixed-size
buffer. It accounts for the allocator's reported capacity before filling it.
Both serialization passes check the caller deadline at each output write, even
without a registered document-memory host. Encoding and capacity waits finish
before the grouped writer transaction starts. The original side-row admission
wall still commits the encoded value; the operation stays alive until the staged
bytes are gone. A refusal leaves the previously stored prefix and decision intact.

The expected prefix kept across each unit is an owned snapshot in the same
admitted encoding, not a full typed-row clone held across the paid call.
Advancing decodes it with the same strict Named codec and still compares the
whole typed row, including generation and original inputs, before and inside
the writer. No hash-only or cursor-only comparison replaces that check. The
serialized snapshot owns its operation until its bytes are gone. The decoded
comparison row is local to advancement and is not yet full-heap admitted.

These checks are cooperative, not preemption: source snapshots, parsers,
hashing, clones, serializer work between output writes, individual copies and
database waits can run between checkpoints. Local prefix clones, decoded rows,
input representations, side-row wall copies and allocator transient surplus are
not full-heap admission. No runtime, hard-time or full FIX 9815 completion claim
is made here.

Normal engine rebuild only. The same content side table and additive release
verb cover both partial and complete rows. There is no migration, compatibility
reader, new operational numeric constant, default cap, timer or configuration key.
