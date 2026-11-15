# AG-UI event-dump ingest

The opt-in registry source `ag-ui` normalizes newline-delimited AG-UI event
objects. It is a file-framing choice for an event dump, not an SSE client or a
live capture connector. It does not start itself or select a vault from app data.

## Native entry points

`INGEST_SOURCE_REGISTRY.normalize` with source ID `ag-ui` returns the ordinary
`NormalizedIngestBatch`. The registered format is `IngestSourceFormat::AgUi`.
`AgUiSource::decode` exposes each event's parsed JSON, original event line,
input line number, import record ID, and an optional in-batch `repeat_of` ordinal.
`AgUiDecodedEvent::links` projects direct protocol IDs from recognized event types.
These types are exported from `oneiron::ingest`.

The protocol vocabulary and ID carriers follow `ag-ui-protocol/ag-ui` commit
`08eae9dc13546e91272efb2d0ef863e21acc6ee3`, `spec/1.0/schema.json`.
This is an evidence decoder, not a complete schema, event-order, JSON Patch,
argument, or chunk-reassembly validator. Missing or non-string `type` values
stay opaque, as do unknown types, `RAW`, and unregistered `CUSTOM` payloads.
Opaque events project no links. All their fields remain available as evidence;
none is interpreted as an instruction.

## What normalization preserves

- Every nonblank event line becomes a record, in order. The event line retains
  its whitespace and JSON spelling, but not the line terminator. Invalid JSON
  or a non-object line returns the existing line-numbered ingest error.
- The record ID is `agui:<full blake3 digest of input bytes>:<zero-based event
  ordinal>`. This is import bookkeeping, not a protocol identity or a join key.
- `repeat_of` names the first event ordinal with identical line bytes in this
  input. Every occurrence remains present. A repeated value alone does not prove
  duplicate delivery, a gap, a reconnect, or a repair. Cross-input completeness
  and deduplication are not implemented here.
- Only a directly recorded `threadId` on `RUN_STARTED` or `RUN_FINISHED` supplies
  a normalized thread. Other events do not inherit thread or run IDs from stream
  position. Message, tool, parent, and subagent links remain direct ID fields.
- Timestamp values remain in the event JSON. The schema does not normatively
  define their unit, so normalization leaves `occurred_at` unset. App roles stay
  in the payload; no role is assigned as an engine actor or principal.
- `RUN_FINISHED` is not classified as success. No success label, repair triple,
  or training/off-device consent is inferred from completion or candidate text.

The batch is records-only: claims and entities are empty, with no fallback note.
Its registry policy matches existing imported sources: imported trust and
proposed admission. Normalization does not write rows or grant authority.
Consumers must still use ordinary authenticated import/admission, entity
resolution, source-trust, secret, and write gates. Those doors can refuse data;
this source does not bypass them or promise byte-preserving persistence.

## Owner-selected file capture and scoped observations

`vault.ingest.ag_ui.import` is an explicit owner door. It captures an app ID,
a live project, the complete JSONL bytes, and the app's CUSTOM mappings in one
fresh `ingest.ag_ui.file` CLAIM. The authenticated owner is the real capture
actor and principal; no event field selects either. The owner proof and project
are checked in the same actor-content writer as the Imported/Proposed claim.
Normal secret masking still runs. The import rechecks the finalized capture in
that same writer and aborts if admission changed any captured bytes or context;
it never bypasses masking or returns an original fingerprint for changed data.
This is file import, not a live connector or an agent-principal setup API.

Each CUSTOM mapping names the exact event `name`, its reported kind (`action`,
`failure`, `repair`, or `outcome`), and JSON pointers into the whole event for
its ID, thread, run, tool, failure/repair references, and observed outcome.
For example, `/value/runId` is an explicit app mapping, not an AG-UI standard
field. Missing or non-string IDs stay missing. Unregistered CUSTOM events,
RAW, unknown events, whitespace and line terminators remain in the captured
JSONL. The original registry normalizer and generic imported-claim doors are
unchanged. Capture does not approve the observations or permit training or
sending data off-device.

The import receipt returns the claim ID and a full BLAKE3 fingerprint over the
captured bytes and context. `vault.ingest.ag_ui.read` requires both. It reads
through the caller's normal scoped, receipted lane, including its credential,
destination and room ceiling. A missing or withheld claim exposes no source
metadata. A changed capture fails the exact fingerprint check; the reader does
not substitute a current file, another claim or an older fingerprint. The
underlying CLAIM retains its ordinary lifecycle, history and erasure rules.
This is a content pin, not a new immutable blob-version store.

The typed reader also proves, in its same read snapshot, that the authenticated
capture author is a live vault owner. A Human actor alone, or a generic imported
claim shaped like a capture, does not attest an owner-registered mapping. Generic
imports remain available without gaining that typed-source status.

The typed reader returns the original JSONL and the registered app observations.
Each reported outcome's repair link names occurrence ordinals only when the
repair explicitly names a failure and the outcome explicitly names that repair.
Thread and run must be present and equal; tool IDs must also match, including
absence. Repeated matching target IDs stay ambiguous, even for byte-identical
occurrences. Missing references, cross-namespace targets and missing outcome
values are reported separately. A linked result is sourced app evidence, not a
success verdict, a checked Oneiron action or a complete training/eval task.

## Explicit response-task compilation

`Memory::read_eval_repair_task` is a native Rust reader for an explicitly
specified task: a text response, or calls to declared pure tools over a JSON
state. `EvalRepairTaskSource` names the exact capture
claim and full source fingerprint, a linked outcome ordinal, the seat, and a
JSON pointer into the linked **failure** event. That pointer must address an
`EvalRepairTaskSpec`; no task is inferred from the repair text, event order,
app role, or a completed run.

The source contract has no defaults. It explicitly names a `world`, a complete
JSON `initial_state`, `preconditions` (JSON-pointer equality checks on that
snapshot), `intent`, `input`, `tools`, `allowed_actions`, and a `grader`.

- `world: text_response` executes no tools: `tools` must be empty, the only
  allowed action is `respond`, and the grader is `observed_response_equals`, or
  `adjudicated_response` when the app's outcome is no usable answer (see the
  seeds below: the check is then an adjudicated audit label).
- `world: {json_state_tools: {tools: [...]}}` (census L1-20, ruling
  L1-20-TOOLWORLD = B) declares pure tools over the state, each a `name` and one
  `effect` at a JSON pointer the declaration fixes: `set` writes the call's
  argument there (or adds the field to the object that would hold it), `append`
  pushes it onto the array there, and `remove` drops the field or array item
  there (its argument is null). `tools` must name distinct declared tools; a tool
  outside the declared set is refused. The only allowed action is `call_tool`,
  and the grader is `observed_state_equals`.

Any other pairing of world, actions and grader is refused. No world executes an
outside app: a tool world's tools change only the task's own JSON state.

The grader is `observed_response_equals`, with a JSON pointer into the linked
registered outcome value. That value must be a string. `grade_response` compares
exact bytes; it never trims, folds case, runs a judge, or classifies arbitrary app
JSON as a success label. `observed_state_equals` points at the end state the app
observed. `grade_tool_calls` has fixed code apply a candidate's calls, in order,
to the rebuilt `initial_state` through the offered tools (`apply_tool_calls`), and
compares the state they leave with that end state as exact JSON. A call to a tool
the task does not offer, a call that cannot apply, or more than 256 calls grades
false. A candidate's own account of its end state is never graded. `response_input` contains the rebuilt state, checked
preconditions, intent, input and action contract, but not the repair, observed
outcome or grader answer. A trace is a task only if its answer is not leaked
in the workspace or the history (ARCH-0053 `#eval-trace-task`): the reader
refuses a task whose trimmed answer is in any string or object key of its
`initial_state` or `input`, or in its `intent`, or is the whole text of a number
or boolean there.
The check is exact text, not similarity: a paraphrased answer passes it, and a
short answer that recurs by chance refuses the task. A tool world's answer is
its end state: the reader refuses a task whose `initial_state` already is that
state, or holds it, or whose `input` holds it, as exact JSON. The intent is shown to
the candidate with them, so the same checks refuse an intent that holds the answer
or the end state. This is not a certificate of task quality.

The reader preserves the AG-UI read receipt, exact content pin, authenticated
capture binding and live-owner checks. A missing or withheld source returns no
task and no source metadata. Unlinked outcomes, missing task fields, invalid
pointers, unmet initial preconditions, unsupported task contracts and a leaked
answer return an error, without changing the original ingest or source-reader paths. The task
hash binds the canonical source recipe, full task contract and expected
response or end state; it is a content digest, not authority. All variants from one capture
share a family root for the explicitly named seat. No family is assigned here.

This is task compilation only. It creates no eval case, outcome label, source
family, cohort, exposure, training grant or automatic nomination, and runs no
model or replay. The case ledger, released-task hydration, paired measurement,
family assignment, reuse, inventory digest and cut-audit integrations remain
separate work. Receipt and Synthetic case paths are unchanged.

## Sealed eval seeds from a repair

A linked repair becomes a held-out eval case through a seed (census L1-20,
ARCH-0053 `#eval-repair-seed`, ruling L1-20-SEEDER = A: the Coach's
eval-authoring skill decides which repair to seed, and fixed code applies it).
`Memory::propose_eval_repair_seed` takes the task source and two skill arms (each
an `EvalArmPin` with a skill digest): the old skill the person's repair corrected,
and the candidate. In one write it compiles the task as above (every refusal
applies, the leaked-answer refusal included), assigns the capture's family root
(`entity:<claim>`) to a `sealed_confirmation` family, and records the seed
`pending`. The family gets its split before any case derives from it. A root that
already belongs to a development or judge-audit family is refused, and so is a
root whose sealed family a cohort already holds: a case added to it then would sit
outside that cohort's membership, and the cohort's retirement would release it to
development unserved. A withheld capture returns no seed; a replay returns the
seed already proposed. The write rechecks that the capture is still live, so a
proposal that compiled before an erase records nothing.

`Memory::settle_eval_repair_seed` is the gate. The measuring host answers the task
under each arm and hands both answers (a text response, or tool calls) and the
two legs' receipts to it. The door recompiles the task, refuses as `task_moved`
if its hash changed, and grades each answer by the task's own grader: the old
answer must fail and the candidate's must pass, against the app's observed
outcome and never the candidate's own text. Then it records one `repair` case in
the sealed family, reading the capture's root, with a `world_outcome` label whose
value is the outcome's BLAKE3 hex and whose reference is
`ag_ui:<claim>:<source_hash>#outcome/<ordinal>`; the seed is `confirmed`.
Otherwise it is `refused` (`old_passed` or `candidate_failed`; `family_held` when
a cohort took the family since the seed was proposed) and no case exists, so
nothing derives from it. A sealed family never feeds training. The gate reads
through the caller's scoped reader before it looks for a seed, so a caller the
capture is withheld from learns nothing of its seed, not even whether one exists.
Its write settles only the seed row it read: a seed that changed meanwhile (an
erase and a new proposal, or another settle) is not graded with that verdict.

An `adjudicated_response` task compiles with no observed answer, so its seed is
proposed `awaiting_label`, and the gate grades nothing until
`Memory::label_eval_repair_seed` lands its label. Only an `adjudicated_audit`
label is taken (an owner's pick arrives through its ask, and a judge's verdict
is never a check). Its value is the adjudicated answer: at most 512 bytes (a
longer one is refused, never cut), refused if the task's workspace, history or
intent holds it or the label's own reference does, and kept only as the BLAKE3
of its bytes, with the label's reference, weight and date. The label door, like
the gate, reads before it looks for a seed, and writes only the seed row it
read. The label is set once (the same answer and reference again change nothing)
and makes the seed `pending`. The gate then compares each response's BLAKE3 with
it, and a confirmed case carries an `adjudicated_audit` label (the answer's BLAKE3
hex, the audit's reference) in place of the `world_outcome` one. No row holds the
adjudicated answer's text.

`Vault::pending_eval_repair_seeds` lists the seeds the gate can grade now. An
erased capture takes its seeds with it; a confirmed seed's case stays, without
the capture in its source rows. A seed's case is dated by its proposal.

The Coach's eval-authoring skill decides which repair to seed, on metadata
only: the inventory names each linked repair's task (capture, outcome, task
pointer, app, time) with every stored seed's seat and standing, and each open
skill revision with its predecessor's content hash. Fixed code applies the
decision through the capture owner's own scoped read, which the Coach gains
no part of. Both arms pin the decision seat's manifest-bound model at its
registry serving revision, with the pair's old and candidate skill digests.
A seed refused as `candidate_failed` is re-proposed with another pair: the
row is replaced with a fresh seed on the same family. The same pair again
leaves it unchanged.

## Remaining feature work

The capture path is a partial delivery of OF-582 / FIX3720; explicit response-task
compilation is a partial delivery of OF-578 / FIX3638. Live connector setup and
transport, choosing a non-owner principal, links across separately captured
files, and completeness tracking across reconnects remain open. Worlds beyond the
explicit text-response and JSON-state-tools tasks, reuse, digest, released-task
hydration of a seed's case, the measuring host's run of the gate and the cut-audit
consumer are separate. Existing typed Repair case storage is unchanged. The
file path adds no table, family ledger, migration, old-format reader, default
cap or timer.
