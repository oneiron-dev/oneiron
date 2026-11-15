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
in the workspace or the history (ARCH-0053 `#eval-trace-task`), and the reader
checks the whole of what a leg is shown, `response_input`: it refuses a task
whose trimmed answer is in any string or object key there, or anywhere in its
compact JSON text (a number's or a boolean's text, or the JSON of a whole value,
which a leg can copy). The check is exact text, not similarity: a paraphrased
answer passes it, and a short answer that recurs by chance refuses the task, in
the contract's fixed words (its keys, the world's kind, the allowed actions) as
in its author's text. A tool world's answer is its end state: the reader refuses
a task whose end state, as exact JSON, is any whole value in that input (the
rebuilt `initial_state`, a task no call needs to solve; a declared tool; a
precondition; the offered tools' list) or, for a text state, an object key
there. This is not a certificate of task quality.

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
erase and a new proposal, or another settle) is not graded with that verdict,
and a capture deleted meanwhile leaves its seed unsettled (a delete keeps the
seed until the erase scrubs it, but it never takes a case).

An `adjudicated_response` task compiles with no observed answer, so its seed is
proposed `awaiting_label`, and the gate grades nothing until
`Memory::label_eval_repair_seed` lands its label. Only an `adjudicated_audit`
label is taken (an owner's pick arrives through its ask, and a judge's verdict
is never a check). Its value is the adjudicated answer: at most 512 bytes (a
longer one is refused, never cut), refused if a leg's input holds it (as for a
compiled answer) or the text the seed keeps does (the task pointer, and the
label's own reference), or if it is one of the seed's identifiers (the capture's
claim ref and fingerprint, the outcome ordinal, the seat, each arm's model,
revision and skill digest; only a whole one counts, since a hex id holds most
one- and two-character answers by chance), and kept only as the BLAKE3
of its bytes, with the label's reference, weight and date. The label door, like
the gate, reads before it looks for a seed, and writes only the seed row it
read. The label is set once (the same answer and reference again change nothing)
and makes the seed `pending`. The gate then compares each response's BLAKE3 with
it, and a confirmed case carries an `adjudicated_audit` label (the answer's BLAKE3
hex, the audit's reference) in place of the `world_outcome` one. The label door
writes no text of the adjudicated answer: the seed and its case keep its digest.

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
One seed stands per task contract in the vault, whatever it stands at and
whatever its source or seat: a seed refused as `candidate_failed` is never
proposed again with another pair, so no candidate is chosen by a sealed task's
result. The contract's key is the BLAKE3 of its RFC 8785 canonical JSON, so the
same contract at another task pointer or outcome, in a file imported again, or
on another seat takes no second seed, and every row of it shows that seed's
standing, while the seed's capture still reads; that capture is then among the
rows the inventory read. A deleted capture's seed holds its contract until the
erase takes it, but shows on no row, and no other row of its contract is
listed, since none can take a seed. An erase takes a seed with its capture. A
reworded contract is another contract: near-duplicate tasks are a limit of the
data, not of this check. The inventory lists at most 64 repair rows, from the
window's newest 64 captures, at most 8 task contracts per failure event, and at
most 64 skill revisions. A capture's events are matched to its mappings by name
from one index, and its repair links resolve from one id index, so listing a
capture takes time linear in its events and mappings.

The measuring host runs each `Pending` seed through one `coach.eval_repair_seed` job per seed key, queued once, when the seed turns pending (a replayed proposal queues nothing, so no replay pays for a seed's legs again; an `awaiting_label` seed queues nothing until its label lands). A job that cannot run its legs (an arm this host does not serve exactly, a call with no answer) leaves the seed pending with no job. The host reads the seed key from its leased attempt, takes the seed's release, answers the released task under each arm, and settles through the capture owner's unchanged gate, which hands the host back only the seed's state. Each leg's receipt names the seed key, the leg and the content handle of the stored answer the gate graded. A tool call is read by its declared input schema (an object whose only property is `argument`); a call that breaks it leaves the leg no tool calls, so a tool world's answer fails. The release holds the seed key, seat, old and candidate arms, the leg input, the declared tools, the source rows, and whether the task moved; it never holds the expected answer, the grader, or any outcome text, and the task text is read only through the capture owner's own scoped read. A confirmed seed's case releases to a claimed measurement as `repair_response`, with the recompiled task's input (its `tools` field holding the declared tools), the capture fingerprint, and the seed's task hash, and with no label, since each label holds the outcome's digest; fixed code grades each leg's answer against the recompiled task exactly, with no judge call.

## Remaining feature work

The capture path is a partial delivery of OF-582 / FIX3720; explicit response-task
compilation is a partial delivery of OF-578 / FIX3638. Live connector setup and
transport, choosing a non-owner principal, links across separately captured
files, and completeness tracking across reconnects remain open. Worlds beyond the
explicit text-response and JSON-state-tools tasks, reuse, digest and the cut-audit
consumer are separate. Existing typed Repair case storage is unchanged. The
file path adds no table, family ledger, migration, old-format reader, default
cap or timer.
