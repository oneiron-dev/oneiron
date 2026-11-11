# Retained sheet answers and byte staging

Sheet-row and folder-item asks have two outputs. `ArtifactAskRun.proposal`
contains a staged edit that passed the normal edit pipeline.
`ArtifactAskRun.sheet_answers` contains paid sheet decisions whose workbook
bytes have not been staged yet. A missing proposal is not evidence that the
second output is empty.

## Native caller order

A native caller that receives `sheet_answers` must retain it with
`Vault::retain_sheet_answer_work_with_reads` before staging. Supply the
original artifact, run reference, actual read rows and producer envelope.
Then call `Vault::stage_pending_sheet_answers` with the same reference and
`Some(work.deadline)`. `SheetAnswerWork.deadline` is the original whole-ask
absolute deadline. It is not a new interval and staging never renews it.

The built-in fresh ask, standing question and wake re-ask callers do this
retention themselves. Standing questions commit the paid answers with the
original answered stamp and history. Wakes commit them with the re-ask log
and completed unit marks. Their byte attempt runs only after that commit.
A later staging failure does not roll back those records or ask completed
units again.

If a later row's intake hits the machine memory floor after paid answers have
completed, `ArtifactAskRun.deferred_floor` carries the original typed refusal.
Retain the completed cohort before returning `machine_memory_refused(refusal)`;
do not attempt staging on that path. `SheetAnswerWork.next_sheet_row` persists
with the pending record and appears in its summary, including after staging.
Standing asks also commit their remaining selection and failed-kind history;
wakes mark only the completed prefix. None of these paths repeats a paid call
or replaces the original deadline. A floor before any paid value and unrelated
errors keep their ordinary error path.

## Pending state and retry

The existing pending record carries either the paid answer bundle or the
validated edit. An unstaged bundle has `kind: "needs_staging"`, `byte_len: 0`
and an empty `content_hash`. There are no proposed workbook bytes to hash.
The fresh facade outcome puts this view in `needs_staging`, not `proposed`.
Other staging errors remain errors, with the paid record still retained.

Staging uses the recorded original workbook version and content hash. It
promotes that same pending record only after the normal validation succeeds
and only if the record is unchanged and unsettled in the committing writer.
Discard, erase or another settlement cannot resurrect it through that
promotion. A changed workbook head is not silently substituted as the base.

A later native caller may retry byte work through
`Vault::stage_pending_sheet_answers` with its own actual deadline, or `None`
when that caller has no work clock. The method never calls a decision model.
There is no new automatic staging queue in this change.

The existing Keep action can stage and settle the retained answers in one
action. It is not an additional approval step. Keep without a clock uses the
ordinary untimed resource port. The existing typed-answer split still checks
which units changed and carries or withdraws them under the normal rules.
Discard consumes the same reference and records its answer bundle without
claiming workbook bytes were produced.

## Resource and proof boundaries

The native cell edit, native formula recalculation, external-link preservation
and edit-pipeline checkpoints share the operation's `Resources`. A typed
resource refusal is not a precision-fallback opportunity. An ordinary
unsupported calculation can still use the working host fallback when the
caller's clock permits it. A session with no clock keeps its untimed behavior.
With no host memory port registered, an explicit deadline still applies at
cooperative checkpoints; memory keeps its original non-reserving measuring
behavior.

The sheet answer bundle and its scoped allocation share one retained lifetime.
This does not claim full heap admission for persistence clones, decoded pending
rows, folder answers, nested decisions or all staging intermediates. Cooperative
checkpoints do not preempt uninterruptible host or package work. Acquisition,
unpolled inner loops, complete retry scheduling and whole-operation memory
coverage remain separate work. No deadline default, grace period or count cap
is added here.
