# Connector input resume state

The served connector host hands the first round's opaque resume state to the
engine in zeroizing memory. The engine seals it under that call's existing
resume custody in the same transaction that keeps the input row and settles any
code consent wait. The live handle is bound before that transaction can publish
its reply. On success, a crash after the row commits no longer falls between the
initial input-row commit and a second resume-state write.

Resume persistence remains best-effort. Only its seal runs in a nested
transaction. If opening, sealing or committing that savepoint fails, the failure
is logged and the live questions still commit without resume state. Errors in
the input row, off-record argument seal or code-wait settlement still fail the
whole row transaction and abandon the live questions. An exchange that ended
before the post-commit check is marked uncertain as before.

The stored resume format, protocol, call binding and custody-generation mapping
are unchanged. Resume bytes remain sealed at rest and zeroized in memory. The
existing retirement of the call's resume custody also covers a leaf published
by a failed seal. There is no new table, grant, refusal, retry or timeout.

This change covers the initial round in the served host. Later rounds retain
their existing persistence path. A stream without a last event id still has no
state to reattach from. No deployment setting or vault migration is needed;
update the engine and served host together. This describes source behavior, not
runtime or crash-recovery proof.
