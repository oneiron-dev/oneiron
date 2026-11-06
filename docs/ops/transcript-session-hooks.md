# Caller-bound transcript session hooks

`vault.calendar.transcript.ingest` keeps the original caller's actor, class,
read checks, uploaded blob version and outer SDK row receipt. A NOTE fallback
still authors an ordinary NOTE and runs no session hooks. The direct host
file-drop helper remains unchanged and is not covered by these hooks.

For an imported SESSION, open-pre runs first, then close-pre. Both run outside
the import writer. Close-pre observes the intent to import and close the sitting,
BEFORE its SESSION commits. A granted read sees the actual absent/current row;
the hook is not given a fabricated sitting. This differs from ordinary close,
whose SESSION already exists. Close Ask/Skip remains advisory and its stop text
is stored on the closed lifecycle record.

Minting the prepared id, writing the ordered turns and source provenance,
closing, planning the SessionEnd wake and linking the meeting outcome still
share one verified actor writer. Open-post then close-post run only after that
writer commits. Their results use the actual returned close, not a later read.

The retained upload keeps the original source version and private session
id/key/start/end. Before any pre-hook, a synchronous import atomically joins or
enqueues its native pending attempt and claims that exact row. Actor/class and
meeting intent stay separate. A concurrent owner of the same upload keeps its
lease; `queued` truthfully names that retained attempt without starting another
hook chain. The worker checkpoints a new prepared identity under its current
lease and generation BEFORE pre-hooks. Payload rewrite and requeue use that same
lease in one transaction. No new lock, worker, timer or lease policy is added.

`hook_pending` is an honest no-mint answer naming the prepared sitting and its
actual open-hook ask. The existing 60-second transcript drain retries its same
invocation as the original caller. Waiting follows native ask settlement and
its actual deadline, not the busy-session 24-hour cap. An unavailable saved
invocation fails rather than starting fresh. The user's hooks-off switch can
let the retained call retry its ordinary boundary; it is not a new grant.

If another sitting wins the import writer's open-pointer recheck, nothing was
imported and both resumed pre-hook answers are rearmed. Only native Storage or
MapFull writer errors also rearm them; a facade INTERNAL code is not treated as
proof of a clean storage abort. Committed WRITE calls are never blindly replayed.
The first pending answer is published only after retention succeeds; no stronger
cross-process exactly-once guarantee is claimed.

Busy-session waiting keeps its existing 24-hour absolute window and 60-second
cadence. No operating timeout, cap, default, dependency or compatibility reader
is introduced. Deploy the engine and existing transcript drain together through
the normal deployment owner.

## Retained caller and retries

Retained imports keep the original reader's verified proof and host-action
guard in engine-owned work. A drain rebuilds those same native guards; it
does not replace a credential-bound caller with the actor's wider native
read. Revocation and holder binding are still checked by each ordinary
read. The retained destination includes all proved peers, even if the
original locality was on-device.

A room or thread keeps its held world, facet, clearance and P7 terms, not
just its id. A drain rebuilds current membership and meets those current
terms with the saved narrowing. Narrowing learned during an import is
saved again before retry. The personal/held choice and effective author
run-attempt stamp are retained; request-only observers are not replayed.
An explicit, newly admitted caller retry that reclaims the upload lease
records that actual caller before continuing. A background retry does not
renew or widen its authority.

Both session pre-hooks and a retained retry's wait-status probe reuse a
calling operation's held task-work turn. Only the turn is shared with the
ask's saved author; the caller's authority is not. An ask never needs a
second permit while that operation holds the only one. The existing
busy-session deadline remains saved during an ask: it is bypassed only
while the native ask is waiting, and applies again if
the sitting is busy after the ask proceeds. No new timeout is introduced.
