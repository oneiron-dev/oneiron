# Durable image calls and budget traps

A resident agent run's granted `ai.image` call uses the run's existing media
admission, replay key, receipts, worker lease, and settlement. Reference edits use
the same path. This does not create an image-specific budget or ledger.

## When the call parks

The resident dispatcher binds its actual vault, attempt, run reference, actor,
and code-run id to the entry's host door. This entry has no wake-pass deadline.
The owner-row dispatcher preserves this binding when a non-owner falls back to
the agent door. A proven owner still uses the existing owner path.

A per-call observation follows every rung and fallback. It becomes true as soon
as any rung's existing `admit_media` succeeds, before that rung can enter a
backend or gate.

A typed `BudgetDenied::Exhausted` or `BudgetDenied::HostCheck` opens the existing
budget trap only while that observation is false. The existing durable-step
helper commits the trap and its signal park in one transaction. The two denial
kinds retain their existing, distinct park reasons. A host check is not counted
as a spent budget.

This observation means that a rung was admitted, not that it sent bytes or
answered. Once true it stays true across later rungs and fallbacks. A denial
following admission, partial work, or settlement keeps the previous error path;
it is not turned into a trap or a replayable never-ran marker.

## Native stop and replay

After a committed trap the door raises `DurableStepTrapped`. The write receipt
keeps `media_step_trapped` as its never-ran marker. The native bridge records a
typed failure and retains its hard failure even if JavaScript catches the guest
error. Later bridge calls cannot continue that step.

The resident entry checks its private trap flag before ordinary completion or
failure settlement. An already parked attempt is not completed, failed, or
parked a second time. Its live run, seats, and spend scope remain held for the
existing signal-resume path. Resumption uses the same attempt and media replay
key; the never-ran write is eligible to run again. The next entry receives a new
media binding and per-call observation.

## Scope

This path applies only to a granted, non-job image call in a resident native
entry. Unbound callers, owner programs, speech, video jobs, and turn-program text
steps retain their existing behavior. In particular, a host check that occurs
after admission is not covered by this early-denial path.
