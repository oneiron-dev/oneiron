# Lease expiry and recovery evidence

An expired `Leased` attempt returns to the ready queue under the same attempt
id. Cleanup re-reads the row in its write transaction and checks the stored
lease clock again. A lease renewed since the initial scan is left running.

Before cleanup clears an expired lease, it appends an `AttemptLeaseExpiry` to
that row's `lease_expirations`:

- `attempt_count`: the expired lease generation within this attempt;
- `lease_owner`: the worker named by the stored lease;
- `lease_updated_at`: the stored lease clock cleanup checked;
- `observed_at`: the cleanup instant at which the lease was expired;
- `lease_timeout_secs`: the timeout passed to that cleanup.

These are runtime observations, not worker-authored failures, output artifact
references or terminal outcomes. They record the elapsed window, not a proof
that a worker process died. Re-running cleanup on the queued row adds nothing.
The next claim increments its generation by the queue's existing rule.

The history belongs to this physical attempt row. Ordinary retries, landing
handoffs and owner prompt continuations mint a fresh row with an empty expiry
history; the original row keeps its observations. A snapshot or restore that
carries the attempt row carries this history with it. No separate side table
or history retention limit is introduced.

An expired `Landing` attempt still takes the existing force-cancel path. This
change does not turn a leased attempt into `Abandoned` or create a distinct
recovery attempt. That transition still needs one atomic transfer of every
continuation family. SAME-ID recovery keeps its existing parks, holds, pins,
checkpoints, pending signals, asks and other attempt-keyed state in place.

The expiry observation does not close a spend scope, create a payment receipt,
restore a physical model-call permit or authorize a new call. The existing
runtime admission remains responsible for each new physical execution.
