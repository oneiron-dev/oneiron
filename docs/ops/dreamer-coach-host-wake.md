# Served Coach host work in wake passes

An invoked served Dreamer wake pass can use the installed `coach.host`
consumer as well as the server's separate worker. The installation records the
actual served runtime on the same `AiHandle`. Both serial and macro pass
constructors lend that runtime and the bound server to the complete native
per-attempt dispatcher. They do not invent a model, a ladder or credentials.

The executor advertises host-job support only with those actual resources,
or preserves an inner executor's own support. It dispatches the native queue
kind, not a selected subset of payload facets. Every branch of the existing
`coach_host::run_one` remains in use, with the same model and decision suppliers.
This integration does not itself opt in to the separate `coach.heal` queue.

## Preserve triage jobs that wait on their children

A feedback revision can split into part and synthesis jobs. Its native
dispatcher parks the revision while those children run. The wake adapter must
not report that revision completed.

After a successful native dispatch, the adapter reads one actual park row
using the worker's existing predicate: the triage facet, the same attempt id,
its native park owner, and a park recorded at or after this run's clock. The
worker's boolean `yielded` check delegates to that same row helper. When the
row is present, the adapter returns its stored reason and cause. The driver's
existing already-parked settlement preserves the row and refunds only its own
queue reservation. It does not create a new park or terminally settle the job.
Native lease fencing still applies if children resume the row before settlement.

Other successful dispatches return normal completion. Native errors return the
same terminal failure reason as the worker. A panic reaches the wake driver's
existing panic containment. The dispatcher runs on the recorded served
runtime's blocking pool and is awaited before an outcome returns. The native
training-run dispatcher still starts its existing lease-free, durable training
work; this adapter does not turn that existing background work into a join.

## What stays unchanged

- The dedicated worker's round, research enqueue, cadence and settlement remain.
- `DigestHostReady` remains the worker's own lapsing signal and drop behavior.
  Recording a runtime is not a readiness or authority claim.
- The wake driver alone settles attempts it admitted. The adapter never calls
  worker admission, round, budget refund or settlement.
- Existing Coach model and decision payment lines remain. Queue reservations
  add no second model charge.
- No timer, new park policy, cap, refusal, default model or readiness gate is added.
- Without an actual bound server and installed runtime, this wrapper preserves
  the inner executor's capability and leaves queued work unchanged.

The native queue lease decides whether a worker or a wake pass receives each
attempt. This is a served consumer integration, not hostless execution, an
automatic Coach deadline, or proof that every night cycle finishes.
