# Coach jobs in an embedded wake executor

Coach host work (`coach.host`) and heals (`coach.heal`) normally run through the
server's separate Coach consumers. An embedded host can instead run either queue
through the executor it supplies to a Dreamer wake pass.

## Opt in only for work the executor implements

`DreamerAttemptExecutor` exposes two independent capability methods:

- `runs_coach_host_jobs()` opts in to `coach.host`.
- `runs_coach_heals()` opts in to `coach.heal`.

Both return `false` by default. Implementing `execute` alone does not opt in.
Return `true` only when that executor actually executes the corresponding jobs.
The executor receives the native admitted attempt and the wake pass context.
It returns the normal `DreamerAttemptExecution` outcome and uses the same
step-based, at-least-once execution contract as other wake work.

On each pass iteration, after ordinary maintenance and before recipe wakes,
the driver can admit Coach host work and then heals for an opted-in executor.
These admissions use the existing Coach admission doors, lease, budget, reserve
and started milestone. Dispatch, cancellation, panic containment and settlement
use the existing wake-pass path. No work is marked completed merely because
a host advertises support.

## What is unchanged

A host that does not opt in leaves Coach queues to their existing consumers.
No job is discarded, parked, detached from its parent or assigned a new deadline
because no embedded Coach executor is present. The server's Coach consumers
continue to work as before. Normal queue leases still decide each actual
admission when a worker and a wake pass both serve the queue.

This is an execution port for an invoked wake pass, not a Coach model, a new
scheduler or a timer registration. The host still supplies its executor and
drives its wake passes. It does not make an unconfigured embedded host execute
Coach work or prove that every night run finishes.

## The served wake pass borrows the installed heal consumer

When serve installs its Coach-heal worker, it shares that worker's actual
publisher candidates and served runtime with the same `AiHandle`. A wake pass
on the bound server can then admit `coach.heal` and call the worker's existing
per-attempt dispatcher. This includes code fixes with those publisher
candidates, health-card asks, CASE heals and Issues. It does not opt in to the
separate `coach.host` queue.

The pass holds the server and the installed resources through execution. The
blocking dispatcher runs on the served runtime, not the Dreamer supervisor's
current-thread runtime, and the pass awaits it before returning an outcome.
The wake driver alone settles its admitted lease. It never calls the worker's
round, admission or settlement. Coach model and decision calls retain their
existing payment lines; the queue reservation adds no second model charge.
A per-attempt error is reported as a terminal failure, as in the worker, and a
panic reaches the wake driver's existing panic containment.

Without the actual bound server and installed worker resources, this wrapper
does not advertise heal support; any inner executor's capability is preserved.
No new timer or readiness policy is added. Unconfigured and hostless executors
still need their own real Coach supplier. This served integration is not proof
that all night runs finish or that hostless Coach work executes.
