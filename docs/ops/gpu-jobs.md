# Customer GPU jobs on the host (`[gpu_jobs]`)

Row L10-31; canon CROSS-ARCH-0023 (`#gpu-lifecycle`, `#c2`, `#c3`, `#c6`, `#money-collect`).

A customer GPU job runs on our account, on an offer this host posts. The engine
(`crates/oneiron/src/gpu_job/`) decides every step of a job. The server
(`crates/oneiron-server/src/gpu_host.rs`) holds what a step needs and cannot
store: the backend that provisions each offer, and the run permits of the
chunks it runs.

## The section

```toml
[gpu_jobs]
default_maximum_secs = 3600   # a job's maximum when its request names none
step_secs = 30                # how often the worker steps each live job

[gpu_jobs.offers.h100-us-east]
class = "h100"
provider = "example-cloud"
region = "us-east"
backend = "skypilot"          # the registered backend that provisions it
price_per_second = 2          # our posted price for one second of the class
cost_unit = "credit-micros"   # the allocation's money unit
catalog_revision = "gpu-prices-2026-11"
startup_secs = 60
teardown_secs = 30
rounding_secs = 60
# list_cost_per_second = 1    # the provider's list price, shown beside ours
# price_shape = "at_oneiron_list"
```

The section is file-only. `serve` refuses an unknown key, a zero
`default_maximum_secs`, `step_secs` or `price_per_second`, an empty
`catalog_revision`, and any `price_shape` other than `at_oneiron_list` (C3 A:
one posted price per GPU class, whichever provider serves it). With no offer,
every quote refuses and no worker starts.

## What the server does

- **Quote** (`vault.gpu.jobs.quote`): the rate times the maximum, plus
  startup, teardown and rounding. It writes nothing and is good for 10
  minutes.
- **Start** (`vault.gpu.jobs.start`): the owner presses start on the quote
  they saw, which is the showing of the maximum (C2 01). The job's own run
  reserves the whole quote on the server's host account, so a vault with no
  paid allocation is refused before anything starts (FRAUD-1). Then the
  backend creates the resource under the chunk's idempotency key.
- **Worker**: every `step_secs`, one step of each live job on the blocking
  pool. A step reads the resource's status, tells the job to checkpoint at
  50, 80 and 95 percent, writes the customer's warning at 95 percent, and
  stops the job at its maximum only after a checkpoint taken after that
  warning. The stop writes an add-funds notice. A chunk settles its billed
  time at confirmed termination, never above its quote.
- **Resume**: `vault.gpu.jobs.start` with `resume: true` on a quote for the
  stopped job starts the next chunk from its checkpoint, once per stop. The
  stop prices one more chunk of the job's first maximum; the add-funds notice
  offers it as its one tap (an inbox action calling `vault.gpu.jobs.start`
  with that quote), and `status` shows it as `stop.resume_quote`. That quote
  stays good while the stop stands; the start still checks it against the
  offer as it stands then, so a changed offer asks for a new quote.
- **Cancel** (`vault.gpu.jobs.cancel`): the owner ends the job. If the
  provider does not answer, the cancel stands and the worker terminates the
  chunk on its next steps.
- **Allow** (`vault.gpu.jobs.allow`): the owner sets, beside one agent
  Grant, the longest run time one job that agent starts may declare over all
  its chunks (`maximum_secs`; 0 removes it). The Grant must be the one that
  admits its agent to `vault.gpu.jobs.start` now.
- **Status and list** (`vault.gpu.jobs.status`, `.list`): run time and spend
  against the maximum, the signals sent, the warning, the checkpoint and the
  stop.

Quote, status and list admit the owner, or an agent whose own Grant names the
verb. Start and cancel admit the owner, or an agent whose own Grant names the
verb (RULING L10-31-STARTER = B), judged again in the act's own write:

- a start passes only when the owner set a maximum beside the Grant that
  admits the agent to start (one Grant answers alone, the first in id order),
  and the job's total maximum fits it. The owner's setting is the showing of
  that maximum (C2 01);
- a resume or cancel passes only on a job the agent started.

Allow is the owner's own act.

## Backends

No backend ships yet (C6 02 is GPU-LAUNCH-BACKENDS). The registry is empty
until a backend registers, and a start on an offer whose backend is not
registered refuses with `gpu_jobs.no_backend` before any reservation. A
backend implements `oneiron::gpu_job::GpuJobConnector`: `create`, `find`,
`status`, `signal` and `terminate`, all blocking.

## Pinned workloads (the vault's own machines)

A job on one of the vault's own machines runs a pinned workload: one exact
thing, named by its digest (sha256 of the pin's canonical encoding). The pin
names the template the machine holds and its digest, the code revision, the
contract and its sha256, the entry, the arguments and the resource request.
It never names a program or a host path. The issuer keeps each pin in the
side table `JOB_WORKLOAD` (pass 33, row R2).

- `vault.jobs.workloads.pin`: the owner, or an agent whose Grant names the
  verb, pins a workload. A pin approves nothing, and it is written once.
- `vault.jobs.workloads.approve`: the owner's own act, with presence asked
  at `Important`. It names the machines the workload may run on (each must
  hold a live `oneiron/job/1` grant), the Grants that may start it (none
  named: only the Grant it was pinned under), and an expiry.
- `vault.jobs.workloads.revoke`: the owner's own act. No later start passes
  the gate, and a revoked workload is never approved again.
- `vault.jobs.workloads.get` and `.list`: the owner reads every workload; an
  agent reads the workloads its Grant pinned or may start.

Before a start on a pinned workload reserves anything, the start gate checks
the workload with `Vault::check_workload_start`. The pin must exist and must
not be revoked; its approval must stand and must not have expired; it must
name the starter and the quoted machine; and the quote's maximum must be no
more than the pin's. The machine's own answer must then hold the pin's
template under the pinned digest and must not refuse. A refusal names
`workload_unknown`, `workload_not_approved`, `workload_revoked`,
`workload_expired`, `starter_not_named`, `request_above_pin`,
`machine_not_approved`, `machine_unreachable` or `machine_refuses`.

## Restart

A permit cannot be stored. When the server stops, each live chunk's permit is
handed off without a charge. After the restart, the step of a live job admits
its chunk again at its quote's frozen price, and that new permit pays the
chunk's end. If it no longer fits, the chunk runs on unpaid and the job record
says `admission_lost`, since a running chunk is never cut for money.
