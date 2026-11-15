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
  stopped job starts the next chunk from its checkpoint, once per stop.
- **Cancel** (`vault.gpu.jobs.cancel`): the owner ends the job. If the
  provider does not answer, the cancel stands and the worker terminates the
  chunk on its next steps.
- **Status and list** (`vault.gpu.jobs.status`, `.list`): run time and spend
  against the maximum, the signals sent, the warning, the checkpoint and the
  stop.

Quote, status and list admit the owner, or an agent whose own Grant names the
verb. Start and cancel are the owner's own acts for now; the agent start arm
(STARTER = B, a per-job maximum on the Grant) and the stop notice's one-tap
resume come in a later PR.

## Backends

No backend ships yet (C6 02 is GPU-LAUNCH-BACKENDS). The registry is empty
until a backend registers, and a start on an offer whose backend is not
registered refuses with `gpu_jobs.no_backend` before any reservation. A
backend implements `oneiron::gpu_job::GpuJobConnector`: `create`, `find`,
`status`, `signal` and `terminate`, all blocking.

## Restart

A permit cannot be stored. When the server stops, each live chunk's permit is
handed off without a charge. After the restart, the step of a live job admits
its chunk again at its quote's frozen price, and that new permit pays the
chunk's end. If it no longer fits, the chunk runs on unpaid and the job record
says `admission_lost`, since a running chunk is never cut for money.
