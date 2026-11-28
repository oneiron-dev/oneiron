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
- **History** (`vault.jobs.history`): every ended attempt (one chunk of a
  job), newest end first, with its machine, device, reserved, occupied,
  billed, charged and returned seconds and its end cause, and totals by
  machine, line, family and line period. It reads the job rows and the lane
  economy's unit claims and keeps nothing of its own: a period's charged total
  is what the line's own fold charges that period for the same ended attempts
  (open claims and open holds are not history). An occupancy is shown only
  where a machine measured it or a provider reported a chunk's final run time
  (its exit); a stop, a cancel and a lost machine or resource show it as
  unknown, never as zero. A chunk one of the vault's machines ran shows what
  the issuer holds of its key (`JOB_OBSERVATION`): the machine that answered
  and its device, and from the end the issuer confirmed, the machine's end
  cause, when the issuer received it, the seconds the machine measured (a
  stop's and a cancel's too), a lost key's last seen run time as lost, and
  the meter (`agreed` when the machine's seconds lay inside the issuer's own
  bracket, `bracketed` when the bracket was billed, `unknown` for a lost
  machine). A chunk the provider refused before anything ran
  charged nothing and returned its whole quote. A chunk the owner wrote off
  (door 10) shows `written_off`: its occupancy is unknown, and it settled
  zero. A stopped job that the customer cancels keeps its last chunk's end at
  its maximum. An attempt a
  work order made names its order and its number there, who ordered, how
  long the order waited for it (from the order, or from the end of the
  attempt before), when the machine was first seen running it, and what the
  RANK, PLACE and AFTER rules decided, all as the order's row keeps them; the
  totals sum those waits, and `order` narrows the list to one order. Jobs a
  machine ran for the vault that no row of it names (after the issuer was
  restored from an older backup) show as unattributed seconds, as the
  allocation records them against the generation their submit named: their
  own sum fields (`unattributed_secs`, and `unattributed_running` for those
  still running), by machine and, for a line's generation, by line and
  period, never by family and never inside the other seconds. Only the owner
  sees them, and a family or `order` filter shows none. The reply is never
  kept for a same-id retry, which reads again.

Quote, status and list admit the owner, or an agent whose own Grant names the
verb. History admits the same callers, judged in the snapshot it reads; an
agent sees only the line units it reserved and the first chunk of each job it
started (a resumed chunk's starter is not stored), and totals over those; of
a RANK decision it sees only its own order among the options, as
`vault.jobs.orders.get` shows it.
Start and cancel admit the owner, or an agent whose own Grant names the
verb (RULING L10-31-STARTER = B), judged again in the act's own write:

- a start passes only when the owner set a maximum beside the Grant that
  admits the agent to start (one Grant answers alone, the first in id order),
  and the job's total maximum fits it. The owner's setting is the showing of
  that maximum (C2 01);
- a resume or cancel passes only on a job the agent started.

Allow is the owner's own act.

## Funding a self-hosted server (`[gpu_jobs.host_allocation]`)

Every offer is host-paid: a start reserves the whole quote on the server's
host account, in the offer's `cost_unit`. A managed server's supervisor
delivers that account's allocation. A self-hosted server has no supervisor,
so its account starts empty and every start answers "the host has delivered
no allocation". The owner funds it in their own config
(R6-VAULT-MACHINE-FUNDING = A):

```toml
[gpu_jobs.host_allocation]
id = "own-gpu"           # a plain name
units = 3600             # granted at each start; greater than zero
unit = "credit-micros"   # the cost_unit of one [gpu_jobs.offers] offer
```

- At each start, `serve` (and the desktop app's embedded serve) grants the
  account `units` of `unit` as the walletless allocation `id`. Jobs reserve and
  settle on it, and are receipted, as on any allocation.
- The host account lives in memory until the durable allocation ledger is
  wired, so every start begins with the full `units` again: one process, one
  budget.
- A managed server refuses to start with the section: its supervisor funds
  its account.

## Backends

No backend ships yet (C6 02 is GPU-LAUNCH-BACKENDS). The registry is empty
until a backend registers, and a start on an offer whose backend is not
registered refuses with `gpu_jobs.no_backend` before any reservation. A
backend implements `oneiron::gpu_job::GpuJobConnector`: `create`, `find`,
`status`, `signal` and `terminate`, all blocking.

## The `vault_machine` backend

The `vault_machine` backend runs a pinned workload on one of the vault's own
machines over the mesh job protocol (pass 33, section 8).

```toml
[gpu_jobs.vault_machine]
enabled = true                # default false: the backend is not built
issuer = "<MACHINE id, hex>"  # the one install that issues these jobs
# paused = false              # true: no new dispatch; nothing running is cancelled
# submit_window_secs = 300    # a signed reserve and submit expire after this
# recheck_horizon_secs = 900  # nothing the live recheck reads may end sooner
# call_timeout_secs = 10      # one job protocol call, the dial included

[gpu_jobs.offers.own-a6000]
backend = "vault_machine"
at_maximum = "stop"           # required for this backend
# class, provider, region, price and seconds as for any offer
```

- It registers only on the install whose MACHINE is `issuer`, and never on a
  managed server. A start on any other install refuses with
  `not_the_issuer` before any reservation. The node's own `issuers` list
  stays the hard check.
- A quote names the machine in `inputs.machine` (required) and may name a
  device in `inputs.device_id`.
- `at_maximum = "stop"`: the node ends the run at the job's maximum, with or
  without a checkpoint, and the end reason says the maximum was reached
  (pass 34, 9.2). An offer of any other backend leaves `at_maximum` out and
  follows C2 at the maximum. `serve` refuses a `vault_machine` offer without
  it and any other offer with it.
- A job is billed the occupied time of the attempt's leases, as the node
  measured it, and never more than the issuer's own bracket or the quote's
  maximum. A key that never started settles zero, including overhead; the job
  reads `ended` / `never_started` (or `cancelled` for a cancel), and the node
  part names the machine's end.

## Pinned workloads (the vault's own machines)

A job on one of the vault's own machines runs a pinned workload: one exact
thing, named by its digest (BLAKE3 of the pin's canonical encoding). The pin
names the template the machine holds and its digest, the code revision, the
contract and its sha256, the entry, the arguments and the resource request.
It never names a program or a host path. The issuer keeps each pin in the
side table `JOB_WORKLOAD` (pass 33, row R2).

- `vault.jobs.workloads.pin`: the owner, or an agent whose Grant names the
  verb, pins a workload. A pin approves nothing, and it is written once. The
  pin is hashed into its own key, so the vault's secret scan refuses a pin
  that holds a secret (a token in an argument, say) instead of masking it.
  A job's secrets come from its template instead (Job credentials, below).
- `vault.jobs.workloads.approve`: the owner's act, with presence asked at
  `Important`. It names the machines the workload may run on (each must hold
  a live `oneiron/job/1` grant), the Grants that may start it (none named:
  only the Grant it was pinned under), and an expiry.
- `vault.jobs.workloads.revoke`: the owner's act. No later start passes the
  gate, and a revoked workload is never approved again.

Only the owner approves and revokes (card EN-1 A); no agent's Grant admits
either act. Pass 34 moves an agent's own pins onto the built check-in under a
standing grant (R2's follow-up PR); the owner's approval of an exact digest
stays as its `manual` value.

- `vault.jobs.workloads.get` and `.list`: the owner reads every workload; an
  agent reads the workloads its Grant pinned, and those whose approval,
  unexpired and not revoked, names its Grant as a starter. A revoked or
  expired workload shows nothing to its starters. Neither read keeps its reply
  for a retry under the same invocation id: the retry reads again.

Before a start on a pinned workload reserves anything, the start gate checks
the workload with `Vault::check_workload_start`. The pin must exist and must
not be revoked; it must hold the owner's approval, which must not have
expired; it must name the starter and the quoted machine; and the quote's
maximum must be no more than the pin's. The machine's own answer must then hold the pin's
template under the pinned digest and must not refuse. A refusal names
`workload_unknown`, `workload_not_approved`, `workload_revoked`,
`workload_expired`, `starter_not_named`, `request_above_pin`,
`machine_not_approved`, `machine_unreachable` or `machine_refuses`.

## Job credentials

A template in the node's root-owned file may name root-owned files, by name.
Every job of that template gets them as systemd credentials. The engine
account never reads them, and no pin or verb can name one.

```toml
[execution_node]
# Default true: a credentialed job launches only while every template here
# requires the file wall (`require` keeps `file_wall`, as its default does).
# Every job runs as the one job account, and only the Landlock wall keeps one
# job out of another's files and memory. Set false on a node that runs one job
# at a time.
# credentials_need_walled_node = true

[execution_node.templates.worker]
# ...
credentials = { api-key = "/etc/oneiron/credentials/worker/api-key" }
```

- Each file is root's, a regular file with no group or other access (mode
  0400 or 0600), on a path that is root's and writable by no one else, and a
  job's files hold at most 1 MiB together (systemd's credential cap,
  systemd.exec(5); unconfirmed until `scripts/execution-node/field/credential_probe.sh`
  runs on a node).
- The workload reads `$CREDENTIALS_DIRECTORY/job_<name>` (here
  `job_api-key`). The directory is the service manager's, readable by the
  job account alone and gone when the unit stops.
- Naming a file, or moving it, changes the template's digest, so pins of
  the old digest are refused (`template_digest_changed`) and need a new pin. A
  new content (a rotated key) keeps the digest; the next job reads it.
- How it works: the unit template loads `/run/oneiron-credentials/<instance>`
  (`LoadCredential=job:...`). The root job control handler stages that
  directory just before it starts the unit, and the prepare step removes the
  copy first. So run `oneiron execution-node install` again after the update:
  it writes the unit's line and the handler's directory, and prints
  `template <t> credential <name> <path>: ok, <n> bytes` or the file's fault.
- A job of that template is refused before any workload exists with
  `credentials_need_walled_node`, `template_outdated` (install again) or
  `credential_not_loaded: <name>: <why>`. The prepared record lists the
  names it loaded, never the values.
- A workload that prints its secret puts it in its own log and outputs: that
  is the pinned code's act, as for any output.

## Machine status (`vault.machines.status`)

The owner's read of every machine of his: the fields `vault.machines.list`
shows, the machine's latest capacity claim (cores, memory, GPU memory, disk,
power and the agents it can run) with the time the machine measured it and
its age, and, with `refresh: true`, what each machine's execution node
answers to `Node` now. Only the vault's issuer of vault machine jobs asks the
nodes, each within `[gpu_jobs.vault_machine] call_timeout_secs`, all at once.
A node that answers shows `answered` (enabled, paused, drained, each template
with its digest, the launch scopes and what each enforces, disk); one that
refuses this issuer shows `refused` with the refusal; one that gives no answer
shows `unknown`, never idle, and its capacity claim stays its last sample.
Nothing is stored: a node's answer is a sample.

## Machine execution (`vault.machines.execution.get`)

What each machine the vault holds a job grant for offers its GPU jobs now,
asked of the machine by the vault's issuer: the owner reads it, and so does an
agent whose own Grant names the verb. Per machine it shows the two job grants
the vault holds (`oneiron/job/1`, `oneiron/job-status/1`), the node's answer to
`Node` in the form above, its GPUs as its driver read them when asked (asked
only once the node answered), and the keys it holds that have not ended (asked
under the status grant, even when the job route refuses). Each ask shows
`not_asked` with why, `answered`, `refused` or `unknown`, with when it was
asked. Hourly capacity is never shown as availability. Name one `machine` to
read it whether or not it holds a grant.

## Restart

A permit cannot be stored. When the server stops, each live chunk's permit is
handed off without a charge. After the restart, the step of a live job admits
its chunk again at its quote's frozen price, and that new permit pays the
chunk's end. If it no longer fits, the chunk runs on unpaid and the job record
says `admission_lost`, since a running chunk is never cut for money.

On a self-hosted server, each start grants `[gpu_jobs.host_allocation]` again
before any job steps, so a chunk that was running is admitted again on it.
