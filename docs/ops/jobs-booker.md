# The job booker (`oneiron jobs run`)

Row ONEIRON-BOOKER-CLI (FLEET-TOOL-PARITY, 28 Nov 2026: every booking the fleet tool makes moves
into Oneiron). `oneiron jobs run` books one job the way `fleet run` books one, but on the vault's
own machines:

1. It reads the machines the issuer holds a job grant for (`vault.machines.execution.get`).
   `--host` picks machines by the name the vault shows or by id, and the template's digest comes
   from each node's own answer.
2. It hashes the contract file as `--commit` holds it in `--repo` (sha256, as the node checks it).
3. It pins the workload for the booker's PROJECT (`vault.jobs.workloads.pin`).
4. It orders the workload (`vault.jobs.order`): `--key` is the intent key, and `--host` is the
   order's `limits.machines`.
5. It follows the order (`vault.jobs.orders.wait`) and each attempt's stdout and stderr
   (`vault.jobs.logs.tail`), and exits with the job's code.

`oneiron jobs follow <order>` re-attaches to an order that `run --detach` made. Every call runs as
the one booker agent under its slip. No call is the owner's, and the booker mints no Grant.

## Reach

kel's API listens on its loopback only, at 127.0.0.1:47231 (RUNBOOK 4.1), and its LAN bind is
not open (LOCAL-SERVER-HTTP F1). So a booker on sel reaches kel through a tunnel:

```sh
ssh -N -L 47231:127.0.0.1:47231 kel
oneiron jobs run --url http://127.0.0.1:47231 ...
```

The booker does not open kel's bind, and it opens no listener of its own. `--resolve-address`
(as `oneiron api` takes it) is for the day kel binds the LAN under a name.

## Before each order

- **The commit must be in the node's mirror.** The node never fetches (staging.rs). Push the
  head into the template's mirror first (OPUS-COORD-E2E's `push_head.sh`, row NODE-MIRROR-PUSH).
  If the commit is missing, the attempt ends `launch_refused_changed` or `never_started`.
- **The contract is the check script, hashed as main holds it** (row ONEIRON-CHECK-TEMPLATE).
  The booker reads the sha256 from the commit with `git cat-file`, so the working tree's copy is
  never what gets hashed.

## The booker principal: five owner acts

These are done once, by the owner, in order. Each is one visible act. Acts 2 to 5 are
`oneiron api call` under the owner's credential (`ONEIRON_SECRET` / `ONEIRON_BINDING_KEY`) against
the issuer. The test `crates/oneiron-server/tests/jobs_booker_principal.rs` makes the same four
acts and checks that they suffice.

1. **Slip.** Stop kel's unit, then mint the booker's credential on the stopped vault:
   `oneiron token agent --name oneiron-booker --tier full-access --out <new file> --config <kel's oneiron.toml>`.
   Copy the file to sel, readable by its owner only, and start kel again. The output names the
   agent's principal (32 hex): it is `<agent>` below.
2. **Grant.** `vault.agents.grants.mint` names exactly the verbs below, and `read`, because a
   Grant without `read` confers nothing:

   ```json
   {"agent": "<agent>", "authority_scope": {
     "worlds": {"kind": "all"}, "facets": {"kind": "all"}, "bands": {"kind": "all"},
     "audience": {"kind": "all"}, "sensitivity": {"kind": "all"},
     "verbs": {"kind": "some", "values": ["read", "vault.machines.execution.get",
       "vault.jobs.workloads.pin", "vault.jobs.order", "vault.jobs.orders.wait",
       "vault.jobs.orders.cancel", "vault.jobs.logs.tail", "vault.gpu.jobs.start"]}}}
   ```

   The answer's `grant.grant_ref` is `<grant>`. The booker never calls `vault.gpu.jobs.start`.
   It is on the Grant because `vault.gpu.jobs.allow` refuses a Grant that does not admit its
   agent to start (gpu_job/allowance.rs), and an agent order's attempt starts only within the
   maximum set beside the Grant it ordered under (gpu_job/start.rs).

GRANT VERBS: `read`, `vault.machines.execution.get`, `vault.jobs.workloads.pin`, `vault.jobs.order`, `vault.jobs.orders.wait`, `vault.jobs.orders.cancel`, `vault.jobs.logs.tail`, `vault.gpu.jobs.start`

3. **Per-job maximum.** `vault.gpu.jobs.allow` `{"grant": "<grant>", "maximum_secs": 10800}`.
   That is 3 h, the check template's `max_secs` (FLEET-TOOL-PARITY, kind 5). A booking whose `--timeout` is over it is
   refused at its start (`allowance_exceeded`).
4. **PROJECT.** `vault.projects.mint` `{"name": "fleet-booker", "intent_key": "jobs-booker/project"}`
   (row OWNER-PROJECT-MINT-DOOR). The answer's `project.project` is `<project>`. Set it as
   `ONEIRON_BOOKER_PROJECT` for the booker.
5. **Standing grant.** `vault.consent.create_standing_grant` names the templates, network modes,
   scopes and machines the booker's pins may use:

   ```json
   {"bound": {"actor": "<grant>", "class": "compute.pin", "envelope": {
     "project": "<project>", "audience": [],
     "compute": {"templates": ["oneiron-check"], "network": ["none"], "scopes": ["host"],
                 "machines": ["<nelly's MACHINE id>"]}}}}
   ```

   A pin inside it goes at rung 0, with no screen and nobody asked, while the pin check-in mode
   stays `auto` (the default). A new template or machine needs a new grant. The owner revokes
   it with `vault.consent.revoke`.

Without act 5, a pin waits on its check-in: the booker exits 2 and names the check-in. Without
act 3, the order waits on `allowance_exceeded`. Without act 2, every call is `forbidden`.

## Flags: `fleet run` -> `oneiron jobs run`

| `fleet run` | `oneiron jobs run` | Default and source |
|---|---|---|
| (fleet's own login) | `--credential-file <file>`, else `ONEIRON_SECRET` + `ONEIRON_BINDING_KEY` | none: the booker never calls as nobody. A fresh holder proof is signed for each call (`commands/api.rs`) |
| (fleet's own host list) | `--url` (`ONEIRON_URL`) | `http://127.0.0.1:9090`, as `oneiron api` |
| `--host nelly` | `--host nelly` (a shown name or a 32-hex id; repeat it) | none: every machine the approval names |
| `--need cuda,gpu-4090` | `--gpu COUNT[:MIN-MEMORY-MIB[:FEATURE,...]]` | none: a CPU-only run (pin.rs) |
| `--need rust-1.96` | `--template oneiron-check` | required: the template fixes the toolchain |
| `--mem 28G` | `--mem 28G` (M, G, T) | required. fleet's 12G default never fits |
| `--threads 6` | `--threads 6` | 0: the template's default (pin.rs) |
| `--disk 60G` | `--disk 60G` | required |
| `--timeout 3h` | `--timeout 3h` (d, h, m, s, or seconds) | required: the node stops the run there |
| `--key K` | `--key K` (the order's intent key, 1 to 128 bytes) | none |
| `--detach` | `--detach` (prints `order <id>`) | off |
| `--no-wait` | `--no-wait` (the order's wait `no`) | off: the order waits (`open`) |
| `--sync <dir>` | `--commit <sha> --repo <checkout>`, after the mirror push | `--repo`: the working directory (chosen) |
| `-- cmd args` | `--entry <path in the commit> -- args` (no shell) | required |
| | `--contract <path in the commit>` | required |
| | `--offer <name>` (`ONEIRON_BOOKER_OFFER`) | required |
| | `--project <id>` (`ONEIRON_BOOKER_PROJECT`) | none: no grant covers the pin |
| | `--network none\|host` | `none` (pin.rs). `host` waits for NODE-NETWORK-HOST-UNIT |
| | `--output <name>`, `--returnable-output <name>` | none |
| | `--class interactive\|normal\|background` | `normal` (work_order/record.rs) |
| | `--retry-on exited:<code>\|memory_limit\|disk_limit\|time_limit\|lost\|never_started\|expired` | none |
| | `--max-time <secs>` per call (`ONEIRON_API_MAX_TIME`) | 75 s (chosen: above the 60 s a log read may wait, work_order/logs_tail.rs) |

While following, the booker asks for the order's state every 5 s when no log read is waiting
(chosen). Each stdout read waits up to 10 s for bytes (chosen). After 3 unanswered calls in a row
it leaves the order to run on (chosen). Stdout bytes go to stdout, and stderr bytes go to stderr
with the booker's own lines, which begin `[oneiron]`. The last line is
`[oneiron] order <id> on <host> ended: exit <N> (<end>)`, in the form of fleet's
`[fleet] job <id> on <host> ended: exit <N>`.

TERM or INT asks the issuer to cancel the order once, then follows the order to its end. HUP
changes nothing.

## Exit codes

| End | Exit | Source |
|---|---|---|
| the job exited by itself with code C (0 to 255) | C | the node's `exited(C)` |
| stopped at its maximum | 124 | fleet `--timeout` |
| over its memory | 137 | fleet |
| the node lost it | 77 | fleet `EXIT_BOX_LOST` |
| it never started, or its start window expired | 79 | fleet `EXIT_NOT_ADMITTED` |
| `--no-wait` and no room now, or its wait ran out | 75 | fleet `--no-wait`. A never-fits order refused at once under `--no-wait` also exits 75 |
| cancelled by someone else | 78 | fleet `EXIT_WITHDRAWN` |
| cancelled for this booker's TERM / INT | 143 / 130 | 128 + the signal |
| `--key` already made another order; nothing was ordered | 80 | fleet `EXIT_KEY_HELD` |
| refused before anything was ordered (a flag, a host, a template, the pin's refusal or check-in, a Grant) | 2 | chosen (clap's usage code) |
| the issuer stopped answering while the order lives on | 74 | chosen (sysexits `EX_IOERR`). Re-attach with `oneiron jobs follow <order>` |
| any other end (disk limit, a changed launch, revoked, written off, closed, never fits, upstream; an exit code outside 0 to 255) | 1 | chosen. The end line names the end |

The fleet codes come from the fleet tool (/home/lexi/.local/bin/gpu on sel, read 28 Nov 2026).
