# scripts/rack: the rack harness (pass 34 row K1)

Canaries and readbacks for pass 34 sections 13 (from ssh keys to grants) and 15 (fleet tool retirement). They answer
in the contract of the rack audit's approved workflow checks, so the audit's TEST.sh can call them as its
`reviewed-workflow-checks` executable.

```
python3 -I scripts/rack/workflow_check.py [--config FILE] HOST PHASE CHECK
python3 -I scripts/rack/workflow_check.py --list
python3 -I scripts/rack/workflow_check.py [--config FILE] --export-client-keys HOST
```

| Exit | stdout | stderr | Meaning |
|---|---|---|---|
| 0 | `PASS HOST PHASE CHECK` | nothing | the check passed on this box |
| 1 | nothing | `FAIL HOST PHASE CHECK: <reason>` | it did not |
| 3 | nothing | `WAITS HOST PHASE CHECK: needs <rows>` | the rows it proves are not merged yet; never a skip |
| 2 | nothing | `workflow_check: <why>` | usage, configuration or evidence error |

- HOST must be this box: its hostname is one of the host's `box_names`. One box never answers for another.
- PHASE is `before`, `staged` or `after`. Only the key readback reads it: at `after` no rack key may still be authorized.
- Each run writes its evidence first, redacted, as a 0600 file in a 0700 directory on the box's own disk (a
  shared filesystem is refused). Without evidence there is no PASS. `ONEIRON_RACK_RUN_ID` names the run.
- No printed line carries a key, fingerprint, token or address.
- Nothing here changes a machine. Canaries call Oneiron only through `oneiron api ... call <verb> --data -`. The
  credential stays in the environment variables the issuer's entry names, and no other variable reaches the child.

## Checks

`--list` prints each check, whether it is built or waiting, and the rows it needs.

Readbacks at the box (read-only, no sudo; the journal needs a group that reads it, such as wheel on Arch):

- `old-channels-drained` (gate B, the drain readback). Passes when none of these is left: a process of the tool, an
  sshfs mount, a unit or timer of the tool, an established ssh transport to a rack address, an ssh control socket,
  an ssh forward, or a transfer program. A source it could not read is no proof of absence, so the check fails.
- `other-rsync`: the transfer part of the same readback.
- `identity-scope`, `pivot-audit` (gate C, the key readback). Passes when no rack key logged in since the freeze
  and no live inbound session runs on one. A rack key is another rack machine's client key that is not one of the
  owner's devices; `--export-client-keys` writes each box's list. A live session with no accept record, an
  unreadable authorized_keys file (root's needs root), a missing freeze time or a missing rack list fails.

Canaries through Oneiron alone, each answering for the box it runs on:

- `mesh-probe` (`canary/machines.py`): `vault.machines.execution.get` lists every machine of
  `canary.target_machines`, and each machine's node answered. (`vault.machines.status` answers the owner only.)
- `kind-3-machine-switch`, `kind-5-drain-guard`: the same read, recording each machine's enabled and paused state,
  or its drain. Their write sides change a machine and are not here.
- `fleet-exec` (`canary/fleet_exec.py`): the probe template's digest as `canary.exec_machine` offers it; a pin (one
  thread, no network, no device); an interactive order on that machine charged to `canary.offer`; then
  `vault.jobs.orders.wait` until terminal, polled (over HTTP it answers at once). It passes on a done order whose last
  attempt started on that machine and exited 0, with its signed receipt. A pin that waits for the owner's check-in
  fails with the check-in's id; `canary.probe.check_in_ref` names it once he has answered.
- `forward-policy`: no ssh forward is live, and the model gateway answers its model list on its own route. It makes
  no model call and spends nothing. A loopback URL is refused.
- `inbox-append` waits: at main 14c82900 no verb lets a Grant bound a write to one destination with a list read
  beside it, and the inbox moves only when the lanes run as Oneiron agents (gate C names that trigger).

The Grant a host calls with lists `vault.machines.execution.get` (every machine canary), and for `fleet-exec` also
`vault.jobs.workloads.pin`, `vault.jobs.order`, `vault.jobs.orders.wait` and `vault.gpu.jobs.start`, with the owner's
per-job maximum. The probe template is a row of the exec machine's box file.

Every other check answers WAITS until the row it proves is merged. The row's PR then adds its canary (one canary
rides each row it proves).

## Configuration

One JSON file: `--config`, else `$ONEIRON_RACK_CONFIG`, else `~/.config/oneiron-rack/rack.json`.
`rack.example.json` lists every key; a value in `<...>` is a placeholder the Orchestrator fills, every other value is the default. An unknown key or a wrong type exits 2. Host, unit and
process names, addresses, the freeze time and every time bound are values of this file, not constants of the
harness.

## Tests

`scripts/tests/test_rack_*.py` (pytest) run the entry as a subprocess against a stand-in box: stub programs on
PATH, a fake /proc and fixture files (`scripts/tests/rack_fixture.py`). They need no live host.
