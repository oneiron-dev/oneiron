# scripts/rack: the rack harness (pass 34 row K1)

Canaries and readbacks for pass 34 sections 13 (from ssh keys to grants) and 15 (fleet tool retirement). They answer
in the contract of the rack audit's approved workflow checks, so the audit's TEST.sh can call them as its
`reviewed-workflow-checks` executable.

```
scripts/rack/workflow_check.py [--config FILE] HOST PHASE CHECK
scripts/rack/workflow_check.py --list
scripts/rack/workflow_check.py [--config FILE] --export-client-keys HOST
```

The entry is executable (the audit's TEST.sh calls it by its absolute path) and its first line,
`#!/usr/bin/env -S python3 -I`, runs it isolated: no PYTHON* variable or user site directory loads code into it.

| Exit | stdout | stderr | Meaning |
|---|---|---|---|
| 0 | `PASS HOST PHASE CHECK` | nothing | the check passed on this box |
| 1 | nothing | `FAIL HOST PHASE CHECK: <reason>` | it did not |
| 3 | nothing | `WAITS HOST PHASE CHECK: needs <rows>` | the rows it proves are not merged yet; never a skip |
| 2 | nothing | `workflow_check: <why>` | usage, configuration or evidence error |

- HOST must be this box: its hostname is one of the host's `box_names`. One box never answers for another.
- PHASE is `before`, `staged` or `after`. Only the key readback reads it: at `after` no rack key may still be authorized.
- Each run writes its evidence first, redacted, as a 0600 file in a 0700 directory on the box's own disk (a
  shared filesystem is refused). The run directory (`<evidence root>/<run id>`) is opened without following a link
  (a link there is refused) and must be on the evidence root's own filesystem; the file is written through it.
  Without evidence there is no PASS. `ONEIRON_RACK_RUN_ID` names the run.
- No printed line carries a key, fingerprint, token or address.
- Nothing here changes a machine. Canaries call Oneiron only through `oneiron api ... call <verb> --data -`. The
  credential stays in the environment variables the issuer's entry names, and no other variable reaches the child
  but a private `TMPDIR`. The call runs in its own process group: past its deadline the group (oneiron and its curl)
  is killed and the TMPDIR, which holds the staged request body, is removed. An issuer URL whose host connects to
  this box is refused unless `issuer.loopback_allowed` says the box serves the issuer. The call is held to the
  addresses that check judged: `oneiron api` starts `curl` from PATH, and the harness puts its own first there (in
  the private TMPDIR), which starts the real curl with `--resolve <host>:<port>:<judged addresses>`. A call that
  answered without going through it fails. A host that is an address literal needs no pin.

## Checks

`--list` prints each check, whether it is built or waiting, and the rows it needs.

Readbacks at the box (read-only; the journal needs a group that reads it, such as wheel on Arch; another user's ssh
process and root's authorized_keys need the Orchestrator's privileged run):

- `old-channels-drained` (gate B, the drain readback). Passes when none of these is left: a process of the tool, an
  sshfs mount, a unit or timer of the tool, an established ssh transport to a rack address, an ssh control socket,
  an ssh forward, or a transfer program. A source it could not read is no proof of absence, so the check fails.
  An ssh forward is a forward flag or option on the command line, a forward directive in the ssh configuration the
  process reads (its `-F` file, else the owner's `~/.ssh/config` and `drain.ssh_system_config`, with Includes; any
  Host block counts unless the command line has `-o ClearAllForwardings=yes`), or a listening socket it holds (a
  forward, or a control master that can take one). Configuration lines are split as OpenSSH splits them (quotes,
  backslash escapes), so a quoted Include path with a space is the file ssh reads; a line or Include ssh would
  refuse, or a directory on an Include's path that cannot be listed, fails the check. The process table (`proc_root`)
  must show every process: a proc mount with `hidepid` fails a run that is not root or in its `gid=` group, and so
  does a process entry that exists but cannot be read. The units are read with `systemctl --user`, which reaches the
  user's manager through `XDG_RUNTIME_DIR` or `DBUS_SESSION_BUS_ADDRESS` (an ssh login sets them); only those two
  variables are passed on, and without them the units are not read and the check fails.
- `other-rsync`: the transfer part of the same readback.
- `identity-scope`, `pivot-audit` (gate C, the key readback). Passes when no rack key logged in since the freeze
  and no live inbound session runs on one. A rack key is another rack machine's client key that is not one of the
  owner's devices; `--export-client-keys` writes each box's list. A live session with no accept record, an
  unreadable authorized_keys file (root's needs root), a missing freeze time or a missing rack list fails. The files
  read are sshd's AuthorizedKeysFile (`keys.authorized_keys_file_patterns`: `%h`, `%u`, `%U`, `%%`, relative to the
  home) for root and every account of `keys.login_accounts`, found with `getent passwd`, and any further absolute
  file of `keys.authorized_keys_files` (a privileged run refuses `~` there: it would be root's home). No login
  account, or one the password database does not know, fails. The sshd journal must reach back to the freeze:
  `keys.journal_since_unix` later than `keys.freeze_unix` fails, and so does an sshd journal (`keys.sshd_units`) with
  no record from before the freeze. Every running sshd listener must run in one of `keys.sshd_units` (by its
  cgroup): a listener in another unit, none found, or a process table not read in full fails. sshd must run as the
  readback reads it: with each listener's own `-f` (absolute) and `-o` options, for root and every login account,
  from every connection of `keys.rack_connections` (each rack machine's `addr=`, with `host=`, `laddr=`, `lport=` or
  `rdomain=` when sshd_config matches on them, since `sshd -T -C` applies only the Match blocks whose fields it is
  given), `sshd -T` must log an accepted key (LogLevel INFO or more), read no AuthorizedKeysFile outside
  `keys.authorized_keys_file_patterns`, take keys from no AuthorizedKeysCommand but one of
  `keys.authorized_keys_commands` run as root (default: Arch's `/usr/bin/userdbctl ssh-authorized-keys %u`; the
  readback runs it for each account as sshd runs it, only when the program and its directories are root's alone,
  from / with PATH and root's USER, LOGNAME and HOME, and counts its keys as authorized), and trust no
  TrustedUserCAKeys. Read after those settings, the files `sshd -T -dd` names, their directories, the Include
  directories and every symbolic link on the way must not have changed since the listener started (a reload keeps
  the start: restart sshd), and the listener must have started before the freeze. The program run is
  `keys.sshd_program`, never a path read from a process; a reason names a listener by its pid. A listener title
  with options (it hides where arguments end), -q, -e, -E, -d, a relative -f, an unread configuration file, an
  authorized_keys path that is not a regular file, or an sshd that does not print its settings (it needs root)
  fails.

Canaries through Oneiron alone, each answering for the box it runs on:

- `mesh-probe` (`canary/machines.py`): `vault.machines.execution.get` lists every machine of
  `canary.target_machines`, and each machine's node answered. (`vault.machines.status` answers the owner only.)
- `kind-3-machine-switch`, `kind-5-drain-guard`: the same read, recording each machine's enabled and paused state,
  or its drain. Their write sides change a machine and are not here.
- `fleet-exec` (`canary/fleet_exec.py`): the probe template's digest as `canary.exec_machine` offers it; a pin (one
  thread, no network, no device); an interactive order on that machine charged to `canary.offer`; then
  `vault.jobs.orders.wait` until terminal, polled (over HTTP it answers at once). It passes on a done order whose last
  attempt started on that machine and exited 0, with its signed receipt. A pin that waits for the owner's check-in
  fails with the check-in's id; `canary.probe.check_in_ref` names it once the owner has answered.
- `forward-policy`: no ssh forward is live (as the drain readback finds one, and every source of that was read),
  and the model gateway answers its model list on its own route. It makes no model call and spends nothing. A URL
  whose host connects to this box (loopback or unspecified in any spelling, such as `127.1`, or one of its own
  addresses) is refused. The request connects only to the addresses that judgement saw (TLS still checks the URL's
  host name), and no redirect is followed: a 3xx fails, since its next hop was never judged.
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
