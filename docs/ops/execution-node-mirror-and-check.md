# Execution node mirrors and the `oneiron-check` template

Two pieces that let a booking host (sel) hand an execution node code it never fetches itself, and one template that
uses them to run a cargo check of the oneiron workspace as an Oneiron job:

- **The push account and its mirrors** ([NODE-MIRROR-PUSH]): `scripts/execution-node/mirror/`. Any template whose code
  changes per job (a lane head, a stage) gets its commit this way.
- **The `oneiron-check` template** ([ONEIRON-CHECK-TEMPLATE]): `scripts/execution-node/check/`. It is a cold
  `cargo check` with no network, from a vendored crates root and a toolchain root on the node.

The node side of both is set up by a person at the box, as root, at enrolment. Nothing here runs on a node by itself.

## Why a push

A node takes a job's code only from the template's host-local mirror, at the pinned commit, and never fetches
(`crates/oneiron-server/src/gpu_execution_node/jobs/staging.rs:1-35`). A commit the mirror lacks ends the key as
`LaunchRefused { commit_missing }`. So the booking host pushes each head into the node's mirror before it orders a job
that pins it.

The staging git reads the mirror's objects only. Its `GIT_DIR` is a view the stager writes in the key's payload
directory, owned by the engine account, and the mirror is its `GIT_OBJECT_DIRECTORY` (`jobs/staging/git_process.rs`).
So git's ownership check never meets the mirror. What counts is that the engine account can read the mirror's objects,
and that the mirror borrows none (`objects/info/alternates` is refused).

## The push account

`install_mirror_account.sh` (root, idempotent, `--dry-run` prints each step):

- the system account `oneiron-mirror`, with a locked password. It is in no group of the engine (`oneiron`) or the jobs
  (`oneiron-job`).
- `/srv/oneiron-mirrors` (root:root 0755) and one bare mirror `<name>.git` per template, **owned by the push
  account**. Its files are 0644 and its dirs 0755, so the engine account reads it and nobody else writes it.
  - Settings: `receive.fsckObjects=true`, `gc.auto=0`, `receive.autogc=false` and `core.sharedRepository=0644`. With no
    gc, no repack ever removes an object while a staging reads it (staging.rs:22-24 trusts the pushing account on
    exactly that).
  - An existing mirror is checked and never overwritten. A mirror the account does not own (mel's root-made ones) is
    left as it is.
- `/srv/oneiron-check/vendor` and `/srv/oneiron-check/vendor-incoming`, owned by the push account, on one file system.
- `/usr/local/libexec/oneiron-mirror-shell` and `oneiron-vendor-receive` (root:root 0755).
- `~oneiron-mirror/.ssh/authorized_keys`, root:root 0644 in a root-owned dir, so the account cannot change its own
  keys. Each key runs only the forced command:
  - `restrict,command="/usr/local/libexec/oneiron-mirror-shell" <sel's push key>`
  - `restrict,command="/usr/local/libexec/oneiron-mirror-shell --vendor-only" <the vendor job's key>`

The row asked for a root-owned mirror. The mirror is the push account's instead, inside a root-owned root, because a
mirror owned by root takes a push only through root. The trust is the same (the Engine's ACCEPT, 28 Nov 15:47, C1 = A).

`oneiron-mirror-shell` allows exactly four commands:

| Command | Allowed for | Does |
|---|---|---|
| `git-receive-pack '/srv/oneiron-mirrors/<name>.git'` | the push key | a push into an existing mirror |
| `git-upload-pack '/srv/oneiron-mirrors/<name>.git'` | the push key | a ref read (the push check) |
| `vendor-list` | both keys | the crate dirs in the vendor root |
| `vendor-receive <name>-<version>` | both keys | one crate dir, as a tar on stdin |

Anything else exits 126 and names why: another path, a name that is not `<name>.git`, a missing mirror, a mirror that
borrows objects, or an interactive login.

`oneiron-vendor-receive` unpacks with tarfile's `data` filter, so nothing lands outside the dir: no absolute path, no
`..`, no link that leaves the dir, no device. It then checks every file against the crate's `.cargo-checksum.json`,
which is the check cargo makes at build time. A present dir is never replaced: the same checksums answer `present`,
and other checksums are refused.

Keys: the push key is `/home/lexi/.ssh/oneiron_mirror_push` on sel. The vendor key is `~/.ssh/oneiron_vendor_push` of
the account fleet jobs run as on the node (lexi). Only their public halves go into the install script's arguments.
Each side's `known_hosts` needs the node's host key (and `localhost`'s, for the vendor key).

## Pushing a head (sel)

```sh
scripts/execution-node/mirror/push_head.sh [--repo <clone>] [--vendor] nelly oneiron-check <full sha>
```

- The commit lands as `refs/pins/<full sha>`, so it stays referenced while orders name it.
- The script checks the ref with `git ls-remote` and prints `## MIRROR-PUSH rc=0 node=nelly mirror=oneiron-check head=<12> secs=<n>`.
- The first push to an empty mirror sends the whole history: the oneiron pack is about 951 MiB (`git count-objects -vH`
  on sel, 28 Nov). Later pushes send only new objects.
- `--vendor` (the check template) then compares the crate dirs that `Cargo.lock` locks at the commit with
  `vendor-list`. Only when some are missing does it book `vendor_job.sh` as a fleet job on the node.
  - That job reads the commit from the node's own mirror. It runs `cargo vendor --locked --versioned-dirs` with the
    node's toolchain and network, and sends each missing dir with `vendor-receive`.
  - cargo never runs on sel (the Engine's ACCEPT, 28 Nov 15:47, C2 = B). FIX [NODE-VENDOR-ONEIRON-JOB] moves that job
    into Oneiron once the node has a host-network unit.
  - The script prints `## VENDOR rc=0 ... missing=0` when the root holds every locked crate.

## The `oneiron-check` template

The table is `scripts/execution-node/check/oneiron-check.template.toml`. Append it to `/etc/oneiron/execution-node.toml`
on the node. `crates/oneiron-server/tests/execution_node_check_template.rs` proves that it validates and admits a check
pin. Its figures and their sources are in the file's header:

- max_secs 10800, memory 28 GiB, disk 60 GiB, 6 threads: the fleet's own check booking;
- `require` is mel's kernel bounds;
- network `none`;
- the one entry `scripts/execution-node/check/oneiron_check.sh`;
- the one returnable output `verdict.json`.

The node must let one job hold that much: `job_memory_gib` at least 28 and `job_threads` at least 6. nelly starts at
8 and 4 (NELLY-BEL-ENROL-STEPS.md, the Engine's note 2), and grows to 32 the day the first check runs there.

Read roots on the node, root:root 0755 (the job reads only system paths, its payload and the template's `read`,
`scope_systemd/prepare.rs` exec_file):

- **Toolchains**: `/opt/oneiron/toolchains/rust-<channel>`, where `<channel>` is the `channel` of `rust-toolchain.toml`
  (`1.100` on 28 Nov).
  - Fill it with a copy of the fleet's own toolchain dir (`cp -a ~lexi/.rustup/toolchains/1.100-x86_64-unknown-linux-gnu
    /opt/oneiron/toolchains/rust-1.100`, then `chown -R root:root`). That is the same rustc the fleet's checks use, with
    rustfmt.
  - Or fill it from the standalone installer from static.rust-lang.org, checked by its sha256.
  - A toolchain bump adds a dir. It changes no template, so no pin digest moves.
- **Vendored crates**: `/srv/oneiron-check/vendor`, the push account's, filled by `push_head.sh --vendor`. Each crate
  dir is `<name>-<version>`, and the root holds every version any pushed head locked. It only grows; FIX
  [NODE-MIRROR-PIN-PRUNE] adds pruning.

The issuer's offer for the node's CPU jobs is NELLY-BEL-ENROL-STEPS.md A9 (`[gpu_jobs.offers.nelly-cpu]`, price 1 a
second in `credit-micros`). The one host allocation funds every offer in its unit (`config/gpu_jobs.rs:256-272`), so
kel's `[gpu_jobs.host_allocation] units` is set at fleet scale: `units = 1000000000` (Engine 28 Nov, open for a
one-owner home fleet). Checks, trains and pre-flights on nelly took about 170,000 job-seconds a day (FLEET-TOOL-PARITY.md
section 1), so it lasts about 16 years.

## A check pin, and what comes back

A check pin (the booker, [ONEIRON-BOOKER-CLI], makes it):

- template `oneiron-check` at the node's digest, and `commit` = the pushed head;
- `entry` and `contract_path` both `scripts/execution-node/check/oneiron_check.sh`;
- **`contract_sha256` = that file's sha256 on main**. A head that edits the check script is then refused at staging
  (`contract_changed`). It is never checked by its own script; it is checked on the fleet until its script reaches
  main;
- `request.devices = []`, network `none`, and output `verdict.json` returnable;
- `args` are `name=value`, each matched whole by the template's params:
  - `packages=<pkg>[,<pkg>...]`;
  - `features=all|default`;
  - `tests=[<pkg>:]<stem>[,...]`, where a bare stem is crates/oneiron's and `lib` is a package's lib unit tests,
    checked under `--cfg oneiron_test_support`;
  - `fmt=0|1`.

`oneiron_check.sh` runs with no network and no `.git`. It works in this order:

1. It picks the toolchain that `rust-toolchain.toml` pins.
2. It writes `$HOME/.cargo/config.toml`, which replaces crates-io and every git source of `Cargo.lock` with the vendored
   directory source.
3. It refuses before cargo runs when a locked crate is missing.
4. It runs `cargo check --locked --offline`, then the test-file checks, then `cargo fmt --check`.

The job's log (`vault.jobs.logs.tail`) carries the same lines a lane's fleet check prints: `## CRATE rc=`,
`## TESTCHECK rc=` and `## FMT rc=`. `verdict.json` carries the three rcs, the minutes, the toolchain, and the first
errors (at most 64 KiB). The job's exit code is the receipt's:

| Exit | Means |
|---|---|
| 0 | every step passed |
| 2 | refused before cargo ran; `verdict.json` `refused` names why: `argument_unknown`, `argument_invalid`, `toolchain_channel_not_pinned`, `toolchain_missing <channel>`, `vendor_root_missing`, `vendor_incomplete <name>-<version>`, `source_unsupported <source>` |
| other | the first failing step's cargo exit code (101 for a compile error) |

Every check is cold today: no target dir outlives a job (`node_settings.rs:599-604`, `write` must be empty). A lane
check took a median of 1,180 s cold on nelly (FLEET-TOOL-PARITY.md section 1). [NODE-TEMPLATE-CACHE-DIR] adds a kept
cache dir behind a setting, and `oneiron_check.sh` already uses it when the unit sets `ONEIRON_JOB_CACHE`.

- Staging unpacks every file with the commit's time (the tar crate keeps each entry's mtime). So the script copies the
  checkout into `<cache>/src` by content (`rsync -rlc --delete`, without `-t`): a changed file gets a fresh time, and an
  unchanged one keeps its old time.
- cargo builds there, with `CARGO_HOME` and both targets in the cache. A kept target never takes a changed file as
  unchanged.

## Tests

- `crates/oneiron-server/tests/execution_node_check_template.rs`: the committed template validates and admits a check
  pin, and refuses another entry, the host network, a device, values its params refuse, and a request above its
  ceilings.
- `scripts/execution-node/mirror/test_mirror_shell.sh`: a push and a ref read through the forced command; every
  refusal; crate receipt, `present`, never-replace, unlisted or changed files, and tars that climb out or link out.
  It runs on a temporary tree with no root and no network.
- `scripts/execution-node/check/test_vendor_config.sh`: the source replacement from a fixture `Cargo.lock`, the vendor
  and toolchain refusals, the argument checks and the rc lines, with a stand-in toolchain.
