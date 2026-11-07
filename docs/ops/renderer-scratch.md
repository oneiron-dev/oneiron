# Optional capped renderer scratch (FIX8239, partial boundary)

The existing slide renderer stores scratch in the vault spool. Its disk claims
are estimates. It checks the reserve after each LibreOffice or pdftoppm child.
That remains the behavior when `ONEIRON_RENDER_SCRATCH` is absent.

An operator can instead set `ONEIRON_RENDER_SCRATCH` to a **dedicated Linux
noswap tmpfs filesystem**. The operator chooses its total capacity. The engine
adds no capacity default. This option does not install or mount anything.

## Provision the mount

`deploy/render-scratch/systemd_dropin.py` emits a systemd service drop-in. It
requires `--bytes`, `--uid` and `--gid`. Choose the capacity for the workload and
choose the uid/gid of the engine service. Save its stdout as an opt-in drop-in
for that service, then apply it through the deployment's normal service flow.
The generator itself performs no installation, mount, restart or deployment.

The drop-in's `TemporaryFileSystem=` directive is the producer: systemd creates
one private tmpfs at `/run/oneiron-render`, with the requested size and owner,
`noswap`, `nosuid`, `nodev` and `noexec`. The corresponding environment variable
selects it in the engine. Use a system-manager service or a user-manager setup
that can actually create that mount namespace. The kernel must support tmpfs
`noswap` and Landlock ABI 3. Unsupported opt-in systemd mount settings can fail
that service's start; an already running engine with an unusable configured
mount cannot render there. There is no silent fallback to the vault spool.
No shipped unit, image or release pin is changed by this option.

The engine opens the selected directory without following a final symlink. It
checks the held descriptor's tmpfs type and positive finite capacity, and joins
its `mnt_id` to the actual `noswap` superblock options in `/proc/self/mountinfo`.
It requires a filesystem distinct from the vault's. A directory or environment
string by itself is not evidence of a cap. Keep this operator-managed mount
configuration stable while the service runs.

## What the source path does

The engine pins the root and each private scratch directory with open directory
handles. Engine I/O uses `/proc/<engine-pid>/fd/<fd>` rather than re-opening a
replaceable mount path. The handles live through child teardown and scratch
cleanup. Each child inherits only its scratch-directory descriptor in addition
to stdio. Every child argument, profile, cwd and temporary-file environment uses
`/proc/self/fd/<fd>`: Landlock does not permit dereferencing its unconfined
parent's descriptor links. Engine deck/PDF/PNG I/O keeps the parent-pinned path.
The version probe is included.

Opted-in children start through the existing descriptor-isolating spawn helper.
They receive no vault, call or credential descriptors. An already-built native Landlock
ruleset is applied before exec and inherited by descendants. It permits the
existing filesystem reads, but permits file-content writes only in the actual
scratch directory and to `/dev/null`. Cwd, temporary directories and the XDG
cache point into scratch. HOME and the existing system/font/config reads remain
unchanged. The existing process groups, deadlines, cancellation, retries,
output checks, memory leases and cleanup paths remain in use.

Disk claims use the actual scratch filesystem, not the vault filesystem. All
engine renderers selecting the same filesystem share one pending-claim counter,
including renderers in different SyncServers. Each server keeps its configured
`limits.disk_reserve_bytes`; it does not inherit another server's reserve.
The existing deck/export/page estimates remain estimates. Actual stored bytes
are observed by the filesystem after a claim drops. The kernel's total tmpfs
capacity, not those estimates, bounds scratch file contents. A mount smaller
than the configured reserve plus a render's estimated demand cannot admit that
render. Do not mistake the default two-GiB reserve for a new tmpfs size default.
Other processes' use is visible through filesystem free space, but their future
writes are not engine reservations.

When the selected floor cannot admit a write, the existing `render_disk_floor`
code names the scratch filesystem rather than incorrectly blaming the vault.
An invalid explicit mount configuration reports an existing configuration error
(or no renderer on the existing best-effort path). Generic child failures keep
their original failure result; the engine does not infer ENOSPC from an opaque
LibreOffice failure. The option adds no new published refusal code.

## What this does not prove

This is a **scratch file-content boundary**, not the whole strict FIX8239
no-crossing boundary. Landlock ABI 3 does not mediate every metadata operation:
a same-uid child may still cause outside-scratch xattr, ownership or timestamp
writes. It does not close AF_UNIX deputy channels, cap memfd allocations, prove
whole-process memory accounting, or prevent a process from escaping the existing
process-group cleanup with a new session. Escaped descendants can retain tmpfs
storage; the cap still applies to that filesystem. `noswap` on this mount is
not a claim about global OS swap or other memory users.

No mandatory namespace, syscall filter, new uid, helper, numeric cap or default
is introduced to hide those limits. FIX8239 remains PART. No runtime rendering,
mount, kernel, resource or deployment proof is claimed by this source change.
