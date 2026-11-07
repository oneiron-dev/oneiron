# oneiron-guest

Linux PID-1 agent for the Firecracker host protocol. This crate does not include
Firecracker, a kernel, or a JavaScript interpreter. The WAT conformance component
is an ABI test only. No native boot acceptance is claimed by its local tests.

## Production image

Install an architecture-matched Linux executable as `/sbin/oneiron-guest` in the
read-only ext4 rootfs. A dynamically linked build also needs its ELF interpreter
and shared libraries. The rootfs must already contain `/proc`, `/sys`, `/dev`,
`/run`, `/tmp`, and `/mnt`. Use the host's existing boot argument
`root=/dev/vda ro init=/sbin/oneiron-guest`. No arguments are accepted in PID 1.
The binary refuses the production path if it is not root Linux PID 1.

Required kernel facilities:

- `CONFIG_PROC_FS`, `CONFIG_SYSFS`, `CONFIG_TMPFS`, `CONFIG_DEVTMPFS`.
- `CONFIG_OVERLAY_FS`, `CONFIG_CGROUPS`, `CONFIG_CGROUP_PIDS`, cgroup v2.
- `CONFIG_EXT4_FS`, `CONFIG_VIRTIO_BLK` and the platform's virtio transport.
- `CONFIG_VSOCKETS`, `CONFIG_VIRTIO_VSOCKETS`.

PID 1 mounts proc, read-only sysfs, devtmpfs, cgroup2, and bounded tmpfs mounts:
`/run` (128 MiB / 65536 inodes), `/tmp` (16 MiB / 1024 inodes), and `/mnt`
(1 MiB / 32 inodes). Those are ceilings, not preallocated memory. It receives the
snapshot over AF_VSOCK host CID 2, port 52. It creates a read-only bind-mounted
lower directory and an OverlayFS workspace with upper/work on the state tmpfs.
The original rootfs and host source tree are never writable through this path.

The single child joins `/sys/fs/cgroup/oneiron` with the host's `pids.max` before
Wasmtime compilation. It sets resource limits, no-new-privileges, clears
supplementary groups, and drops all real/effective/saved gid/uid to 65534.
PID 1 stays outside this child cgroup so it can reap even when the ceiling is
full. It sends `finish` only after reaping the child. It does not reboot or exit
after sending; the host's owned-VM shutdown/watchdog remains authoritative.

## Wire and component contract

The wire protocol is strict JSON behind a 4-byte big-endian length. `start`
requires `source` in addition to the host's version, vm_id, tier, pids, and
component_bytes fields. Only `foreign` and `untrusted` tiers are accepted.
Both peers use shared `GUEST_PROTOCOL_VERSION = 3`; there is no old-wire reader.
After component chunks, each seed arrives as `file_open` (path, byte length),
nonempty `file_chunk` frames and `file_close`. Empty files use open/close only.
The declared length must match exactly. Chunks write directly to fresh,
descriptor-relative regular files; only paths and lengths remain in `Input`.
The host keeps its exact base in anonymous spools, not whole-file buffers.
A source file uses one request regardless of byte length. File chunks and
source closes are not requests. A partial or malformed seed fails before any
component executes; callers discard its scratch state.

Limits: 8 MiB encoded frames; 64 MiB components in sequential nonempty chunks;
1 MiB source text and individual file chunks. Step-result JSON has no separate
whole-result size check; its encoded frame must still fit. Snapshot and proposed
files have no whole-file wire size bound. Canonical path/tree checks remain in
the shared sandbox contract, including 4096-byte virtual paths. Source and
outbound request budgets are 16384 (outbound reserves result and finish slots).
Host calls have a 16383-call ceiling. Workspace files are read to EOF.
Random-byte outputs use fallible native allocation with no separate per-call
byte ceiling. There is no cumulative read/random-output byte ceiling.
The runtime caps each store to one 64 MiB memory, eight tables, 10000 table
elements, 32 instances, and 100000000 fuel. The host wall-clock watchdog bounds
compilation, credential I/O, and VM execution.

The ABI comes from `../oneiron/wit/code-run.wit` (world `guest`), via Wasmtime 48
bindgen.
The export is `run-step(source: string) -> result<step-result, string>`.
Only these imports link: `read-file`, `credential-call`, `clock-now-unix-ms`,
`random-bytes`. There is no WASI, network, environment, or first-party write
linker. A component with any other function import fails instantiation.

Credential args must be exactly `{ "scheme": "https", "host": "dns.name" }`.
Only handle, operation, scheme and host leave the agent. The host owns the
operation and destination allowlists. The only successful guest response is
`{"accepted":true}`; denial is a fixed error. Unknown receipt fields are refused.
No credential material, host error text, headers, or reflected response body
enters component memory.

The agent validates each proposed path against the seeded shape before sending
it to the host. Typed `proposal-open`, `proposal-chunk` and `proposal-close`
imports stream a proposed file to the host; returned `file-delete` and
`file-rename` deltas name existing seeded files. Each path carries at most one
effect. Only canonical workspace regular files are allowed. Descriptor-relative
paths refuse symlinks, hard links and special files; tree rules refuse traversal,
duplicates and conflicting file/directory paths. Proposals do not mutate the
seeded workspace or the original host tree. Claim-candidate proposals fail the
entire step with `Error::UnsupportedClaimCandidate`.

Each outbound `write_chunk` waits for a successful `receipt` before sending the
next chunk, without spending a logical request or host-call slot. If a host
proposal append reaches the existing typed disk floor, that chunk instead
receives `failure` with the native `SANDBOX_PROPOSAL_DISK_FLOOR` code and the
original detail. The existing proposal-chunk reply returns that reason to the
component and poisons the run, even if the component catches the error. Other
transport failures keep their existing generic errors. The host drops the open
and pending proposals before waiting for one terminal frame under the original
execution deadline/cancellation, then returns the original typed floor error;
it does not dispatch that frame or publish any proposals.

Deploying this wire change requires matching rebuilt guest executables/rootfs
images and artifact pins for both Firecracker and fenced-container agents, plus
release contract metadata for protocol v3. Existing release pins still describe
their older engine revision; no replacement artifact is published here.

## Local conformance tools (not VM or JavaScript evidence)

Generate a binary Component Model fixture, without overwriting an existing file:

```
oneiron-guest --write-conformance /absolute/new-conformance.wasm
```

The component calls metadata using `conformance-handle` at
`https://api.example.com`. After acceptance, it proposes
`/mnt/workspace/result.txt`. Its bytes are the input `source`, or
`typed-component-conformance\n` when the source is empty. It does not execute
that source as JavaScript and does not claim to access a host secret.

To run the actual guest exchange in an unprivileged Unix process:

```
oneiron-guest --localtest-socket /absolute/host.sock /absolute/empty-workspace
```

A host test must bind/listen before invoking the executable. The executable
connects, sends hello, and uses the same
start/component/file_open/file_chunk/file_close/ready and
credential/write_open/write_chunk/write_close/finish exchange as production. The workspace must be private,
empty, absolute, and have no symlink ancestors. This mode is explicitly refused
as PID 1 or uid 0. It uses copied scratch files, not mounts, privilege drop or KVM.

The public library seam is
`serve_localtest<T: Read + Write + 'static>(channel: T, workspace: &Path) -> Result<()>`.
It accepts an owned `UnixStream` or an injected in-memory duplex channel.
`conformance_component() -> Result<Vec<u8>>` encodes the fixture.
`run_production() -> Result<()>` is Linux-only. Both functions are exported at
the library root; their implementation modules and fixture text are not public.
All errors attempt a nonzero finish; callers must discard scratch state on error.

The protocol and CLI tests run unprivileged on Linux or macOS. On macOS they
verify that production startup refuses; they do not compile or exercise Linux
PID-1 mount and privilege setup. Native image/boot acceptance requires Linux
and the provisioned Firecracker/KVM stack.

## Native OCI sessions

The `oneiron.native_session=1` boot path uses its own native Start exchange on
vsock port 52; it does not change the component protocol above. Host and guest
must be updated together. Start carries command, pids, tmpfs budget, reconnect
window, bridge token, explicit non-root uid/gid, and a directory archive's byte
length and BLAKE3 digest. The archive follows Start, outside its 64 KiB JSON
frame. After it is verified and mounted, the guest starts the fenced command and
sends the original one-byte readiness response. Only then does port 52 become
command stdio. Control remains on port 53, egress on port 54, and there is no NIC.

Native read-only mounts are caller-selected directories, not host device mounts.
The host copies regular files, directories and symlink metadata through anchored
file descriptors; it never follows descendant symlinks to gather host files.
The guest extracts to private scratch under its caller-budgeted `/tmp`, verifies
the full digest, and binds each requested directory read-only/nosuid/nodev. An
OverlayFS root view provides missing target directories while preserving the
pinned image and system mounts. PID 1 pivots into that view, detaches the old root,
and remounts the new root read-only before execution. Mount targets and absolute
symlinks therefore resolve inside the guest, not on the host. Native rootfs images
need the same OverlayFS-capable kernel and system mount directories as the
component path, plus `/usr/local/bin/oneiron-fence` and the selected command.
No archive tool is invoked inside or outside the guest.

The native privilege drop uses Start's exact uid/gid with the original cgroup,
rlimit, no-new-privileges and supplementary-group setup. Component execution
continues to use its existing fixed identity. These are source contracts, not a
native boot, compiler or runtime acceptance result.
