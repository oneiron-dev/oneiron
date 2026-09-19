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

Limits: 8 MiB frames; 64 MiB components in sequential nonempty chunks; 1 MiB
source and files; 16 MiB aggregate files; 8192 files/directories; 64 path levels;
4096-byte virtual paths; 16384 wire requests (one slot reserved for finish).
Host calls have a 16383-call ceiling and cumulative read/random output is
limited to 16 MiB. The merged workspace is also bounded to 16 MiB / 8192 files.
The runtime caps each store to one 64 MiB memory, eight tables, 10000 table
elements, 32 instances, and 10000000 fuel. The host wall-clock watchdog bounds
compilation, credential I/O, and VM execution.

The ABI comes from `../oneiron/wit/code-run.wit`, via Wasmtime 38 bindgen.
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

The agent validates every proposal before applying it to its scratch overlay.
Only canonical workspace regular files are allowed. Descriptor-relative paths
refuse symlinks, hard links, special files, traversal, duplicates, conflicting
file/directory paths, and excess data. It enumerates the resulting tree and
reports changed whole files only. Deletions are unsupported. Claim-candidate
proposals fail the entire step with `Error::UnsupportedClaimCandidate`.

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
connects, sends hello, and uses the same start/component/file/ready and
credential/write/finish exchange as production. The workspace must be private,
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
and the provisioned Firecracker/KVM stack. The root coordinator owns that
separate evidence.
