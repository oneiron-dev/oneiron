# Host-configured Firecracker guest ABI v1

This is a real jailer launch path. It is not proof that a guest image boots.
The repository does not include Firecracker, jailer, a guest kernel/rootfs,
or a QuickJS component. No dependency is installed by this backend.

## External artifacts and host configuration

The host must provide:

- Linux KVM accessible to a privileged jailer-launching engine process.
- Compatible executable Firecracker and jailer binaries with absolute paths.
- cgroup v2 memory, pids, and cpu controllers and a delegated host parent.
- Private host-owned scratch/chroot directories and a dedicated non-root uid/gid.
- Host-pinned BLAKE3 kernel, rootfs, and component digests.
- A read-only ext4 rootfs containing `/sbin/oneiron-guest` as trusted PID 1.
  The guest agent must create tmpfs writable state, seed a read-only lower tree,
  mount OverlayFS with a tmpfs upper/work pair at `/mnt/workspace`, constrain
  unprivileged component execution (including the supplied guest pids ceiling),
  collect only regular files from that overlay, and report failures as nonzero.
- A component implementing `wasmtime_runtime/guest.wit`. A QuickJS-class
  interpreter is required to execute JavaScript. ABI test fixtures are NOT JS.

`ONEIRON_MICROVM_CONFIG` names JSON matching `FirecrackerHostConfig`.
`configured(config)` provides the same host-only input without environment use.
The binary-only constructor never authorizes boot. There is no automatic dev
fallback in debug, test, or release builds. No network device is configured.

The host enforces VM memory via machine configuration and a host overhead-bound
cgroup. Jailer pids.max limits host VMM threads; guest pids are separately the
trusted guest agent's responsibility. CPU is limited by vCPU count and cpu.max.
A wall-clock watchdog kills the owned process group and reaps the jailer/VMM.

## Socket framing

The guest connects AF_VSOCK to host CID 2, port 52. Firecracker forwards this to
`/vsock.sock_52` inside the jail. Each frame is a 4-byte big-endian JSON length,
then that many UTF-8 bytes (maximum 8 MiB). Unknown fields are refused.

1. Guest: `{"type":"hello","version":1}`.
2. Host: `start` with version, vm_id, tier, pids, component_bytes.
3. Host: ordered `component` frames (offset, byte array), then `file` frames
   (virtual workspace path, byte array), then `{"type":"ready"}`.
4. Guest: any bounded sequence of:
   - `credential_read` (handle, operation, scheme, host). Host checks its own
     allowlist before resolution and calls a host-installed read-only transport.
     Guest receives only `receipt` (accepted boolean), never secrets, host
     errors, headers, reflected bodies, or arbitrary network response bytes.
     Unknown operations must be refused by the host transport. The host
     transport must validate destination/TLS, disallow redirects and bound I/O.
   - `write` (path, bytes). Workspace-only regular whole-file proposals;
     duplicates, traversal, other mounts, excess bytes/count fail closed.
     Deletions, symlinks, and special files are unsupported and must refuse.
   - `finish` (status). Nonzero discards every proposal. Success seals deltas
     and kills/reaps the VM before exposing them to the adapter.

Per-file limit: 1 MiB; total source/proposals: 16 MiB each; files: 8192;
requests: 16384. Source bytes are copied through the socket. Host source trees
are never attached as writable devices. Proposed changes do not touch them.
Collection is consume-once and only possible after successful completion.

## Evidence status

Socket-pair tests prove protocol framing, credential refusal before resolution,
secret-free receipts and proposal-only output. They do not boot a VM.
The ignored `firecracker_real_boot_returns_only_proposals` test requires the
host profile plus `ONEIRON_MICROVM_TEST_KERNEL`, `_ROOTFS`, `_COMPONENT` paths.
Its conformance guest must produce a file proposal. Run it explicitly on a
provisioned host. A real QuickJS script and real Firecracker boot remain unrun
when these externally built artifacts are absent.

## Provisioned conformance run

The ignored `firecracker_real_boot_returns_only_proposals` fixture requires the
pinned guest to call read-only `metadata` with `conformance-handle` at
`https://api.example.com`, then propose a UTF-8 edit at `/mnt/workspace/result.txt`.
The fixture records credential resolution and transport on the host. The guest
receives only an acceptance receipt, never the credential. A guest that omits
the credential call does not satisfy the boot acceptance test.
