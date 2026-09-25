# Host-configured Firecracker guest ABI v1

This is a real jailer launch path. It is not proof that a guest image boots.
The repository includes the `oneiron-guest` PID-1 source, an artifact build recipe
at `scripts/microvm/`, and a typed conformance component generator. It does not
include Firecracker/jailer binaries, prebuilt kernel/rootfs images, or a QuickJS
interpreter. No dependency is installed by this backend or recipe.

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
- A component implementing `crates/oneiron/wit/code-run.wit` and its typed
  `run-step(source) -> result<step-result,string>` export. A QuickJS-class
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
2. Host: `start` with version, vm_id, tier, pids, component_bytes, and source (at most 1 MiB).
   `GuestImage::with_source` supplies source; an empty string selects an embedded
   conformance entry program.
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
Its conformance guest must resolve the prescribed credential on the host and
produce a file proposal. `oneiron-guest --write-conformance NEW.wasm` builds
that typed ABI fixture. It is not JavaScript. Run it explicitly on a
provisioned host. A real QuickJS script and real Firecracker boot remain unrun
when these externally built artifacts are absent.

## Provisioned conformance run

The ignored `firecracker_real_boot_returns_only_proposals` fixture requires the
pinned guest to call read-only `metadata` with `conformance-handle` at
`https://api.example.com`, then propose a UTF-8 edit at `/mnt/workspace/result.txt`.
The fixture records credential resolution and transport on the host. The guest
receives only an acceptance receipt, never the credential. A guest that omits
the credential call does not satisfy the boot acceptance test.


## First-party ABI convergence

The shared WIT and generated SDK are byte-identical to C13 boundary commit
`681957d045b59b4a3d5ae1c09875025f48fcba98`. The former string `run` ABI is removed.
The in-process engine adapter keeps its pin, resource ceilings, replay clock/RNG,
and per-operation gate bridge. It links only the tier's selected typed imports.
First-party returned proposals are refused; writes must use their typed host traps.

`step-result.result-json` in the first-party adapter is the strict JSON object
`{"done":true,"observation":"text","outputs":[]}`. `done` and `observation` are required; outputs default empty. Output entries contain `path` under `/mnt/outputs` and
byte-array `bytes`. This envelope is an engine result, not arbitrary JavaScript
return-value coercion. A QuickJS guest must produce this envelope. In contrast,
the foreign agent only checks that result-json is valid bounded JSON; its mutations
are explicitly carried by file-write proposals, not that result text.
`claim-input.subject` is a JSON-encoded entity hex string; `value` and credential
`args` are JSON documents, and search results are individually JSON-encoded.
Unknown/invalid authority fields do not exist in the typed claim record. Denied
calls return typed errors. The canonical WIT has no budget-envelope field in its
result records: the engine still enforces and records budget decisions, but this
ABI cannot expose the existing JSON budget extension to a guest. That is an
explicit shared-boundary limitation, not a locally invented alternate WIT.

The agent currently refuses claim-candidate proposals and deletions. Neither is
silently discarded or applied. All file proposals are validated before scratch
application. Host intake lowers changed whole files into exact-base file edits.
