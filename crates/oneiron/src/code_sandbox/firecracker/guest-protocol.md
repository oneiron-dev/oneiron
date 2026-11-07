# Host-configured Firecracker guest ABI v3

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

OCI sessions resolve their artifact paths from the host's
`ONEIRON_MICROVM_OCI_IMAGES` registry. Each selected OCI reference must also
have its own `oci_pins` entry in `FirecrackerHostConfig`, keyed by that exact
reference and containing its kernel, rootfs and component BLAKE3 digests.
Those pins come from the host profile, not from the path registry or the guest.
Both OCI boot doors use the selected entry for verification and evidence;
`pins` remains the raw-boot triplet. The current profile format requires
`oci_pins` (an empty object for a raw-boot-only profile). No old-format reader
or image artifact is supplied by this source change.

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

1. Guest: `{"type":"hello","version":3}`. The shared
   `GUEST_PROTOCOL_VERSION` is used by both peers; a different version refuses.
2. Host: `start` with version, vm_id, tier, pids, component_bytes, and source (at most 1 MiB).
   `GuestImage::with_source` supplies source; an empty string selects an embedded
   conformance entry program.
3. Host: ordered `component` frames (offset, byte array), then one or more
   `file_open` (virtual workspace path, `len` in bytes), `file_chunk` (byte array),
   `file_close` sequences, then `{"type":"ready"}`. An empty snapshot sends no
   file sequences. Only one file may be open. Each nonempty chunk is at most
   1 MiB, and close must match the declared length exactly; an empty file opens
   with length zero and closes without chunks. The host retains immutable
   anonymous spools, not whole-file buffers or mutable source descriptors.
   The guest writes chunks directly through checked workspace descriptors and
   retains only source paths and lengths. Production seals the lower tree
   read-only before untrusted execution; the container agent uses its private
   fenced scratch tree. A file consumes one source request, not one per chunk.
4. Guest: any bounded sequence of:
   - `credential_read` (handle, operation, scheme, host). Host checks its own
     allowlist before resolution and calls a host-installed read-only transport.
     Guest receives only `receipt` (accepted boolean), never secrets, host
     errors, headers, reflected bodies, or arbitrary network response bytes.
     Unknown operations must be refused by the host transport. The host
     transport must validate destination/TLS, disallow redirects and bound I/O.
   - `write_open` (path), `write_chunk` (bytes), `write_close`. A proposed
     workspace regular file streams to an anonymous host spool. Chunks spend
     no request budget; each waits for a successful `receipt` before the next
     chunk. Open and close each receive one receipt too.
   - `delete` (path). Deletes a file that exists in the seeded base tree.
   - `rename` (from, to). Moves a seeded base file to a distinct workspace path.
   - `finish` (status). Nonzero discards every proposal. Success seals deltas
     and kills/reaps the VM before exposing them to the adapter.

   For streamed writes, `delete` and `rename`, every path must be in the
   workspace mount and carries at most one effect (a rename occupies both its
   paths). The host applies each accepted effect to its copy of the base tree's
   shape under the shared contract's path/tree checks and checked byte
   arithmetic. Duplicates, traversal, other mounts, symlinks and special files
   refuse the run. Open/close, chunk, delete and rename receive `receipt`
   (accepted true); any refused proposal fails the whole run. A chunk whose
   append raises the existing typed proposal disk-floor error receives instead
   `failure` with `code: "SANDBOX_PROPOSAL_DISK_FLOOR"` and the original error
   `detail`. This is a proposal error, not a credential response. The guest
   returns that reason through its existing proposal-chunk error string and
   poisons the run, so catching the error cannot make the run succeed. Other
   append and transport errors retain their existing behavior.

   On that floor error the host releases the open and all pending proposal
   bodies and claims before sending `failure`. If sending succeeds, it reads
   exactly one subsequent guest frame under the same execution deadline and
   cancellation before returning the original typed error. A normal guest
   sends `finish` only after the component returns; the host never dispatches
   this terminal frame, retries an append or publishes a proposal. A send/read
   failure still returns the original floor error; a raced cancellation keeps
   its existing priority. There is no new timer, quota or success path.

Frames stay bounded to 8 MiB. Snapshot and proposed files stream without a
whole-file wire size cap; source text and step-result JSON retain their 1 MiB
bounds. Guest workspace files are read to EOF; each random-byte output retains a
1 MiB bound, without a cumulative read/random-output byte ceiling. Source and outbound
request budgets remain 16384; file chunks and source file closes do not spend source
requests. Source bytes are copied through the socket. Host source trees are
never attached as writable devices. Proposed changes do not touch them.
Collection is consume-once and only possible after successful completion.
Lowering against the exact spooled base retains immutable UTF-8 views of the
expected and replacement spans, including a new file's complete replacement.
Clones share those spools and their disk-floor claims through review. Public
proposal JSON and durable receipts still contain the exact text as ordinary
strings, not temporary body IDs. Whole-JSON encoding and receipt-ledger storage
still allocate their encoded values; this is not end-to-end streamed storage.
The slice-based lowering API copies an expected span from a borrowed base, which
it cannot retain, but its replacement remains body-backed.

Protocol v3 requires matching rebuilt guest executables/rootfs images (including
the container agent) and updated artifact pins and release contract metadata.
The existing pinned release recipe still describes its older engine revision;
this source change does not publish or deploy replacement artifacts.

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

The shared WIT is `crates/oneiron/wit/code-run.wit`, with generated bindings in
`crates/oneiron/wit/generated/`. Both the foreign agent and the in-process engine
adapter use it. The in-process adapter has its own pin, resource ceilings,
replay clock/RNG, and per-operation gate bridge. It links only the tier's selected typed imports.
First-party returned proposals are refused; writes must use their typed host traps.

`step-result.result-json` in the first-party adapter is the strict JSON object
`{"done":true,"observation":"text","outputs":[]}`. `done` and `observation` are required; outputs default empty. Output entries contain `path` under `/mnt/outputs` and
byte-array `bytes`. This envelope is an engine result, not arbitrary JavaScript
return-value coercion. A QuickJS guest must produce this envelope. In contrast,
the foreign agent only checks that result-json is valid bounded JSON; its mutations
are carried by file write, delete and rename proposals, not that result text.
`claim-input.subject` is a JSON-encoded entity hex string; `value` and credential
`args` are JSON documents, and search results are individually JSON-encoded.
Unknown/invalid authority fields do not exist in the typed claim record. Denied
calls return typed errors. The canonical WIT has no budget-envelope field in its
result records: the engine still enforces and records budget decisions, but this
ABI cannot expose the existing JSON budget extension to a guest. That is an
explicit shared-boundary limitation, not a locally invented alternate WIT.

The agent refuses claim-candidate proposals; the whole step fails, and nothing
is silently discarded or applied. All file proposals are validated before
scratch application. Host intake turns each accepted `write`, `delete` and
`rename` into a typed `SandboxProposalWrite` (`FileWrite`, `FileDelete`,
`FileRename`), which the adapter wraps as a `SandboxProposalDelta` at
`Proposed` approval.

## Streamed step output

After `ready`, the guest may send `output_text { target, start, frame }`,
`output_bytes { path, frame }`, or `store_bytes { start, frame }` alongside its
proposal stream. These frames do not spend logical requests. Each frame is bounded
by the shared `MAX_CHUNK_BYTES`; `output_bytes` names only `/mnt/outputs` files.
Text targets are `console`, `finish`, and `store`. Console and files append; a
`start` frame replaces the previous finish or store value.

The host passes each frame directly to the caller's output sink on the exchange's
thread. A `receipt { accepted: true }` follows only after that sink stores the
complete frame. `failure` reports a storage error and the exchange returns the
original host error under the original cancellation token and deadline. A guest
poisons its step after either failure or a transport error. Output does not alter
`step_result`, the terminal status, workspace proposals, or the shared protocol
version. Release the matching guest executable, rootfs/container agent, and engine
together: an older guest still drops its output imports before sending any frame.
