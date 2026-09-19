# W7-C13 QuickJS implementation notes

## Decisions

- Reuse the read-only C04 `wasmtime_runtime/{mod,typed,wire}.rs` implementation.
  Its current WIT is byte-identical to C13. C13 retains the canonical
  `oneiron:code-run/guest@1.0.0` world. No adapter or version translation is
  needed for first-party calls.
- The C13 copy adds `Send` to adapter trait objects for the server runtime
  factory, per-handle Engine/epoch isolation, and a 100M fuel default. Guest
  maximum linear memory remains 32 MiB. C04 integration should take these
  changes rather than keep two diverging runtime implementations.
- Build upstream QuickJS 2025-09-13-2 as real C interpreter WASM. The source
  archive is pinned; the build rejects every non-canonical/ambient import.
  The two tier artifacts share the same source and canonical types.
- Source generation derives C bridge functions from the existing generated WIT
  SDK inventory. No stringly generic host-effect import is introduced.
- Guest Date/seed calls use the typed clock. Date timezone is pinned to UTC.
  Math.random uses the same typed RNG import as the SDK. C04's host derivation
  `oneiron:component-random:v1` is preserved exactly.
- The concrete production provider requires a hash-verified, real-JS-probed
  factory. It is attached to SyncServer before serving, not a new global.
  Existing fixture/global host APIs do not make a server advertise execution.
- Host source/task identity stays scoped to the resolved MCP actor. The
  interpreter hash joins the durable config identity through the stable seed.
  A host-owned per-run single-flight guard closes the concurrent retry window.
  Existing EngineNativeExecutor checkpoints and gated writes remain authoritative.
- Runtime-local finish/output/proposal declarations are separate from typed
  host-effect declarations. The executor teaches them without advertising
  extra imports. Bare finish/console/writeOutput syntax passes wire healing.

## C04 foreign adapter

The foreign artifact's imports are exactly C04's four non-write imports and its
`run-step` export has the same typed result. C04's current VM accepts file-write
proposals but deliberately rejects `claim-candidate`. Do not narrow or fork the
canonical WIT to hide that gap. At the C04 boundary, validate and carry the
claim-candidate as proposal data for host review; never commit it. No C04 file
was changed here. The C13 component and test return both proposal variants.

## Canon corrections

The older host-free `execute_code` language is deployment-conditional now:
unbound servers still fail closed; verified configured servers register the
real tool. The engine's parked-wait terminal marker is not a human settlement
API. Same-run re-entry resumes yielded work and returns terminal receipts;
wait settlement remains a separate engine door.

## Build custody and evidence

The pinned source and production integration are applied. Artifact builds and
execution acceptance remain pending; no build tools were installed. The pinned
QuickJS source archive is stored at
`target/w7-validation/quickjs-2025-09-13-2.tar.xz` (SHA-256
`996c6b5018fc955ad4d06426d0e9cb713685a00c825aa5c0418bd53f7df8b0b4`).

The inspected Linux host has clang, but no WASI SDK/sysroot, wit-bindgen, or
wasm-tools binary. The controlled build requires wasi-sdk 27, wit-bindgen
0.46.0 and wasm-tools 1.239.0 on the assigned build host. Missing native
provisioning is separate from runtime/server implementation. No binary hash
or successful compilation is claimed. Root owns artifact build, C/Rust
compile corrections, fixture execution, formatting and map regeneration.


## Review repairs and C04 handoff

Runtime handles now compile their pinned bytes into separate Engines. A completed
or timed-out request cannot advance another run's epoch deadline. A real-JS
concurrent-handle fixture holds one typed host call while another run completes.
Both boundaries trap on memory growth refusal and default to 32 MiB.

Foreign file proposals are checked in C independently of JavaScript prototypes.
The canonical `WasmtimeRequest::run_step` also validates result size, virtual
mount/path, claim ids, JSON, predicate, confidence and time range as inert data.
C04 must use that typed door (or the same `validate_step_result` over the canonical
bindings) before storage/review; its privileged low-level generic `call` remains
an ABI-conformance primitive, not proposal admission. No proposal is committed by
this validator. C04 still needs to carry the claim-candidate variant for review.
No C04 file was edited and the WIT world was not forked.

The C allocator handles limit subtraction without wrapping, non-byte bridge
lists have an element cap, the guest interrupt backstop is one million ticks,
and SDK/bootstrap internals live in one closure. Artifact-based acceptance is
still pending the exact provisioned build tools, not substituted by WAT or Node.

## Provisioned build receipt

The owner provisioned the exact MacBook toolchain on 2026-09-19. Both tiers
are now checked in under `components/code-run-quickjs/artifacts/`, with pinned
manifest and upstream license. The build version parser accepts official
commit-stamped release output but still requires the exact version. The only
additional upstream patch removes the unused dtoa `setjmp.h` include, guarded
against any actual API usage; this avoids experimental WASM exception features.
A second build in another output directory is byte-identical for both binaries.
The manifest pins patched dtoa and QuickJS source separately. CI verifies
component/file/source/WIT hashes. Real native interpreter qualification remains
pending in `target/w7-validation/quickjs-native-qualification.*`.
