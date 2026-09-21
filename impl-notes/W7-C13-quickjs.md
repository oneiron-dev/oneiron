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

The pinned source and production integration are applied. The initial build was pending owner provisioning; the final native
qualification and handoff below supersede that initial status. The pinned
QuickJS source archive is stored at
`target/w7-validation/quickjs-2025-09-13-2.tar.xz` (SHA-256
`996c6b5018fc955ad4d06426d0e9cb713685a00c825aa5c0418bd53f7df8b0b4`).

The inspected Linux host has clang, but no WASI SDK/sysroot, wit-bindgen, or
wasm-tools binary. The controlled build requires wasi-sdk 27, wit-bindgen
0.46.0 and wasm-tools 1.239.0 on the assigned build host. Missing native
provisioning is separate from runtime/server implementation. That initial probe did not qualify a binary. Root owns artifact build, C/Rust
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
and SDK/bootstrap internals live in one closure. Artifact-based acceptance uses the provisioned toolchain below, never WAT or Node.

## Provisioned build receipt

The owner provisioned the exact MacBook toolchain on 2026-09-19. Both tiers
are now checked in under `components/code-run-quickjs/artifacts/`, with pinned
manifest and upstream license. The build version parser accepts official
commit-stamped release output but still requires the exact version. The only
additional upstream patch removes the unused dtoa `setjmp.h` include, guarded
against any actual API usage; this avoids experimental WASM exception features.
A second build in another output directory is byte-identical for both binaries.
The manifest pins patched dtoa and QuickJS source separately. CI verifies
component/file/source/WIT hashes. Real native interpreter qualification passed across the two selective runs
listed below.

## Qualified C04 artifact handoff (2026-09-19)

Use the complete directory, not one loose WASM binary:

- Engine checkout: `components/code-run-quickjs/artifacts/`.
- Absolute shared source: `/home/lexi/w7-build/wt/W7-C13/components/code-run-quickjs/artifacts/`.
- Original MacBook build: `/Volumes/Cinema/w7-build/wt/W7-C13/target/w7-validation/quickjs-native/`.
- Required files: `quickjs-first-party.wasm`, `quickjs-foreign.wasm`,
  `manifest.json`, and upstream `LICENSE`.
- First-party SHA-256: `3ddb36f6ca801c9b19dc59f17960ad139539a6a05a3f74d05de4220dc295f1f6`.
- Foreign SHA-256: `4ae3c57ba74758d5669b6568c2508b76914ce036fde9389788b3704381366a07`.

The canonical typed ABI remains `oneiron:code-run/guest@1.0.0`, from
`crates/oneiron/wit/code-run.wit`. Build instructions are in
`components/code-run-quickjs/README.md`. Each tier passed `wasm-tools validate`;
an independent output-directory rebuild produced identical bytes.

Native execution evidence (not a WAT stand-in):

- `quickjs-native-qualification.log`: real HTTP `execute_code` actor binding,
  persisted run/resume/terminal retry, fresh store, hash/instruction limits,
  concurrent runtime isolation passed.
- `quickjs-note-qualification2.log`: real language (Map, RegExp, BigInt, async),
  typed writes, fixed clock/random replay, ambient escape refusal, foreign
  zero-write import construction and both inert proposal variants passed.
  This mixed run was 26/27 because an independent NOTE cursor regression
  panicked; it did not fail a QuickJS case.

C04 must retain canonical proposal validation and its own host-tier admission.
This handoff does not claim C04's Firecracker integration is tested by C13.


## Final admission qualification

Source `92c67833` removes the historical `execute_code_unavailable` code. A
server without a verified host reports `code_host_unbound` with an explicit
backend/budget binding recovery path. The final native three-case MCP selection
passes this refusal, recovery suggestions and actual QuickJS wire resume without
repeated writes. Production server Clippy passes without test-hook unification.
Both pinned guest binaries and their hashes above are unchanged.
