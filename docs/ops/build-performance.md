# Build performance

## Policy

The workspace uses limited debug information (`debug = 1`) in the `dev` profile.
The `test` profile inherits it. This keeps file/line backtraces and module-level
information, but omits type and local-variable debugger information. It does not
by itself change optimization, assertions, overflow checks, panic behavior,
features, or release profiles. Dependency-only optimization is described below.

For a debugging session that needs locals, opt back into full debug information:

```sh
CARGO_PROFILE_DEV_DEBUG=2 cargo test -p oneiron --lib --all-features
```

Use the same profile setting for repeated commands that should reuse artifacts.
Changing the setting invalidates affected Cargo units once. Do not set `RUSTFLAGS`
for the warning gate: use Clippy's existing `-- -D warnings`. Global flags also
reach vendored path dependencies and split otherwise compatible caches.

The profile settings work on the MacBook, Mac mini, and Arch Linux hosts, but
portability is not a uniform speedup claim. The initial debug-info comparison
below is from the MacBook; the repeated codegen-unit follow-up is from the Mini.

The core package also uses 256 codegen units for dev/test builds. This improves
the measured non-incremental Mini core build while matching the ordinary
incremental default count. It is not a measured incremental edit-loop gain.
Other packages' codegen-unit settings and release/bench defaults are unchanged.
Dependency optimization is a separate setting below. See the follow-up results
and package-specific comparison override below.

## Optimized dependencies in dev and test builds (2026-09-26)

`[profile.dev.package."*"] opt-level = 2` optimizes dependencies, including
non-member path packages (`heed`, `paste`, and the `pkix-chain` patch). Workspace
member library, binary, and test units, including `oneiron`, `oneiron-bench`,
and `oneiron-napi`, keep the dev optimization default (`0`); their build
scripts follow the separate build override (`2`). The existing `oneiron`
codegen-unit setting remains. The test profile inherits dev. Release, bench,
and napi production builds using release retain their own profile defaults;
no profile for them changes.

On a clean 16-core box at main `97bb7049` with rustc 1.96.1, featureless
library nextest (7,474 tests; `--profile featureless --retries 0`) took **733 s**
with dependencies at opt-level 0 and **430 s** at opt-level 2, a **41% runtime
reduction**. The corresponding cold test-binary build rose from **276 s** to
**329 s**. The build cost is paid once for cached dependencies; this is not a
claim that every feature set or host sees the same test speedup.

A single cold-build comparison on remote Ubuntu (8 Cargo jobs, rustc 1.96.1,
separate fresh targets, identical featureless `cargo test -p oneiron --lib
--no-default-features --no-run --locked`) held dependency opt-level at 2 and
changed only `profile.dev.build-override.opt-level`:

| Build-dependency opt-level | Cargo-reported build time | Wrapper wall time |
| --- | ---: | ---: |
| 0 (default) | 8m44s | 544 s |
| 2 (adopted) | 7m36s | 894 s, including ~438 s host-capacity wait |

Build-override 2 matches the normal-dependency setting and reduced the measured
cold **build phase** by 68 s (13%) in this pair. The wrapper wall figures are
not directly comparable because the second run queued before Cargo started.
This does not prove all shared build/normal dependencies compile once: host
and target units or different features may still require separate builds. It
also does not predict edit-loop gains. With both settings, a separate featureless
nextest run on the remote host passed 7,474 tests in **595 s wrapper wall time**
(nextest reported 581.326 s); it reused the optimized cold-build target and is
not a paired 0-versus-2 comparison. Both changes are dev/test-only; release,
bench, and napi release builds use their unchanged profiles.

To opt out when stepping through dependency code in a debugger, use the
package override for that session, not a workspace-wide optimization change:

```sh
cargo test --config 'profile.dev.package."*".opt-level=0' \
  -p oneiron --lib --no-default-features
```

This causes a separate one-time dependency rebuild. To inspect build
scripts/build dependencies without optimization too, add
`--config 'profile.dev.build-override.opt-level=0'`. For debugger locals,
also use `CARGO_PROFILE_DEV_DEBUG=2` as described above. Keep override choices
the same across commands when you want to reuse their artifacts.

## Cache retention

The CI jobs that run cache maintenance keep their existing 20 GiB cap; the
Linux jobs currently do not run it. `scripts/ci/cap-target-cache.sh` first asks Cargo
1.96 to clean workspace-owned outputs in both the dev/test and release profiles,
including old feature variants. It retains
third-party dependencies, including excluded vendor packages, if that is enough
to get under the cap. Only a successful cleanup and remeasurement that is still
over the cap triggers a full reset.

This is **workspace-first retention**, not LRU eviction. First-party code rebuilds
after cleanup. A dependency-heavy cache can still require a cold build after the
fallback reset. No job-time reduction is guaranteed by this policy.

Maintenance requires a canonical absolute `.../ci/target` path. Before each Cargo
clean pass, a Python 3 scan checks every descendant without following symlinks.
Any symlink (including internal, file, or dangling links), file or directory on a
different device from the root, or scan/stat/read failure keeps the remaining
cache without a full-reset fallback. This deliberately skips cleanup for
otherwise valid build outputs that contain symlinks. Under-cap caches remain a
no-op and do not need the scan.

Each successful scan emits best-effort JSON diagnostics on stderr: available
filesystem bytes (`f_bavail * f_frsize`) and apparent regular-file bytes grouped
as `debug/deps`, `debug/build`, `debug/incremental`, `release`, `doc`,
`tests/trybuild`, and `other`. Component totals reuse the existing no-follow stat
results: no second walk or under-cap scan is added. Hard-link names count
separately and sparse-file holes count toward apparent size; these are **not
allocated bytes**. `du` remains the cap's allocation measure. Unavailable metrics
are `null`; metric or diagnostic-write failures never change cleanup decisions.
Safety-scan failures still refuse cleanup and emit no diagnostics.

Both clean passes pin Cargo's `build.build-dir` to the validated target with an
explicit CLI config value and remove the inherited `CARGO_BUILD_BUILD_DIR` from
the child environment. A separately configured build directory is not cleaned.
Paths containing braces are refused because Cargo can expand build-dir templates
even in quoted strings. Symlinked root paths, invalid caps, and measurement/cleanup
failures also do not trigger a full reset.

Maintenance failures do not change a build's pass/fail result. The caller must own
the target, prevent concurrent changes, and keep the filesystem namespace stable
for the entire run. The target must have no mounted descendants, including Linux
same-device bind mounts and file mounts. The device check is defense in depth: it
does not detect same-device mounts or prove that this precondition holds. The
preflight is not a lock and does not prevent path-swap races. Run the script only
after the runner's build, never alongside a process that shares that target.

The behavior tests use stub tools and disposable directories, not a live cache:

```sh
python3 -m unittest discover -s scripts/ci -p 'test_*.py' -v
```

## Featureless nextest process models

Full verification always runs `cargo test -p oneiron --lib --no-default-features`.
This mandatory libtest lane runs tests as parallel threads in one process, so it
exercises cross-test shared state and race behavior, including `#[cfg(test)]`
statics. Nextest isolates tests in separate processes. Matching test IDs therefore
does not preserve that semantic coverage; see `AGENTS.md` and the #922/#923 cases.

The obsolete `ONEIRON_FEATURELESS_RUNNER=nextest-8` full-script selector is rejected
before any stage runs. Unset or `libtest` retains the same nine mandatory commands.
Discover or run the full gate normally; the extra narrow-sync gate in `WORKFLOW.md`
is still required:

```sh
scripts/verify.sh --list
scripts/verify.sh
```

For a local **inner loop**, run the strict featureless profile directly:

```sh
env NEXTEST_USER_CONFIG_FILE=none cargo nextest run -p oneiron --lib \
  --no-default-features --profile featureless --test-threads 8 --retries 0
```

This includes all non-ignored featureless library tests, including the slow set.
The CLI pin overrides inherited `NEXTEST_RETRIES`; user-config suppression applies
only to this command. It is not full verification, does not emit `VERIFY-OK`, and
must not replace the mandatory shared-process libtest lane. Both CI test jobs run
the shared-process `cargo test` lane and the per-test-process nextest lane, in
that order. The CI nextest commands pin `--retries 0` even if the runner exports
`NEXTEST_RETRIES`; they do not suppress user configuration or set eight threads.

These **local inner-loop measurements** are a latency/compute choice, not
equivalent gate coverage. On the **Mac mini at eight slots**, with `CARGO_INCREMENTAL=0` and `debug=1`, three paired
featureless-library comparisons reduced wall time by **4.02%, 9.25%, and 6.90%**
(median paired reduction **6.90%**). Median user CPU rose from **197.7 to 251.8 s**;
median system CPU rose from **76.4 to 88.2 s**. These measurements establish no
aggregate-RAM benefit and no full-script speedup. Two clean Arch pairs showed no
improvement (nextest was slightly slower); a contaminated third pair was excluded.
No precise pooled Linux effect is claimed. These results do not show a speedup for
the CI recipes, which now include both process models.

## Diagnosing macOS vault-open ENOSPC

`StorageFull` / OS error 28 at vault open does not always mean the disk is full.
The macOS build explicitly enables LMDB's `posix-sem` feature to avoid SysV
semaphore key collisions (ONE-1148). Opening an LMDB environment needs two named
POSIX semaphores. Exhausting that host-wide pool also returns ENOSPC.

Check the actual failed allocation before deleting build output. Check free space
on both the build and temporary volumes; on APFS inspect the container as well:

```sh
df -h /Volumes/Cinema /private/tmp
diskutil apfs list
sysctl kern.posix.sem.max
```

A single successful `sem_open` is not enough to rule out pool exhaustion. In one
test-host incident, file writes, `F_FULLFSYNC` and memory maps succeeded. One
uniquely named semaphore opened, but a second **simultaneously held** semaphore
returned ENOSPC. Changing TMPDIR and reducing test threads did not fix vault open.
Any diagnostic semaphore must have a fresh exclusive name and must be closed and
unlinked by its creator. Never unlink another process's semaphores or change the
host-wide limit as an uncoordinated ticket repair.

Use the next available, capacity-guarded test host when the preferred host cannot
allocate the required pair. Keep the same feature set and tests, and record the
actual host. A host failure is not a reason to disable vault tests, weaken storage
errors, remove the macOS `posix-sem` selection or delete shared caches/snapshots.

## Measure a candidate

Use one heavy build per host. Check CPU load, active Rust/runner processes, and
free disk first. Never clean a developer's or runner's existing target to produce
a cold result. Give each configuration a fresh target **outside the checkout**.
Keep enough disk space for both targets; serialize and remove only your own
scratch targets if necessary. On macOS use a real `TMPDIR` under `/private/tmp`,
not the symlinked system default.

Capture the host, toolchain, revision, exact command/environment, wall time, CPU
time, peak RSS, target size, and Cargo's timing HTML for each stage. The examples
below disable incremental compilation to match the current CI runner contract;
they are not a prediction for a developer's incremental edit loop.

The command below is a **macOS example**. On Linux, use a run-owned path under
`/tmp` instead of `/private/tmp`, and GNU `/usr/bin/time -v` if it is installed.
GNU time was absent in the Arch preflight for this session, so that experiment
used a task-owned `wait4` recorder instead. Keep the remaining flags and
environment the same.

```sh
# Run from the worktree. These directories must be new and owned by this run.
mkdir -p /private/tmp/oneiron-build-measure/baseline /private/tmp/oneiron-build-measure/tmp
# macOS: /usr/bin/time -l. Linux: /usr/bin/time -v.
env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u CARGO_BUILD_BUILD_DIR \
  -u CARGO_PROFILE_TEST_DEBUG \
  CARGO_TARGET_DIR=/private/tmp/oneiron-build-measure/baseline \
  CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=2 \
  TMPDIR=/private/tmp/oneiron-build-measure/tmp \
  /usr/bin/time -l cargo clippy --workspace --all-targets --all-features \
  --config 'profile.dev.package.oneiron.codegen-units=16' \
  --config 'build.build-dir="/private/tmp/oneiron-build-measure/baseline"' \
  --locked --timings -- -D warnings
# Pin 16 units when reproducing the original debug-only comparison.
# Then run the scoped codegen build with exactly the same environment:
# cargo test --config 'profile.dev.package.oneiron.codegen-units=16' \
#   --config 'build.build-dir="/private/tmp/oneiron-build-measure/baseline"' \
#   -p oneiron --lib --all-features --no-run --locked --timings
```

Repeat with `CARGO_PROFILE_DEV_DEBUG=1` and a new `candidate` target, updating
both `CARGO_TARGET_DIR` and the CLI `build.build-dir` pin. Cargo's target-dir
setting alone does not constrain a separately configured build directory.
These commands do not run nested Cargo; for trybuild, clear the override and
verify that native metadata resolves both outer and nested target/build directories
inside the owned target. Do not assume an unsupported `{target-dir}` template.
Measure a warm repeat separately; a warm artifact hit is not a compiler optimization.
Cargo saves reports in `$CARGO_TARGET_DIR/cargo-timings/`. Copy each report to an
evidence directory before another command replaces `cargo-timing.html`. `du -sk`
reports allocated target size in KiB on these hosts. macOS `time -l` reports
maximum RSS in bytes; Linux `time -v` uses KiB.

Environment overrides propagate into subprocesses. In particular, trybuild's
generated workspace does **not** inherit the root profile table, while a
`CARGO_PROFILE_DEV_DEBUG` override reaches its nested Cargo process. Do not use an
environment-based whole-suite result as proof of an identical root-profile gain.
The scoped `--lib --no-run` measurement above does not execute trybuild.

A build benchmark is not the verification gate. Keep the all-target/all-feature,
featureless, standalone-server, full nextest, sync, doctest, and rustdoc warning
checks. Use `scripts/verify.sh` and the current `WORKFLOW.md` policy for gates,
not a reduced performance command.

## Initial resource comparison (2026-09-17)

Base: `ae13354be7bf8de6875de88272f0ca50ddb3c267`. Host: MacBook M4 Max
(`Mac16,5`), 16 cores, 64 GiB RAM, macOS 27.0 arm64. Cargo/rustc 1.96.0,
nextest 0.9.137. No linker, optimization, job-count, or feature changes.
`CARGO_INCREMENTAL=0`; separate fresh targets; no global Rust flags. Each target
ran workspace/all-target/all-feature Clippy, then the all-feature core library
test **build** (`--no-run`). Registries were already populated. This is a
single-pair result on a live workstation, not an isolated-machine benchmark.

| Stage / metric | Full debug (`2`) | Limited debug (`1`) |
| --- | ---: | ---: |
| Cold workspace Clippy wall | 102.07 s | 111.39 s |
| Cold workspace Clippy user CPU | 338.43 s | 338.19 s |
| Cold workspace Clippy system CPU | 45.33 s | 45.89 s |
| Cold workspace Clippy maximum RSS | 6.35 GB | 6.35 GB |
| Core lib test build wall, after Clippy | 118.39 s | 126.55 s |
| Core lib test build user CPU | 342.81 s | 300.36 s |
| Core lib test build system CPU | 25.83 s | 27.54 s |
| Core lib test build maximum RSS | 9.29 GB | 8.81 GB |
| Allocated target size after both builds | 5,322,748 KiB | 4,373,884 KiB |
| Allocated core test executable | 270,156 KiB | 257,268 KiB |
| Warm workspace Clippy wall | 3.12 s | 4.30 s |

Limited debug reduced measured test-build user CPU by **12.4%**, peak RSS by
**5.1%**, and the paired target footprint by **17.8%**. It did **not** demonstrate
an elapsed-time improvement. Background desktop activity varied; unrelated
`ffmpeg`/`node` work appeared during this window. The root profile change is a
resource-efficiency choice, not a claim of faster Clippy or a percentage reduction
in end-to-end CI time. Runtime test duration and full-workspace build size were
not measured by this comparison.

Cargo timings identified the core crate as the main bottleneck. In the baseline,
its Clippy library-test unit took 55.41 s. The core test build's library unit took
34.75 s and its test unit took 69.20 s. Limited debug reduced the library codegen
section from 11.72 s to 8.08 s, but does not remove the large front-end workload.

Raw evidence for this work session is outside the public repository at
`/private/tmp/oneiron-build-speed-evidence/`: command files, `measurements.json`,
preflight snapshots, `/usr/bin/time -l` logs, copied Cargo timing HTML, native
cleanup evidence, and stub-test results. That scratch path is a local artifact,
not a permanent published benchmark service. Use the recipe above to reproduce
on a new host and retain its own evidence.

### Initial codegen-unit probe

One extra experiment set only `profile.dev.package.oneiron.codegen-units=256`.
It reused the limited-debug dependency artifacts with incremental compilation
off. A control followed `cargo clean -p oneiron` in that scratch target and
rebuilt the same core command at the default 16 units. Native output contained
256 and 16 codegen objects respectively.

| Warm-dependency core rebuild | Default 16 units | Package-only 256 units |
| --- | ---: | ---: |
| Wall | 100.27 s | 95.16 s |
| User CPU | 152.01 s | 150.61 s |
| System CPU | 5.09 s | 5.22 s |
| Maximum RSS | 8.75 GB | 7.80 GB |

That single pair suggests a possible memory benefit and a small time benefit,
but is not a repeated or cross-host result. The test-unit artifacts grew from
686.9 MB to 700.4 MB (logical size), and the object count rose sixteenfold.
This single pair was not sufficient for the initial adoption decision. The
later repeated Mini measurements below support the package-only setting without
turning this historical pair into a general or incremental-build speed claim.

## Follow-up results (2026-09-17)

The follow-up baseline was `11830e7c035cf0465e61dc27db66493f8e3de838`.
Small repeatable gains count; these results are not a combined CI speedup figure.
Existing feature sets, warning gates, ignored tests, and release settings remain.

### Core codegen units: 256 adopted for dev/test

The Mac mini (`Oletymac`, M4, 16 GiB) ran package-only core library test builds
with all features, `--no-run`, four Cargo jobs, `debug=1`, and incremental
compilation disabled. Every accepted warm sample rebuilt zero non-core units.
The initial 16-unit build rebuilt 205 dependency units and is excluded as warm-up.
Interrupted/noisy attempts remain in the raw evidence, not as CGU correctness
regressions or usable performance samples. Valid slower controls are retained.

| Core codegen units | Warm samples | Median wall | Median total CPU | Maximum-child RSS range |
| --- | ---: | ---: | ---: | ---: |
| 16 | 3 | 93.036 s | 147.780 s | 4.92–5.43 GB |
| 64 | 3 | 88.695 s | 143.858 s | 4.91–5.21 GB |
| 256 | 4 | 89.127 s | 144.118 s | 5.00–5.33 GB |

Every accepted 256-unit build was faster than every accepted 16-unit build.
The median reduction was **3.909 s / 4.20% wall time**, with **2.48% less total
CPU**. The samples span recorded runtime-gap and build-only series; they are not
three uninterrupted balanced blocks. The direction held in both series.
RSS ranges overlap and their ordering changes by series: this establishes no
universal RAM improvement or penalty. Maximum-child RSS is not aggregate
process-tree memory. Median allocated core rebuild growth was about **9.6 MB
larger** at 256 units; that is not a full-workspace footprint measurement.

The root profile applies 256 only to `oneiron` dev/test code generation. Cargo's
ordinary incremental default is already 256; this preserves that count, but
**incremental edit-loop performance was not measured**. The 64-unit median was
about 0.43 s lower, with overlapping ranges, and selecting it globally would
change the ordinary incremental count from 256 to 64. Other packages' profile
settings and release/bench profiles stay unchanged. A profile change can still
rebuild dependent artifacts once.

There was no complete second-host reproduction: Arch trials encountered other
workloads, and MacBook admission failed its background-load rules before any
build. The earlier MacBook single pair above is supporting context, not a new
same-baseline reproduction. No Linux or universal speedup is claimed. Completed
core runtime trials used nextest's default tier and recorded nextest LEAK labels;
they are not a leak-free result and do not replace full verification and CI on
the integrated candidate.

For a controlled 16-unit comparison, override the named package setting, not a
less-specific global profile variable:

```sh
cargo test --config 'profile.dev.package.oneiron.codegen-units=16' \
  -p oneiron --lib --all-features --no-run --locked
```

### Other follow-ups

- **Compile-fail harness consolidation adopted.** Three `trybuild::TestCases`
  sessions became one, with the same ten explicit external-crate cases and all
  twenty source/expected-error files byte-identical. On the Mini, three warm runs
  per variant reduced median selected-set wall time from **3.371299 to
  1.339431 s**: **2.031868 s saved**. Median user/system CPU changed from
  **1.759024/1.427739 s** to **1.018909/0.771072 s**. Maximum-child RSS was
  effectively unchanged (about 231 MB). Three outer test IDs become one; each
  case still checks its expected diagnostic. Do not attribute the separate
  cold/warm harness-build difference or a whole-CI percentage to this change.
- **Workspace-first cache retention kept.** In a guarded, task-owned target,
  workspace dev cleanup reduced allocated size from **21.923 to 11.011 GiB**.
  Third-party dependencies, about 0.51 GiB of documentation, and about 1.72 GiB
  of nested trybuild output remained. The release pass succeeded with no release
  outputs to remove; there was no full reset. Separately, ready CI on the fixed
  baseline retained about **19.52 GiB** after workspace cleanup. These observations
  support keeping the current policy and diagnostics, not raising the 20 GiB cap
  or introducing a Linux cap without longer-term evidence.
- **Two duplicate Wire Cargo calls removed.** The helper remains the single
  place for the separate locked server and provisioner builds. The SDK dev
  build, NAPI release build, Python release build, and contract/parity tests
  remain. Fixture compilation errors now surface later; standalone helper use
  rejects stale lockfiles. Two fewer invocations are certain; elapsed-time
  savings were not measured.
- **Featureless nextest was initially retained for the local inner loop**, with the
  scoped Mini latency/CPU tradeoff above. Wave 8 later added it alongside the
  mandatory shared-process libtest lane in CI. Matching test IDs do not make
  the two process models coverage-equivalent.
- **No linker switch adopted.** Native probe output identified LLD 22.1.2, and
  captured workspace link invocations already selected `-fuse-ld=lld`. External
  Arch work interrupted the complete link-share/alternate-linker comparison.
  Mold performance remains inconclusive; do not assume a GNU-ld bottleneck or
  extrapolate a whole-workspace saving from the partial links.

The durable machine-local evidence archive is
`/Users/olety/.local/share/oneiron-build-ci-evidence/2026-09-17-aa35e5ce/followups/`:
`cgu-result-mini.json`, `cgu-independent-review/REVIEW.md`,
`trybuild-result-mini.json`, cache/featureless reports, raw commands, and
interruption records. It is outside the public repository, not a hosted
benchmark service. Preserve the exact host, revision, flags, warm-up exclusions,
and runtime/CI verdict separately when reproducing these results.
