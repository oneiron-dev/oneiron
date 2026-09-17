# Build performance

## Policy

The workspace uses limited debug information (`debug = 1`) in the `dev` profile.
The `test` profile inherits it. This keeps file/line backtraces and module-level
information, but omits type and local-variable debugger information. It does not
change optimization, assertions, overflow checks, panic behavior, features, or
release profiles.

For a debugging session that needs locals, opt back into full debug information:

```sh
CARGO_PROFILE_DEV_DEBUG=2 cargo test -p oneiron --lib --all-features
```

Use the same profile setting for repeated commands that should reuse artifacts.
Changing the setting invalidates affected Cargo units once. Do not set `RUSTFLAGS`
for the warning gate: use Clippy's existing `-- -D warnings`. Global flags also
reach vendored path dependencies and split otherwise compatible caches.

The profile setting is portable to the MacBook, Mac mini, and Arch Linux hosts.
The measurements below are **MacBook measurements**, not a Linux or Mac mini
speedup claim. Release builds retain Cargo's release defaults.

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

The command below is a **macOS example**. On Arch Linux, use a run-owned path
under `/tmp` instead of `/private/tmp`, and replace `/usr/bin/time -l` with
`/usr/bin/time -v`. Keep the remaining flags and environment the same.

```sh
# Run from the worktree. These directories must be new and owned by this run.
mkdir -p /private/tmp/oneiron-build-measure/baseline /private/tmp/oneiron-build-measure/tmp
# macOS: /usr/bin/time -l. Linux: /usr/bin/time -v.
env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS \
  CARGO_TARGET_DIR=/private/tmp/oneiron-build-measure/baseline \
  CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=2 \
  TMPDIR=/private/tmp/oneiron-build-measure/tmp \
  /usr/bin/time -l cargo clippy --workspace --all-targets --all-features \
  --locked --timings -- -D warnings
# Then run the scoped codegen build with exactly the same environment:
# cargo test -p oneiron --lib --all-features --no-run --locked --timings
```

Repeat with `CARGO_PROFILE_DEV_DEBUG=1` and a new `candidate` target. Measure a
warm repeat separately; a warm artifact hit is not a compiler optimization.
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

### Codegen-unit experiment (not adopted)

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
Codegen-unit defaults remain unchanged. Revisit with repeated fleet measurements
rather than treating this as a proven general build-speed setting.
