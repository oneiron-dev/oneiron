# Build performance

This page records the dev/test profile settings in the root `Cargo.toml`, the
measurements behind them, the CI build helpers, and how to measure a profile
candidate. Nothing here is a merge check: the merge bar is
`cargo check --workspace --all-features` on the head (see `AGENTS.md`).

## Profile settings

The workspace uses limited debug information (`debug = 1`) in the `dev` profile.
The `test` profile inherits it. This keeps file/line backtraces and module-level
information, but omits type and local-variable debugger information. It does not
by itself change optimization, assertions, overflow checks, panic behavior,
features, or release profiles.

For a debugging session that needs locals, opt back into full debug information:

```sh
CARGO_PROFILE_DEV_DEBUG=2 cargo test -p oneiron --lib --all-features
```

Use the same profile setting for repeated commands that should reuse artifacts.
Changing the setting invalidates affected Cargo units once. Do not set
`RUSTFLAGS`: global flags also reach vendored path dependencies and split
otherwise compatible caches.

The core package also uses 256 codegen units for dev/test builds. This improves
the measured non-incremental Mini core build while matching the ordinary
incremental default count. It is not a measured incremental edit-loop gain.
Other packages' codegen-unit settings and release/bench defaults are unchanged.

The settings work on the MacBook, Mac mini, and Arch Linux hosts, but the gains
below are host-specific. The debug-info comparison is from the MacBook; the
codegen-unit results are from the Mini.

## Optimized dependencies in dev and test builds

`[profile.dev.package."*"] opt-level = 2` optimizes dependencies, including
non-member path packages (`heed`, `paste`, and the `pkix-chain` patch). Workspace
member library, binary, and test units, including `oneiron`, `oneiron-bench`,
and `oneiron-napi`, keep the dev optimization default (`0`); their build
scripts follow the separate build override (`2`). The test profile inherits
dev. Release, bench, and napi release builds keep their own profile defaults.

On a clean 16-core box at main `97bb7049` with rustc 1.96.1 (2026-09-26),
featureless library nextest (7,474 tests; `--profile featureless --retries 0`)
took **733 s** with dependencies at opt-level 0 and **430 s** at opt-level 2, a
**41% runtime reduction**. The cold test-binary build rose from **276 s** to
**329 s**. The build cost is paid once for cached dependencies; other feature
sets and hosts may see a different test speedup.

A single cold-build comparison on remote Ubuntu (8 Cargo jobs, rustc 1.96.1,
separate fresh targets, identical featureless `cargo test -p oneiron --lib
--no-default-features --no-run --locked`) held dependency opt-level at 2 and
changed only `profile.dev.build-override.opt-level`:

| Build-dependency opt-level | Cargo-reported build time | Wrapper wall time |
| --- | ---: | ---: |
| 0 (default) | 8m44s | 544 s |
| 2 (adopted) | 7m36s | 894 s, including ~438 s host-capacity wait |

Build-override 2 matches the normal-dependency setting and cut the measured
cold **build phase** by 68 s (13%) in this pair. The wrapper wall figures are
not comparable because the second run queued before Cargo started. Host and
target units, or different features, may still need separate builds of a
shared dependency. The pair does not predict edit-loop gains.

To opt out when stepping through dependency code in a debugger, use the
package override for that session, not a workspace-wide optimization change:

```sh
cargo test --config 'profile.dev.package."*".opt-level=0' \
  -p oneiron --lib --no-default-features
```

This causes a separate one-time dependency rebuild. To inspect build
scripts/build dependencies without optimization too, add
`--config 'profile.dev.build-override.opt-level=0'`. For debugger locals,
also use `CARGO_PROFILE_DEV_DEBUG=2`. Keep override choices the same across
commands when you want to reuse their artifacts.

## CI build settings

`.github/workflows/ci.yml` and the helpers in `scripts/ci/` set these:

- PR jobs set `CARGO_PROFILE_DEV_INCREMENTAL=true` and
  `CARGO_PROFILE_TEST_INCREMENTAL=true`, and run the scoped runner under
  `env -u CARGO_INCREMENTAL` to remove the runner's inherited
  `CARGO_INCREMENTAL=0`, which otherwise overrides the profile. Main pushes and
  dispatch runs set both profiles to `false`. sccache 0.15 is `RUSTC_WRAPPER`;
  it caches non-incremental units, and incremental workspace units pass
  through. Do **not** set `CARGO_INCREMENTAL=1`: sccache rejects every compile,
  including Cargo's version probe, with "incremental compilation is prohibited".
- `scripts/ci/rustc-threads.sh` is the `RUSTC_WORKSPACE_WRAPPER` for build and
  test commands. It gives only `oneiron` the parallel front end
  (`RUSTC_BOOTSTRAP=oneiron`, `-Zthreads=8`) and retries a compiler exit 101
  without the flag. `ONEIRON_PARALLEL_FRONTEND=0` opts out. Clippy supplies its
  own workspace wrapper.
- On Linux, `scripts/ci/with-test-tmpdir.sh` checks `/dev/shm` before each test
  command. With at least 12 GiB free it makes a per-command
  `/dev/shm/ci-<runner>-*` directory and cleans it even on failure. It runs a
  small probe there first; a `noexec` mount falls back to disk so test-created
  hooks still run. If the space or execution check fails, `TMPDIR` stays on disk.

Measurements on a clean 16-core Arch box, main `97bb7049`, rustc 1.96.1: core
test edit rebuild **84 s incremental vs 236 s** under `CARGO_INCREMENTAL=0`.
Core-only parallel front end: cold test build **334 s → 169–198 s**, edit
rebuild **84 s → 76 s**. Featureless nextest runtime: **733 s** with test temp
on disk vs **608 s** on `/dev/shm`. These are separate measurements, not a
combined CI saving.

## Cache retention

`scripts/ci/cap-target-cache.sh` keeps a target cache under a cap (default
20 GiB); in CI the Linux `Checks` job and the dispatch-only `Test (macOS)` job
run it. It first asks Cargo 1.96 to clean
workspace-owned outputs in both the dev/test and release profiles, including old
feature variants. It keeps third-party dependencies, including excluded vendor
packages, if that is enough to get under the cap. Only a successful cleanup and
remeasurement that is still over the cap triggers a full reset.

This is **workspace-first retention**, not LRU eviction. First-party code rebuilds
after cleanup. A dependency-heavy cache can still need a cold build after the
fallback reset. No job-time reduction is guaranteed.

Maintenance requires a canonical absolute `.../ci/target` path. Before each Cargo
clean pass, a Python 3 scan checks every descendant without following symlinks.
Any symlink (including internal, file, or dangling links), file or directory on a
different device from the root, or scan/stat/read failure keeps the remaining
cache without a full-reset fallback. This deliberately skips cleanup for
otherwise valid build outputs that contain symlinks. Under-cap caches are a
no-op and skip the scan.

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
even in quoted strings. Symlinked root paths, invalid caps, and measurement or
cleanup failures also do not trigger a full reset.

Maintenance failures do not change a build's pass/fail result. The caller must own
the target, prevent concurrent changes, and keep the filesystem namespace stable
for the entire run. The target must have no mounted descendants, including Linux
same-device bind mounts and file mounts. The device check is defense in depth: it
does not detect same-device mounts or prove that this precondition holds. The
preflight is not a lock and does not prevent path-swap races. Run the script only
after the runner's build, never alongside a process that shares that target.

## Featureless test process models

`cargo test -p oneiron --lib --no-default-features` runs tests as parallel
threads in one process, so it exercises cross-test shared state and race
behavior, including `#[cfg(test)]` statics. Nextest isolates tests in separate
processes. Matching test IDs therefore does not mean the same coverage; see
`AGENTS.md` and the #922/#923 cases. `scripts/verify.sh` rejects
`ONEIRON_FEATURELESS_RUNNER=nextest-8`; unset or `libtest` keeps the libtest lane.

For a local inner loop, run the strict featureless nextest profile directly:

```sh
env NEXTEST_USER_CONFIG_FILE=none cargo nextest run -p oneiron --lib \
  --no-default-features --profile featureless --test-threads 8 --retries 0
```

This includes all non-ignored featureless library tests, including the slow set.
The CLI pin overrides inherited `NEXTEST_RETRIES`; user-config suppression applies
only to this command.

On the **Mac mini at eight slots**, with `CARGO_INCREMENTAL=0` and `debug=1`,
three paired featureless-library comparisons of nextest against libtest reduced
wall time by **4.02%, 9.25%, and 6.90%** (median **6.90%**). Median user CPU
rose from **197.7 to 251.8 s**; median system CPU rose from **76.4 to 88.2 s**.
These show no aggregate-RAM benefit and no full-script speedup. Two clean Arch
pairs showed no improvement (nextest was slightly slower); a contaminated third
pair was excluded. No pooled Linux effect is claimed.

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
host-wide limit as an uncoordinated repair.

If the host cannot allocate the pair, use another capacity-guarded host with the
same feature set, and record which host ran. A host failure is not a reason to
weaken storage errors, remove the macOS `posix-sem` selection or delete shared
caches/snapshots.

## Measure a candidate

Run measurements on a fleet build host (the Mac mini or an Arch box), never on
the owner's MacBook. Use one heavy build per host. Check CPU load, active
Rust/runner processes, and free disk first. Never clean a developer's or
runner's existing target to produce a cold result. Give each configuration a
fresh target **outside the checkout**. Keep enough disk space for both targets;
serialize and remove only your own scratch targets if necessary. On macOS use a
real `TMPDIR` under `/private/tmp`, not the symlinked system default.

Capture the host, toolchain, revision, exact command/environment, wall time, CPU
time, peak RSS, target size, and Cargo's timing HTML for each stage. The examples
below disable incremental compilation, so they measure non-incremental builds,
not a developer's incremental edit loop.

The command below is for the Mac mini (macOS). On Linux, use a run-owned path
under `/tmp` instead of `/private/tmp`, and GNU `/usr/bin/time -v` if it is
installed; if it is not, record wall time, CPU and peak RSS another way. Keep the
remaining flags and environment the same.

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

For a controlled 16-unit core comparison, override the named package setting,
not a less-specific global profile variable:

```sh
cargo test --config 'profile.dev.package.oneiron.codegen-units=16' \
  -p oneiron --lib --all-features --no-run --locked
```

## Measurements behind the settings (2026-09-17)

### Limited debug information

Base `ae13354be7bf8de6875de88272f0ca50ddb3c267`, MacBook M4 Max (`Mac16,5`, 16
cores, 64 GiB, macOS 27.0 arm64), Cargo/rustc 1.96.0, nextest 0.9.137,
`CARGO_INCREMENTAL=0`, separate fresh targets, no global Rust flags. Each target
ran workspace/all-target/all-feature Clippy, then the all-feature core library
test **build** (`--no-run`). One pair on a live workstation.

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

Limited debug cut test-build user CPU by **12.4%**, peak RSS by **5.1%**, and
the target footprint by **17.8%**. It did **not** show an elapsed-time gain: it
is a resource choice, not a speed claim. Cargo timings showed the core crate as
the main bottleneck; limited debug cut its library codegen section from 11.72 s
to 8.08 s but does not remove the large front-end workload.

### Core codegen units

The Mac mini (`Oletymac`, M4, 16 GiB) ran package-only core library test builds
with all features, `--no-run`, four Cargo jobs, `debug=1`, and incremental
compilation disabled, from baseline `11830e7c035cf0465e61dc27db66493f8e3de838`.
Every accepted warm sample rebuilt zero non-core units; the first 16-unit build
is excluded as warm-up.

| Core codegen units | Warm samples | Median wall | Median total CPU | Maximum-child RSS range |
| --- | ---: | ---: | ---: | ---: |
| 16 | 3 | 93.036 s | 147.780 s | 4.92–5.43 GB |
| 64 | 3 | 88.695 s | 143.858 s | 4.91–5.21 GB |
| 256 | 4 | 89.127 s | 144.118 s | 5.00–5.33 GB |

Every accepted 256-unit build was faster than every accepted 16-unit build: a
median **3.909 s / 4.20% wall** and **2.48% total CPU** reduction. RSS ranges
overlap, so there is no RAM claim either way; maximum-child RSS is not
process-tree memory. Core rebuild output grew by about **9.6 MB**. The 64-unit
median was about 0.43 s lower with overlapping ranges, but choosing 64 would
change the ordinary incremental count from 256 to 64. There was no second-host
reproduction, so no Linux or universal speedup is claimed.

### Other results

- **Compile-fail harness consolidation adopted.** Three `trybuild::TestCases`
  sessions became one with the same ten cases. On the Mini, median selected-set
  wall time fell from **3.371 to 1.339 s**; maximum-child RSS was unchanged
  (about 231 MB).
- **Workspace-first cache retention kept.** In a task-owned target, workspace
  dev cleanup cut allocated size from **21.923 to 11.011 GiB** with no full
  reset. Ready CI retained about **19.52 GiB** after cleanup. This supports the
  20 GiB cap, not a higher one.
- **Two duplicate Wire Cargo calls removed.** The helper is the single place for
  the separate locked server and provisioner builds. Time savings were not
  measured.
- **No linker switch adopted.** Workspace links already use LLD 22.1.2
  (`-fuse-ld=lld`). The mold comparison was interrupted and is inconclusive.

The machine-local evidence archive is
`/Users/olety/.local/share/oneiron-build-ci-evidence/2026-09-17-aa35e5ce/followups/`
(`cgu-result-mini.json`, `trybuild-result-mini.json`, cache/featureless
reports, raw commands). It is outside the public repository.
