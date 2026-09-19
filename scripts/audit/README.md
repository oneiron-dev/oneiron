# Engine audit lanes

Pins are in `tools.json`. The CI compiler lanes use sccache 0.15.0, a persistent
host cache plus shared GitHub cache storage keyed by OS, architecture, Rust pin
and lockfile. Full-tier nextest commands are unchanged. `--show-stats` records
hit counts. Do not infer speedup from the existence of the configuration: retain
repeat-build logs and compare clean-checkout wall times.

`python3 scripts/audit/cache.py` measures three serial `cargo check` builds of
oneiron-server (including the core): uncached, cache population, and repeat. Each
starts with an empty run-owned artifact directory at the same path. It uses a
private cache/socket and saves timings plus repeat-only Rust hit counts. This is
a cold-artifact comparison, not a claim that caching beats a no-op warm target.
The script freezes a source copy and uses its own target; run it on an approved
build host within the host job budget; wrapper shells that redirect Cargo to another host
cannot collect that host's files. No installation or shared-target cleanup runs.

`python3 scripts/audit/mutation.py` runs pinned cargo-mutants over touched engine
crates, then checks outcomes. The initial checked-in corpus mutates the GPU
health conjunction and manifest tripwire bounds. This is a deterministic sentinel
audit across both engine crates, not exhaustive mutation coverage. The corpus and
matching test filter are pinned beside the measured baseline; expanding it needs
a fresh baseline receipt. `--report path/to/outcomes.json` checks a saved
report without rerunning. Timeouts, incomplete audits, empty reports and scores
below the checked-in floor fail. `mutation-baseline.json` explicitly distinguishes
a required floor from a measured engine baseline. The initial real-engine audit
is still required before setting `measured=true`.

`python3 scripts/audit/coverage.py --collect --toolchain nightly` collects disjoint full-tier nextest,
featureless libtest and doctest lanes with pinned cargo-llvm-cov. The doctest lane
requires an already installed nightly toolchain with LLVM doctest instrumentation
support (`--toolchain` can select a dated installed nightly). Cleaning removes only
profile counters, not build artifacts, and doctest binaries participate in report
discovery. `coverage.py
lane-0.lcov lane-1.lcov lane-2.lcov` merges existing reports. Canonical source path
and line are the dedupe key; repeated lanes never inflate covered/total lines.
The merged LCOV is line coverage, not a branch-coverage claim. Original lane
reports remain available for branch/region detail.

No tool is installed by the local scripts. Provision the pinned tools on the
approved audit host first. Tooling fixtures run without Cargo:

    python3 -m unittest discover -s scripts/audit -p 'test_*.py' -v

If the installed nightly is below this workspace's MSRV, coverage may use the
pinned stable compiler with the tool's supported rustdoc-only unstable opt-in:

    LLVM_COV=/path/to/llvm-cov LLVM_PROFDATA=/path/to/llvm-profdata python3 scripts/audit/coverage.py --collect --toolchain 1.96 --unstable-doctests

Both LLVM binaries must match the compiler's LLVM major version. The collector
sets `CARGO_LLVM_COV_SETUP=no`, so missing components fail rather than installing.
`RUSTC_BOOTSTRAP=1` is scoped to the doctest lane and its report, not production
checks or other test lanes. On macOS only the seven named UnsupportedPlatform
benchmark cases already excluded by CI are excluded here. Cargo and test threads
are bounded separately to two.
