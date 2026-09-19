# Engine audit lanes

Pins are in `tools.json`. The CI compiler lanes use sccache 0.15.0, a persistent
host cache plus shared GitHub cache storage keyed by OS, architecture, Rust pin
and lockfile. Full-tier nextest commands are unchanged. `--show-stats` records
hit counts. Do not infer speedup from the existence of the configuration: retain
repeat-build logs and compare clean-checkout wall times.

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
