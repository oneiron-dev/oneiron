# Fleet load and regression receipts

`oneiron-bench fleet` measures the shipped server and engine. It does not print
capacity targets. The `fleet20k-v1` profile requires at least 20,000 simulated
agents. Each agent has a distinct persisted PERSON principal, a signed v2 token
with `actor_class=agent`, and one real v8 app-tier WebSocket. No mock server or
in-memory transport stands in for a held connection.

## First measured fleet baseline (2026-09-19)

MacBook M4 Max, 16 logical CPUs, macOS kernel 27.0.0, optimized opt-3 binary.
Cinema worktree storage; 20,000 distinct authenticated actors, 4 listeners,
64 in-flight operations, 4 runtime threads, 1 write/recall round per actor.
This was a shared Wave host, not an isolated CPU-capacity experiment.

| Phase | Completed | Throughput/s | p99 ms |
|---|---:|---:|---:|
| ppr_full | 100 | 13.440 | 234.767 |
| ppr_prepare | 100 | 16.745 | 212.334 |
| ppr_resume | 100 | 13.148 | 135.658 |
| recall_0 | 20,000 | 22.096 | 8,187.406 |
| socket_open | 20,000 | 18,725.396 | 14.832 |
| socket_probe_after | 20,000 | 117,658.969 | 1.180 |
| socket_probe_before | 20,000 | 115,877.485 | 0.667 |
| write_0 | 20,000 | 16.835 | 8,898.897 |

All 20,000 writes were checked against stored MESSAGE text. All 20,000 recalls
contained their corresponding committed message. Both socket probes passed,
with the same 20,000 connections retained for 2,094.427 seconds. The observer
reported exit 0, 2,172.800 seconds total wall time and 5,594,202,112 peak resident
bytes. Setup and post-write content verification are not in the phase timings.

The 100 cold/resume PPR pairs produced identical IDs and score bits. However,
resume achieved only **0.9783x** fresh throughput (0.5480x including preparation).
That is **not** a demonstrated speedup. The lower resume p99 does not erase the
mean slowdown. It remains valid measured baseline data: the committed
[floor](evidence/W7-C10/fleet-macbook-floor.json) permits at most 15% throughput
loss and 20% p99 increase from each phase. The converter checks the recorded
ratio and, on a fresh receipt, the samples. A committed floor carries no samples, so
CI checks its summary numbers for shape only; `verify-floor` recomputes them from the
archived receipt. It does not confuse a valid baseline with a proven speedup.
The separate hot-path optimization acceptance is still open.

Full fleet receipts with per-sample arrays are archived off-repo at
`/Volumes/Cinema/archive/w7-evidence/W7-C10/` (checksums in `SHA256SUMS` there).
Each committed floor points to the archived receipt it was made from, by that
receipt's BLAKE3 over its file bytes. `verify-floor` (see *Explicit measured floors
and CI*) reads this table by the floor's file name:

| Floor | Archived receipt | Receipt BLAKE3 |
|---|---|---|
| `docs/ops/evidence/W7-C10/fleet-macbook-floor.json` | `fleet-macbook-before.json` | `a95a7e3dea6decf82e6b9022a47d978948d6e10c9a3ca5cefabd822bcfa15bec` |
| `docs/ops/evidence/W7-C10/fleet-arch-floor.json` | `fleet-arch-before.json` | `c9dc7b24d27b272749beebea38fff3a75fe80d3db80d1cb9dbd4bc1f2c222037` |

The [process receipt](evidence/W7-C10/fleet-macbook-before-process.json) is committed. The binary BLAKE3 is
`a455c0908e1c91b6c1b3fb9fb1bcfe811a44f5ffbc2bd3d0de717ead3dcdabd7`.
The mirror has no Git metadata; its null revision/dirty fields are retained, not
replaced with an inferred source revision. This artifact includes the telemetry
scalar repair, before the later cache-insert optimization and cfg-only cleanup.

The first durable Arch attempt ended with a 120-second operation deadline error
after 2,003.913 seconds. Its failed receipt does not expose the failing phase or
successful partial counts, so no throughput is inferred. It is retained as
[failed evidence](evidence/W7-C10/fleet-arch-timeout.json) with its
[process outcome](evidence/W7-C10/fleet-arch-timeout-process.json). The next attempt
keeps 20,000 agents and all assertions, with an explicit 600-second operation
deadline. This changes the profile budget, not host settings or storage durability.

### RC42 threshold comparison

The current manifest defaults are 50,000,000 calls per verb and 1,000,000 per
actor in a 60-second window. The measured MacBook aggregate witness and recall rates
extrapolate to about 1,010 and 1,326 calls/minute respectively. The verb default
is over 37,000 times the larger rate. Even the 18,725/s connection/auth-bind
burst extrapolates to about 1.124 million/minute, over 44 times below that default.
These are observations under this workload, not predicted future capacity.
The per-actor default remains far above this one-write/one-recall profile.
Manifest edits still take effect without restart and never refuse a call.

## Workload and measurement boundaries

- One vault and one `SyncServer::new` + `build_app` loopback server share the
  benchmark process. Client and server CPU costs are both included. This is not
  a remote network benchmark, a multi-vault fleet, or an LLM benchmark.
  The explicit `listeners` ports all serve that same instance and vault; agents
  spread evenly over those ports. Before connecting, each listener group
  reserves one kernel-selected loopback source port; sibling sockets reuse only
  that owned port with SO_REUSEADDR and distinct destination ports. This avoids
  macOS's default one-port-per-connect exhaustion without changing host sysctls. The receipt records the count, so comparisons cannot change it silently.
- All agent sockets open and authenticate before measured traffic starts.
  Each remains allocated through every write/recall round and the hold interval.
  Matching WebSocket Ping/Pong probes before and after the interval prove the
  same sockets remain usable. There is no reconnect or retry path.
- Each round sends one HTTP `facade/witness` per agent. The response receipt and
  persisted MESSAGE content must match the submitted deterministic message.
  Then each agent calls `recall` over its own held socket, using light effort
  and a unique alphabetic token. The result must contain that message's short ID.
- Writes and recalls run in separate phases. Concurrency is bounded, closed-loop,
  and stated in the plan. These are not 20,000 simultaneous in-flight writes.
  Per-request latency starts when its bounded-concurrency slot runs and includes
  serialization, transport, the server call and response validation. It excludes
  time waiting for a slot. Throughput uses the whole phase wall clock.
- Setup and the independent persisted-content audit are outside phase timings.
  Every timed operation must succeed. A timeout, bad response, missing entity,
  missing recall hit or socket failure produces a failed receipt and nonzero exit.
  No successful throughput is inferred from partial work.
- The receipt contains sorted raw latency samples, exact completed counts,
  elapsed time, throughput, and nearest-rank p99 for every round and socket phase.
  The printed table is derived from those observations.

## Run

Build on the assigned host and target with the normal workspace toolchain:

```text
cargo build --release -p oneiron-bench
cargo test -p oneiron-bench fleet::tests -- --test-threads=1
python3 -m unittest discover -s scripts/tests -p test_fleet_regression.py -v
```

Use a real absolute scratch directory. On macOS, prefer `/private/tmp/...`, not
`/var/...` symlinks. Host storage preflight may reject a platform; preserve that
failed receipt rather than bypassing the production open door.

Create a JSON plan with explicit workload and host settings. This is a workload
example, not measured performance or a CI floor:

```json
{
  "profile": "fleet20k-v1",
  "host_label": "replace-with-dedicated-host-name",
  "storage_label": "replace-with-device-and-filesystem",
  "scratch": "/absolute/existing/scratch",
  "agents": 20000,
  "listeners": 4,
  "concurrency": 64,
  "runtime_threads": 4,
  "rounds": 3,
  "hold_ms": 1000,
  "timeout_secs": 120,
  "map_size": 4294967296,
  "ppr_nodes": 1024,
  "ppr_samples": 100
}
```

```text
target/release/oneiron-bench fleet run --plan fleet-plan.json --out before.json
```

Provision at least two file descriptors per held socket (client and server),
plus HTTP and vault descriptors. Also check local ephemeral-port capacity.
20,000 held sockets require more than 40,000 descriptors in this process.
The command does not raise OS limits, alter sysctls, weaken auth, or silently
reduce agent count. A caller can raise its own process's soft descriptor limit
before launch (for example `ulimit -n 65536` in an isolated runner shell). This
changes no system-wide setting. Four listeners plus explicit owned source-port reuse accommodate 20k loopback
agents on a host with a 16,384-port ephemeral range. Destination fan-out alone
is insufficient on macOS; the harness explicitly binds before connecting. If permitted process limits are
still insufficient, retain the failed receipt instead of shrinking the fleet.
Host identity, CPU, OS/kernel, logical CPU count, FD limit, build profile and
compiled optimization level are captured in the receipt. Labels must identify
storage and the assigned machine; the program cannot verify an operator's label.
Run on a quiet dedicated host. No isolation from other workloads is implied.
The mandatory binary BLAKE3 digest identifies the measured artifact. Checkout
revision and dirty status describe the measurement directory when Git is available;
source archives and remote mirrors explicitly report null for both, never a guessed
commit. Publish the source build receipt beside those artifacts when applicable.

For a fast functional fixture (never valid for CI floor creation):

```text
target/release/oneiron-bench fleet smoke --scratch /absolute/existing/scratch --out smoke.json
```

Receipts use create-new semantics and are not overwritten. Keep stdout (the
readable table), JSON receipts and the exact plan with benchmark evidence.

## Measured hot-path optimization pair

After shutting down fleet traffic, the harness builds two identical deterministic
ring/chord graphs. Both run the same depth-10 PPR query for each distinct seed.
The baseline computes from scratch. The candidate resumes persisted depth-five
Forward-Push state. No exact depth-10 row exists before either call. Depth-five
preparation is timed separately. The baseline's pages are primed with the public
cache-bypass diagnostic, so "full" means full computation, not a cold OS cache.
Pair order alternates. Every returned ID and score bit must be equal.

The receipt reports both incremental speedup and speedup with preparation cost
included. A value below 1 is a slowdown, not an optimization success. This pair
isolates the existing PPR resume route. It is not a claim that light-effort fleet
recall used PPR or that the fleet as a whole became faster. Publish only observed
results. Keep before/after branch receipts for any later fleet-path change.

## Explicit measured floors and CI

A floor is created only by an explicit command against a successful, optimized,
fleet-scale receipt. There is no checked-in guessed numeric baseline and no
fallback zero floor. The floor retains the source receipt without per-sample arrays;
its `baseline_sha256` is the canonical-JSON SHA-256 of the full receipt.
The explicit tolerances are regression budgets, restricted to 1–30%, not capacity
guesses. The example accepts at most 15% throughput loss and 20% p99 increase:

```text
python3 scripts/fleet-regression.py make-floor --baseline before.json --throughput-loss 0.15 --p99-increase 0.20 --out floor.json
python3 scripts/fleet-regression.py compare --floor floor.json --candidate after.json --out comparison.json
```

Approve and store the measured floor as a host-specific CI artifact. The CI job
must supply it; do not recreate the floor from each candidate. On that dedicated
runner, use this single fail-closed command:

```text
python3 scripts/fleet-regression.py ci --floor floor.json --bench target/release/oneiron-bench --plan fleet-plan.json --candidate ci-run.json --out ci-comparison.json
```

`ci` refuses an absent/invalid floor or different plan before starting the binary.
It then runs the full plan and compares the resulting receipt. Exit codes:
0 = pass; 1 = measured regression; 2 = missing/incompatible/invalid evidence or
failed load. Every per-verb and PPR phase must meet its positive throughput floor
and finite p99 ceiling. A fresh receipt's sample counts, quantiles and arithmetic are
revalidated; the floor carries no samples, so its summary numbers are checked for shape only.
Missing verbs, incomplete writes/recalls, fixture receipts, output changes,
host/build settings changes and profile changes cannot pass. Revision and binary
digest may change; workload, host, and optimization output must not.

A new machine, kernel, FD limit, storage label, build setting or workload needs
new measured baseline approval. Nothing in this command edits a CI workflow or a shared host's settings.
The dispatch-only `.github/workflows/fleet-regression.yml` runs it on the selected
approved host, honours `CI_PAUSED`, and retains candidate/comparison artifacts.
It uses the committed `docs/ops/evidence/W7-C10/fleet-<host>-floor.json`, never a
floor regenerated from the candidate. The job prepares only the scratch path
explicitly approved in that floor; workload/host mismatches fail closed.

CI checks a committed floor's shape only: the full receipts are off-repo, so no CI
step can recompute a floor. On a host that holds the archive, recompute it:

```text
python3 scripts/fleet-regression.py verify-floor --floor docs/ops/evidence/W7-C10/fleet-arch-floor.json --archive /Volumes/Cinema/archive/w7-evidence/W7-C10 --bench target/release/oneiron-bench
```

`verify-floor` reads the floor's row from the receipt pointer table by the floor's
file name and hashes that archived receipt with `oneiron-bench fleet digest --file
<PATH>`, which prints the BLAKE3 hex of the file's bytes. It requires the row's
BLAKE3, `baseline_sha256` equal to the receipt's canonical-JSON SHA-256, and
`make-floor` over the receipt with the floor's own tolerances to reproduce the
floor exactly, so an edited summary number fails under a true digest. Exit codes:
0 = the floor is its receipt's; 2 = refused. With `ONEIRON_FLEET_ARCHIVE` naming the
archive and `ONEIRON_BENCH` a release `oneiron-bench`,
`scripts/tests/test_fleet_regression.py` runs it on both committed floors; elsewhere
that test skips.

## Residual miss scaling (separate receipt)

`fleet ppr-scaling --plan fleet-plan.json --out scaling.json` measures the paired
full/residual route at `ppr_nodes`, four times that size, and sixteen times that
size (maximum 100,000 nodes). It retains the same sample count and depth at every
size. Every pair must have byte-identical result IDs and score bits. The report
carries each raw timing sample, host and artifact identity, the observed miss-cost
growth ratio, and whether that ratio was below the node-growth ratio. The unit
fixture checks arithmetic and exact outputs, not noisy timing thresholds.

This schema is deliberately distinct from a fleet receipt and cannot set a fleet
CI floor. It does not start agent sockets or claim fleet throughput. Use it to
verify the cache-miss scaling acceptance without repeating the unrelated socket
load at every graph size. A non-sublinear result is reported honestly, not masked.

## Keeping a long profile alive across a writer round

`python3 scripts/fleet-observe.py --receipt process.json -- <bench command>`
records the measured process's exit/signal, wall/CPU time and peak resident bytes.
Its process receipt is not a throughput receipt. `--detach --log profile.log`
also creates an admission file and a separate POSIX session. This is useful for
remote macOS jobs, but **setsid and reparenting do not escape a Linux cgroup**.
A factory that cleans up the seat's session scope can still remove those local
processes before their terminal receipt is written.

For a local Linux profile that must outlive its seat, launch the observer as a
new transient user unit (`systemd-run --user --collect`), not under the seat's
session scope. Verify the unit's `ControlGroup` differs from the seat's before
claiming custody. Do not install or restart a service, add a runtime kill clock,
change shared host settings, or kill another unit. Keep the process-local FD
limit and all data/log/output paths explicit. Store runtime data under the
assigned worktree's `target/fleet-*` directories, which the source-sync wrapper
excludes. This prevents live LMDB files or pending receipts from being copied or
deleted during source sync. Compile activity during a measurement must still be
reported as host load, not silently treated as an isolated performance sample.

## Measured residual scaling before cache-insert optimization

The same optimized MacBook binary measured 100 bit-exact cold/resume pairs at
each size. Full and resumed results matched within each graph; graph sizes need
not produce the same score digest. The run retained real persistent-cache IO and
both durable query commits. It did not replace them with CPU-only timings.

| Nodes | Pairs | Full mean ms | Resume mean ms | Resume p99 ms |
|---|---:|---:|---:|---:|
| 1,024 | 100 | 140.045 | 139.369 | 419.134 |
| 4,096 | 100 | 126.070 | 119.899 | 258.909 |
| 16,384 | 100 | 175.348 | 185.796 | 374.936 |

The graph grew 16x while measured residual-miss cost grew **1.3331x**. That is
observed sub-linear growth for this workload, not a universal complexity proof.
The 16,384-node resumed arm was still slower than fresh (0.9438x throughput), so
this scaling result alone is not evidence of an overall speedup. Shared-host IO
variation is visible between runs and remains part of the evidence.
Raw [scaling receipt](evidence/W7-C10/ppr-scaling-macbook-before.json) and
[terminal outcome](evidence/W7-C10/ppr-scaling-macbook-before-process.json).

## Measured Arch fleet baseline (2026-09-19)

Arch Linux kernel 7.0.11-arch1-1, Ryzen 7 8745HS, 16 logical CPUs.
Optimized opt-3 binary, worktree filesystem, 20,000 authenticated actors,
4 listeners, concurrency 64, 4 runtime threads, one write/recall round.
The operation budget is 600 seconds; the workload was not reduced.

| Phase | Completed | Throughput/s | p99 ms |
|---|---:|---:|---:|
| ppr_full | 100 | 19.110 | 533.454 |
| ppr_prepare | 100 | 14.795 | 464.903 |
| ppr_resume | 100 | 21.165 | 366.054 |
| recall_0 | 20,000 | 17.840 | 22,543.896 |
| socket_open | 20,000 | 8,753.748 | 12.374 |
| socket_probe_after | 20,000 | 19,775.210 | 4.723 |
| socket_probe_before | 20,000 | 44,424.149 | 1.761 |
| write_0 | 20,000 | 41.716 | 9,310.103 |

All 20,000 persisted messages and matching recalls passed, as did both socket
probes. Connections were held for 1,602.789 seconds. The process completed exit 0
in 1,626.372 seconds with 5,537,247,232 peak resident bytes. Scoped compilation
and then a release build overlapped this run. It is a shared-host baseline,
not an isolated maximum-throughput claim.

The 100 exact cold/resume PPR pairs measured **1.1076x** incremental resume
throughput. Including the prior depth-five preparation gives **0.4557x**: the
optimization saves work only when that prior state already exists. Both figures
are retained. This is a measured residual-resume gain, not proof of the later
fresh-insert scan optimization.

The full receipt with per-sample arrays is archived off-repo at
`/Volumes/Cinema/archive/w7-evidence/W7-C10/` (checksums in `SHA256SUMS` there);
its BLAKE3 is in the receipt pointer table under the first measured baseline.
The [process outcome](evidence/W7-C10/fleet-arch-before-process.json) and
[approved floor](evidence/W7-C10/fleet-arch-floor.json) are committed. The floor
uses explicit 15% throughput-loss and 20% p99-growth regression budgets.

Binary BLAKE3:
`67f07c30805cff9c98ed4885003b6fb264108c2ec1c6279cef93f98882573be6`.
This binary predates the telemetry-scalar repair and cache-insert optimization.
The receipt’s revision/dirty fields describe its runtime checkout, not an
inferred compilation revision. The artifact remains a baseline, not a claim
that this was final-head performance. The prior binary copy has SHA-256
`d958a55adc0e045df8f54283809b3ee4c2a0ea626e92056fab12f23fbbd7e591`.

## Hot-path follow-up tickets

`ONE-2402` is the implemented residual-resume work in this change. The Arch
profile above demonstrates its incremental benefit with bit-identical results.
The later fresh-key dependency-scan change is its measured-profile follow-up in
this same PR; its new timing receipt is separate from the original resume gain.

The following are local follow-up IDs, not claims that external tracker issues
were created. They describe the next measurements/design work, not completed
optimizations:

- **ONE-2558/PERF-IO** — Attribute the durable write/recall tails and PPR commit
  time on a quiet host. PPR cache flush and telemetry currently commit separately.
  Any later batching must preserve best-effort telemetry isolation and atomic
  cache/dependency writes. Do not disable durability to improve a benchmark.
- **ONE-2558/PERF-PHASE** — Retain typed phase/actor context in a failed fleet
  receipt. The first Arch timeout did not identify its phase, so its cause cannot
  be assigned to retrieval, socket handling or storage from that receipt alone.

No unmeasured throughput improvement is assigned to either follow-up.

## Final cache-insert measurement — no demonstrated end-to-end gain

The final release binary completed 100 exact pairs at each of 1,024, 4,096 and
16,384 nodes. All result digests match the corresponding earlier graph-size
receipts. The 1,024-node phase uses the same plan, host, storage and PPR function
as the earlier Arch fleet profile, but runs without the preceding wire workload.
The host was not isolated. Disk waits dominated this run; its process used
1.246 CPU-user seconds and 0.521 CPU-system seconds over 550.724 wall seconds.

| 1,024-node phase | Before mean ms | After mean ms | Before p99 ms | After p99 ms |
|---|---:|---:|---:|---:|
| ppr_full | 52.329 | 434.047 | 533.454 | 5594.652 |
| ppr_prepare | 67.592 | 444.960 | 464.903 | 6404.892 |
| ppr_resume | 47.247 | 433.008 | 366.054 | 6835.662 |

These observed latencies are worse, not a measured gain for the fresh-insert
change. The source removes an unnecessary full dependency scan, but this sample
does not establish an end-to-end benefit. No floor is silently replaced with
these slower numbers. The earlier Arch 1.1076x incremental residual-resume gain
is separate evidence and remains explicitly qualified by preparation cost.

The later phases also show strong host variation:

| Nodes | Full mean ms | Resume mean ms | Resume p99 ms |
|---|---:|---:|---:|
| 1,024 | 434.047 | 433.008 | 6835.662 |
| 4,096 | 908.833 | 1120.656 | 13470.830 |
| 16,384 | 63.329 | 72.777 | 433.944 |

The final/lower-size cost ratio is 0.1681 despite 16x graph growth. That decrease
does not establish better asymptotic behavior: it reflects uncontrolled timing
variation. Its `observed_sublinear` flag was corrected to `false` during review;
the raw samples remain unchanged. Future receipts require nondecreasing,
sublinear cost at every measured interval. Use the separately published MacBook scaling run for the stated
observed sublinear result, and retain this unfavorable run as well.

Final binary BLAKE3:
`19a34221f48de49083abd1baff5693883efba6162a1f95789e4c1b194d04649e`.
Raw [after receipt](evidence/W7-C10/ppr-scaling-arch-after.json) and
[terminal outcome](evidence/W7-C10/ppr-scaling-arch-after-process.json).
