# Fleet load and regression receipts

`oneiron-bench fleet` measures the shipped server and engine. It does not print
capacity targets. The `fleet20k-v1` profile requires at least 20,000 simulated
agents. Each agent has a distinct persisted PERSON principal, a signed v2 token
with `actor_class=agent`, and one real v8 app-tier WebSocket. No mock server or
in-memory transport stands in for a held connection.

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
fallback zero floor. The floor retains the source receipt and its SHA-256 digest.
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
and finite p99 ceiling. Sample counts, quantiles and arithmetic are revalidated.
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
