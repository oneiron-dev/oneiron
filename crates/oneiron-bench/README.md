# Single-vault swarm baseline (2026-09-26)

This is a **busy-host observation, not a capacity claim**. A quiet-machine rerun
is required before setting a swarm limit or comparing a future optimization.
The 1-minute host load at the start of each run was 5.36–17.95 on a 16-logical-CPU host.

- Machine: `arch` (Linux x86_64, AMD Ryzen 7 8745HS, 8 physical cores / 16 logical CPUs).
- Engine checkout when compiled: `e2bea92777b9b27fa276e884a2bef8067a1cf950` (`origin/main` at branch cut).
  The measured bench source was uncommitted at build time but its exact bytes
  were then pinned in commit `b376ad52699dd69287c41d174445022b6ae32638`.
  Binary SHA-256: `2f91669a55ca69383ebb38def3b8ff1c1df89fc5658b6d174949dea364955b36`;
  measured `src/swarm.rs` SHA-256: `eed67db070c339669600912c7a49debcc35f55511550162efde8f9b1f24b3388`.
  The later source diff is lint-only (`is_multiple_of` and moving an import).
  Do not mistake the engine SHA alone for the binary's complete source revision.
- Release build: `CARGO_TARGET_DIR=/mnt/wd16/w8-build/bench-target cargo build -p oneiron-bench --release -j 8`.
  Vault tempfiles: `TMPDIR=/mnt/wd16/w8-build/swarm-temp` on `/dev/sda1` (ext4).
  The first pilot landed on `/tmp` (tmpfs) and is **excluded** from this baseline.
- 36 fresh-vault trials: three for each mode × agent tier. Seed 42; 256 planted,
  indexed corpus records; warm up every query before opening a synchronized
  worker cohort; 1,200 completed actions per trial (four per worker at 300).
  Every write adds **one** new text-indexed record in **one public batch commit**.
  Recall calls `Vault::search_text_with_telemetry`, verifies a planted hit, and
  records whether its best-effort telemetry row persisted. All recall rows did:
  1,200/1,200 in recall-only and 960/960 in mixed trials. Thus **recall is not
  a read-only transaction workload**; the public API also writes telemetry.
  Mixed slots are fixed at 80% recalls / 20% commits. Thread creation, corpus
  indexing and warmup are outside the timed window. p50/p99 use nearest rank;
  throughput uses the complete cohort window, not the sum of thread durations.
- Exact per-trial metrics, operation counts, elapsed time, and start/end
  `/proc/loadavg` readings are in [`results/swarm-2026-09-26.jsonl`](results/swarm-2026-09-26.jsonl).
  A run with errors fails closed and emits no result row; all 36 rows completed.

### Median of three trials (not a quiet-host capacity estimate)

Each write or recall cell is **operations/s / p50 ms / p99 ms** for that action.
The total column counts both kinds of completed actions. Median is taken per
metric across three complete trials; it is not a pooled percentile.

| Mode | Agents | Total ops/s | Commits/s / p50 / p99 | Recalls/s / p50 / p99 |
|---|---:|---:|---:|---:|
| write | 1 | 5.3 | 5.3 / 40.2 / 1552.0 | — |
| write | 10 | 4.9 | 4.9 / 201.5 / 35105.0 | — |
| write | 100 | 2.9 | 2.9 / 641.0 / 228616.1 | — |
| write | 300 | 26.3 | 26.3 / 3210.6 / 40079.8 | — |
| recall | 1 | 361.8 | — | 361.8 / 2.5 / 12.7 |
| recall | 10 | 379.7 | — | 379.7 / 25.8 / 58.0 |
| recall | 100 | 330.1 | — | 330.1 / 252.9 / 1080.3 |
| recall | 300 | 354.7 | — | 354.7 / 843.0 / 1457.0 |
| mixed | 1 | 88.1 | 17.6 / 17.7 / 203.6 | 70.5 / 2.6 / 54.5 |
| mixed | 10 | 38.5 | 7.7 / 74.4 / 1732.4 | 30.8 / 145.2 / 1575.9 |
| mixed | 100 | 92.3 | 18.5 / 56.4 / 3009.0 | 73.8 / 958.5 / 3559.0 |
| mixed | 300 | 92.1 | 18.4 / 2161.1 / 7412.9 | 73.7 / 2475.7 / 7484.2 |

### First observed bottleneck by tier

The separate 50-ms `/proc/<pid>/task/*/wchan` sampler observed active cohorts
only (at least agents + 1 threads). Its raw counts per trial are in
[`results/swarm-wait-channels-2026-09-26.json`](results/swarm-wait-channels-2026-09-26.json);
[`results/sample_wait.py`](results/sample_wait.py) is the sampler. These are
**wait-channel samples**, not a call-stack trace or a direct measurement of
which mutex owns each futex. Kernel names can vary; other CI builds shared
this disk, so the queue depth is not solely from the bench.

- **1 agent — storage queue/flush path first.** During write trials, the one
  active worker was in uninterruptible disk waits for 21,315 of 21,429
  sampled cohort instants (main thread slept on the join futex). Most common
  waits: `blk_mq_get_tag` 13,581, `rq_qos_wait` 5,663,
  `jbd2_log_wait_commit` 1,108. Even recall-only persisted telemetry on every
  call, and its active worker had 187 disk-wait samples across 196 instants.
- **10 agents — the serialized writer behind the disk queue.** In write trials,
  91,029 worker samples waited on `futex_do_wait` while 9,073 sampled workers
  were in disk waits. This is **consistent with** many calls queuing behind
  one LMDB writer; wchan alone cannot identify the precise mutex. Read-only
  labeling would be wrong because every public recall also wrote telemetry.
- **100 agents — writer wait dominates cohort time.** Write trials had 76,151
  futex samples vs 1,814 disk-wait samples. Recall-only had 75,899 futex and
  738 disk-wait samples, with 1,200/1,200 telemetry writes in each trial.
- **300 agents — writer/telemetry serialization remains first.** Write trials
  had 24,300 futex vs 81 disk-wait samples; mixed trials had 212,160 futex vs
  936 disk-wait samples. The active I/O worker still met a busy ext4 queue.

**Interpretation limit:** these are small, fixed-action cohorts on a highly
contended host. The counterintuitive 300-agent write rate exceeding the
100-agent rate reflects run-to-run I/O interference, **not** scaling. No
engine behavior, storage policy, or write batching changed here.

Reproduce from this worktree (release binary must be rebuilt after any edit):

```sh
mkdir -p /mnt/wd16/w8-build/swarm-temp
CARGO_TARGET_DIR=/mnt/wd16/w8-build/bench-target cargo build -p oneiron-bench --release -j 8
TMPDIR=/mnt/wd16/w8-build/swarm-temp /mnt/wd16/w8-build/bench-target/release/oneiron-bench swarm --matrix > swarm.jsonl 2> swarm-progress.log
```

`swarm --mode write|recall|mixed --agents 1|10|100|300 [--ops 1200] [--seed 42]`
runs one cell. Matrix emits exactly three JSONL rows per cell with per-run load.
