# Extraction teacher checkpoint gate (ONE-2312)

`oneiron-bench teacher-probe --checkpoint DIR --runner EXECUTABLE --manifest
CANDIDATE.json --policy RESOLVED.json --out APPROVED.json` gates a candidate `extraction_teacher`
manifest. It creates **two** new artifacts on pass: `APPROVED.json` and
`APPROVED.json.approval.json`. Publish both, then load the manifest and approval
and call `Vault::set_model_manifest_with_teacher_approval(&manifest, &approval)`.
`Vault::set_model_manifest` rejects an initial teacher pin and any teacher
change without a saved matching approval. The vault validates the pinned probe
identity, exact teacher-binding hash, model ID, and resolved vault policy identity,
then stores the
approval and manifest together. Subsequent writes can change other role rows
without re-running the teacher. A failing probe emits no new approval and
cannot pin the candidate at this public write door. A teacher route override
requires a separate probe for that model and is refused by this single-checkpoint
command and by the vault write. Resident route narrowing still works for
served roles on the same slot. If consolidation then requests the offline
teacher under a narrower resident route, binding fails closed instead of
falling back to its wider approved base checkpoint. The approval is an operator receipt, not a
signature: the checkpoint runner and publishing host must be trusted; this
mechanism prevents accidental bypass, not a malicious host forging a score.

The bench pins `fixtures/teacher_probe/conll_bio.v1.json` (10 English CoNLL
BIO-format sentences, PER/ORG/LOC/MISC, 24 gold spans). These are a deliberately
small **protocol/quality probe**, not the official CoNLL-2003 test set or a
claim of leaderboard quality. Its data are versioned here, not supplied at
runtime. The metric is exact typed entity-span micro-F1: span start, end and type must
all agree; `2*TP/(predicted+gold)` across the whole probe. The shipped
`POLICY_MANIFEST.teacher_probe` row sets the **default** minimum at 0.800000.
Trusted nested manifests may raise that minimum. Holder-specific rows may only
narrow the vault floor; attempted widening is refused. Export the applicable
snapshot through `vault.teacher_probe_policy(None)` (or `Some(holder_ref)` for a
stored holder row), serialize it as `RESOLVED.json`, and give that file to the
bench. No numeric per-run tuning flag exists. The vault re-resolves the policy
in the write transaction; an approval from an older or different policy is
refused even when its recorded F1 exceeds the new bar.
Malformed BIO, missing or extra sentences/tokens, runner failure, wrong model
identity and below-bar results fail closed. No tuning flags exist.

The model repository owns the real `EXECUTABLE` and checkpoint.
`DIR/model_id` must contain the exact candidate manifest model ID
(`provider/name@immutable-revision`). The executable must accept `--checkpoint DIR --probe PATH`, run inference against the provided
pinned sentences, and print one JSON object to stdout:
`{"model_id":"provider/name@immutable-revision","predictions":[["B-ORG","O",...],...]}`.
Rows and tags must align with the probe; the model ID must equal the
candidate manifest's `extraction_teacher` binding. Use an immutable checkpoint
revision and run the published gate before committing that binding. The engine
has no checkpoint weights or inference runtime. The included
`fixture_runner.py` and `checkpoint/output.json` are **canned CI protocol
fixtures**, not inference or proof of the actual LLM2Vec weights. CI exercises
the bench command with the passing fixture and a deliberately below-bar fixture.
The actual McGill-NLP/LLM2Vec-Qwen3-8B-mntp pin remains a model-repo/operator
choice after a real runner and immutable revision have passed. The served
extraction encoder remains a separate manifest role; this gate does not change
its mGTE-306M base or route the teacher to turns.

# Single-vault swarm baseline (2026-09-26)

**Busy-host observation, not a capacity claim. A quiet-machine rerun is required**
before setting a swarm limit or attributing a device-only improvement. Host
load was sampled for *each trial*, not once for each device. The NVMe trials
had 1-minute start load 1.42–6.16; HDD trials 5.06–11.67 on 16 logical CPUs.

- Host: `arch`, Linux x86_64; AMD Ryzen 7 8745HS (8 cores, 16 logical CPUs).
- **Primary NVMe baseline**: `/home/lexi/w8-opus/swarm-temp-nvme`,
  `/dev/nvme0n1p2`, `ROTA=0`, `ext4` (`/`), verified with `df -T` and `lsblk`.
  Raw results: [`results/swarm-nvme-2026-09-26.jsonl`](results/swarm-nvme-2026-09-26.jsonl).
- **Secondary HDD sensitivity run**: `/mnt/wd16/w8-build/swarm-temp`,
  `/dev/sda1` (WD 16 TB disk), `ROTA=1`, `ext4`, likewise verified.
  Raw results: [`results/swarm-hdd-2026-09-26.jsonl`](results/swarm-hdd-2026-09-26.jsonl).
  Storage device, rotational flag, filesystem, and temp root also appear on
  **every JSONL row**. These fields are required caller-supplied provenance,
  verified against the host at run time by the operator, not probed by Rust.
- Engine source at build: `e2bea92777b9b27fa276e884a2bef8067a1cf950`.
  Revised bench source was uncommitted while measuring: `src/swarm.rs` SHA-256
  `f5463a401d2317fd7396cf9478fc0e535ca706a58b4a1d7eca1d876c2239d76d`; optimized binary SHA-256 `92b3c3dc896967c7e1eebe6154a39dd2ede80aec4c00fc3b114304cc21f851f3`.
  Bench-only changes are committed in this PR; the engine did not change.
  The old, pre-fix HDD rows with the contaminated clock were removed, not
  pooled with these results. `/tmp` is `tmpfs`; its pilot is excluded.
- 36 fresh-vault trials per device: 3 trials × 3 modes × 4 tiers = 43,200
  completed operations/device, seed 42. Corpus: 256 planted and indexed text
  records, with all queries warmed before the timed cohort. Each trial runs
  1,200 actions against **one shared vault**, with 1/10/100/300 synchronized
  worker threads (at 300: 4 operations each). Write: one *new* text-indexed
  record per public `batch().commit()`. Recall:
  `Vault::search_text_with_telemetry`, checking the planted hit. Every recall
  persisted its best-effort telemetry row in these runs (1,200/1,200 recall-only,
  960/960 mixed); thus **the public recall path also writes**. Mixed has fixed
  80% recalls, 20% writes (960/240). Errors fail a run; no partial row emits.
- Throughput clock begins **inside the release gate after all workers are
  ready**, and ends at the **latest action completion instant** across workers,
  before parent join and result collection. Corpus/warmup, thread creation,
  readiness waits, and result merging are excluded. Percentiles are nearest
  rank per action; throughput divides completed actions by the whole cohort
  window. Table values are independent medians across three complete trials,
  **not** pooled percentiles. Raw JSONL retains each latency percentile, action
  count, elapsed time, start/end `/proc/loadavg`, device and run number.

### Primary baseline: NVMe (median of three per cell)

| Mode | Agents | Total ops/s | Commits/s / p50 ms / p99 ms | Recalls/s / p50 ms / p99 ms |
|---|---:|---:|---:|---:|
| write | 1 | 202.1 | 202.1 / 4.99 / 8.02 | — |
| write | 10 | 206.9 | 206.9 / 5.01 / 821.92 | — |
| write | 100 | 128.3 | 128.3 / 7.99 / 6575.48 | — |
| write | 300 | 133.2 | 133.2 / 8.50 / 8079.18 | — |
| recall | 1 | 158.2 | — | 158.2 / 5.64 / 15.15 |
| recall | 10 | 167.1 | — | 167.1 / 57.25 / 202.06 |
| recall | 100 | 149.0 | — | 149.0 / 568.57 / 1745.84 |
| recall | 300 | 152.6 | — | 152.6 / 1614.56 / 4090.21 |
| mixed | 1 | 171.5 | 34.3 / 7.69 / 11.66 | 137.2 / 5.31 / 9.60 |
| mixed | 10 | 136.5 | 27.3 / 7.88 / 389.54 | 109.2 / 58.99 / 519.51 |
| mixed | 100 | 155.1 | 31.0 / 6.04 / 2066.58 | 124.1 / 558.02 / 2604.47 |
| mixed | 300 | 147.5 | 29.5 / 6.47 / 4924.63 | 118.0 / 1673.39 / 5362.26 |

### Secondary: rotating HDD (median of three per cell)

| Mode | Agents | Total ops/s | Commits/s / p50 ms / p99 ms | Recalls/s / p50 ms / p99 ms |
|---|---:|---:|---:|---:|
| write | 1 | 20.7 | 20.7 / 26.90 / 454.91 | — |
| write | 10 | 24.3 | 24.3 / 45.31 / 3988.61 | — |
| write | 100 | 11.4 | 11.4 / 65.01 / 78423.05 | — |
| write | 300 | 34.6 | 34.6 / 2127.30 / 31576.10 | — |
| recall | 1 | 358.9 | — | 358.9 / 2.21 / 19.25 |
| recall | 10 | 410.9 | — | 410.9 / 3.55 / 238.87 |
| recall | 100 | 378.5 | — | 378.5 / 147.90 / 1337.49 |
| recall | 300 | 232.1 | — | 232.1 / 693.25 / 3403.03 |
| mixed | 1 | 89.5 | 17.9 / 19.53 / 118.70 | 71.6 / 2.56 / 53.34 |
| mixed | 10 | 37.5 | 7.5 / 34.45 / 1645.57 | 30.0 / 123.78 / 2013.23 |
| mixed | 100 | 89.4 | 17.9 / 32.01 / 3833.22 | 71.5 / 901.09 / 4352.74 |
| mixed | 300 | 48.7 | 9.7 / 93.31 / 16989.88 | 38.9 / 2845.47 / 17500.87 |

The one-agent write median is 202.1 commits/s on NVMe versus 20.7 on HDD.
This is **evidence of storage sensitivity**, not a controlled device-only
speedup: trials ran at different times and under different host loads. The
NVMe 100-agent write p99 is 6,575.48 ms and 300-agent p99 is 8,079.18 ms;
this does not establish a safe 300-agent capacity.

### First observed bottleneck at each tier

Separate 50-ms wait-channel samplers captured **all tasks, including the
process leader**; counts are **only for the full-thread prefix**, starting
when at least `agents + 1` threads exist and stopping after the first worker
leaves. The draining tail is excluded. See
[`results/sample_wait.py`](results/sample_wait.py),
[`results/swarm-wait-channels-nvme-2026-09-26.json`](results/swarm-wait-channels-nvme-2026-09-26.json)
and [`results/swarm-wait-channels-hdd-2026-09-26.json`](results/swarm-wait-channels-hdd-2026-09-26.json).
These are partial-cohort observations, **not a full-trial time breakdown**, a
call-stack profile, or proof of which mutex each futex owns. At 300 agents
NVMe write has only three sampled instants across all three trials, so it
cannot support precise phase proportions. Background builds shared both disks.

- **1 agent: storage wait first.** In NVMe write trials the single active
  worker was in uninterruptible disk waits in 147 all-task sampled instants
  out of 158 (`submit_bio_wait`: 112; `jbd2_log_wait_commit`: 27); the main
  thread waited in `futex_do_wait` while joining. On HDD, 3,172 disk-wait
  samples out of 3,234 instants (`rq_qos_wait`: 1,937). Even recall-only uses
  the telemetry writer: all recall runs recorded all expected telemetry rows.
- **10 agents: single-writer queuing plus storage.** NVMe write prefix:
  1,169 all-task `futex_do_wait` versus 105 disk-wait samples across 117
  instants. HDD: 17,406 futex versus 1,708 disk-wait samples. This pattern
  is consistent with multiple operations queued behind one LMDB writer whose
  active work waits on storage. It does not identify the exact futex owner.
- **100 agents: writer/telemetry serialization is first.** NVMe write
  prefix: 2,799 futex versus 26 disk-wait samples (28 instants); NVMe
  recall-only: 19,897 futex versus 195 disk-wait samples (199 instants).
  All 1,200 recall calls/trial persisted telemetry, so this is *not* a pure
  parallel-reader benchmark. At the HDD tier, 13,300 write futex samples
  versus 129 disk-wait samples (133 instants).
- **300 agents: serialized writer/telemetry remains the likely first
  constraint**, conditional on the sparse full-thread-prefix sample. NVMe
  mixed: 5,398 futex versus 20 disk-wait samples (18 instants); HDD mixed:
  93,899 futex versus 311 disk-wait samples (313 instants). NVMe write itself
  yielded only three full-prefix samples; p99 and rates carry the complete
  timed action window but the wait profile alone cannot establish a precise
  300-agent time share.

### Recall inversion: bounded interleaved diagnostic

The original primary/secondary tables show an HDD-over-NVMe recall-rate
inversion (HDD/NVMe median 2.27×, 2.46×, 2.54×, 1.52× at 1/10/100/300).
**Do not use those recall rows as a device-read-speed comparison.** Every
public recall persists one retrieval-telemetry row through
`Store::record_retrieval_run_with_visibility` and its own LMDB write
transaction + `commit()` (`store/retrieval_telemetry/run_store.rs`). The
retrieval-run record stores `elapsed_us` **before** that commit is attempted
(`vault/search_retrieval.rs`); full public-call latency includes it.

To check the inversion, we alternated **fresh vaults** on NVMe and HDD at
1/10/100/300 agents, three paired trials per tier, with the same release
binary, seed, 256-query warmup and 1,200 recall calls per trial. Pair order
was NVMe→HDD, HDD→NVMe, NVMe→HDD. Two bounded passes are saved:
[`results/recall-interleaved-2026-09-26.jsonl`](results/recall-interleaved-2026-09-26.jsonl)
(the original baseline binary) and
[`results/recall-decomposition-2026-09-26.jsonl`](results/recall-decomposition-2026-09-26.jsonl)
(one new binary used identically on both drives, SHA-256
`d3a7c662db88dee0a7fdfae3e520026326b498e9d3899c905e71696f162b1522`,
`src/swarm.rs` SHA-256
`e08bf8881ba428f904b5093135370dc5ef599e457210fabee3cd874bb0d70936`).
With `SWARM_DIAGNOSTIC=1`, the bench retains each run ID and API-call latency,
then reads its public `Vault::retrieval_run(id).elapsed_us` **after** the
throughput window. It reports both stored search-only time and the **paired
per-call residual** (API time minus search time). The residual includes
telemetry construction/staging/commit and minor post-search work: it is
**not** an isolated fsync timer. All 24 decomposition runs found 1,200/1,200
telemetry records. This bench-only diagnostic does not change engine behavior.

| Agents | NVMe recalls/s | HDD recalls/s | NVMe search / post-search p50 ms | HDD search / post-search p50 ms |
|---:|---:|---:|---:|---:|
| 1 | 245.2 | 278.0 | 0.024 / 3.996 | 0.026 / 2.231 |
| 10 | 244.8 | 304.4 | 0.028 / 29.043 | 0.028 / 24.538 |
| 100 | 243.5 | 395.2 | 0.028 / 319.947 | 0.024 / 207.797 |
| 300 | 261.9 | 348.8 | 0.052 / 1073.013 | 0.041 / 762.403 |

Each cell is the median of three trial-level rates or p50s. Search-only time
is tens of **microseconds** at every tier; the post-search writer path
accounts for nearly all median public-call latency and its inverse-rate
ordering. This **establishes the first bottleneck as per-recall telemetry
write/commit and its serialization**, not text search or an error in the
completed-action denominator. It does **not** establish why this host's
post-search median is lower on HDD than NVMe.

Every diagnostic row also includes start/end `/proc/diskstats` for both
physical devices, counter deltas, whole-process duration, and per-run start/
end load. The counters include unconnected host I/O and setup/warmup/teardown,
so they are not per-call fsync timings. For example, second-pass HDD
100-agent trial 1 had 395.2 recalls/s, 4 reads completed, 5,382 cumulative
write-ms and 3,352 busy-ms over 3.53 process seconds; trial 3 dropped to
81.1 recalls/s with 885 reads, 1,357,912 read sectors (~663 MiB), 19,193
write-ms and 17,641 busy-ms over 18.0 process seconds. Both one-minute
start loads were 7.95. This is direct **HDD I/O interference** evidence not
visible in load average. The NVMe 1-agent diagnostic calls had search p50
0.024 ms and post-search p50 3.996 ms; its HDD paired calls had search p50
0.026 ms and post-search p50 2.231 ms, with ~11,000 versus ~8,000
whole-process block-device writes per typical run. These are observations,
not proof that a device's fsync implementation alone caused the difference.

Mounts differ (`/dev/nvme0n1p2` ext4 `rw,relatime`;
`/dev/sda1` ext4 `rw,noatime`), as do sysfs write-cache modes
(`nvme0n1`: `write back`, `sda`: `write through`). `hdparm -W /dev/sda`
returned permission denied on this host; `nvme` CLI was unavailable. No
cache policy was changed. The cause of the HDD's lower *non-stalled*
post-search latency is still unisolated. **Finding for the next work:** a
public recall is currently a serialized telemetry commit workload; separate
that writer cost before using recall QPS as a pure read or device-ranking
number. Keep the quiet-machine rerun and paired-device caution.

No engine behavior, writer policy, telemetry policy, or group commit was changed.

### Reproduce

```sh
CARGO_TARGET_DIR=/mnt/wd16/w8-build/bench-target cargo build -p oneiron-bench --release -j 8
mkdir -p /home/lexi/w8-opus/swarm-temp-nvme
TMPDIR=/home/lexi/w8-opus/swarm-temp-nvme SWARM_DISK_DEVICE=/dev/nvme0n1p2 SWARM_DISK_ROTATIONAL=0 SWARM_DISK_FILESYSTEM=ext4 /mnt/wd16/w8-build/bench-target/release/oneiron-bench swarm --matrix > swarm-nvme.jsonl 2> swarm-progress.log
```

Confirm `findmnt -T "$TMPDIR"` and `lsblk -o NAME,ROTA,FSTYPE,MOUNTPOINTS`
before running: the storage labels are inputs, not automatic device detection.
`swarm --mode write|recall|mixed --agents 1|10|100|300 [--ops 1200] [--seed 42]`
runs one cell; `--matrix` emits exactly 36 rows. To reproduce the
post-search decomposition, set `SWARM_DIAGNOSTIC=1` and run recall-only cells
on **both** devices with the same freshly built binary; the extra telemetry
lookups happen only after the timed cohort. Capture `/proc/diskstats` and
`/proc/loadavg` just before and after each process to compare with the checked-in
diagnostic rows; alternate device order per pair to reduce time-order bias.

## BEAM deterministic versus independent Chroma fixture (ONE-2180)

The Chroma arm already uses the same `run.jsonl` corpus and f32-LE query
vectors as the deterministic arm. It sends vectors and text to Chroma's v2
HTTP API; it does not call `ContextPackBuilder`. The plan
[`fixtures/beam_measure.chroma.example.json`](fixtures/beam_measure.chroma.example.json)
pins both retrieval cards and the identical answerer model for those arms.
The checked-in run used the real Chroma HTTP server from `chromadb==1.5.9`
(the bundled `chroma` CLI reports 1.4.4). The answerer is the independent
retrieval-sensitive **fixture rule** in
[`scripts/fixture_model_stub.py`](scripts/fixture_model_stub.py), not the GPT
model whose illustrative pin occupies the plan. It extracts the updated code
from the retrieved context and otherwise answers `unknown`. Its exact-match
judge sees the gold only after answering and returns 0 for a wrong candidate.
This is a scored single-question fixture comparison, not a BEAM-128K model
benchmark. The dummy model usage and example prices do **not** support dollar
claims.

To reproduce both the supported and no-evidence control runs, start the
server and fixture host in separate terminals, then run the two plans:

```sh
uvx --from chromadb==1.5.9 chroma run --path /tmp/chroma-beam --host 127.0.0.1 --port 8000
python3 crates/oneiron-bench/scripts/fixture_model_stub.py
ONEIRON_EVAL_API_KEY=fixture-only cargo run -p oneiron-bench -j 8 -- beam measure crates/oneiron-bench/fixtures/beam_measure.chroma.example.json > supported.json
ONEIRON_EVAL_API_KEY=fixture-only cargo run -p oneiron-bench -j 8 -- beam measure crates/oneiron-bench/fixtures/beam_measure.no_evidence.chroma.example.json > no-evidence.json
```

The receipt [`results/beam-chroma-fixture-2026-09-27.json`](results/beam-chroma-fixture-2026-09-27.json)
links the full retained
[`supported`](results/beam-chroma-supported.raw.json) and
[`no-evidence`](results/beam-chroma-no-evidence.raw.json) run outputs by SHA-256
and pins corpus, plan, scorer-script and citation-corpus digests. With support,
the deterministic and Chroma arms each scored 1 for light and medium effort;
backbone-solo scored 0. Removing the supporting update but leaving the same
question and gold made both retrieval arms abstain and score 0. These are
**fixture scores**, not published BEAM accuracy. The timings of one local run
and the example tariff are not a comparative latency or cost study. The
`model_scaffold` wire/purity test still uses a Chroma HTTP stand-in; the
retained output above was obtained from Chroma itself.

The run's `citations.published_baseline_cards` gives stable IDs for the
agent-authored v1 Honcho and BEAM-paper rows in
[`fixtures/beam_citation_corpus.v1.json`](fixtures/beam_citation_corpus.v1.json).
Each ID resolves to a cited source, value, tier and disposition in
`citations.main_table` or `citations.appendix`. These are **published reference
rows**, not same-tier comparisons with the fixture. Unknown judge and retrieval
axes remain walled. For the separate vector-infrastructure cost-framing lane,
the run reuses the three VDBBench vendor-run cards from ONE-2181/#1067 in
[`fixtures/vector_db_infra.v1.json`](fixtures/vector_db_infra.v1.json). Their
recall@10, P99 latency and modeled search-only USD/query figures come from a
different corpus and host; never blend them into BEAM accuracy or interpret
them as measured Oneiron/Chroma local costs. A public model benchmark still
needs a pinned full dataset, real answering/judging, real model usage pricing,
and matching answerer conditions.
