# Performance bench: statistical-validity follow-up (ONE-1966)

Status: **design only**. This is a deferral plan, not an implemented repeat loop,
confidence interval (CI), or new publication criterion. The current
`oneiron-bench perf` certificate already seals `statistics.repeats = 1`, per-axis
*completed* sample counts, and `single_trial_axes`. Its rule states that no
variance or confidence interval is reported. Do not infer independent trials
from hundreds of queries or writes inside that one run. The current
`oneiron-eval perf-verify` consumer copies the single-trial caveat; it owns any
future statistical publication floor, not the engine bench.

This is the sibling **performance** bench of BEAM, not BEAM's answer-quality
scorer. The canonical boundary and axis list live in
[ARCH-0042, Performance bench](https://github.com/oneiron-dev/oneiron-docs/blob/main/site/src/pages/oneiron/eval/oneiron-arch-0042-beam-evaluation-harness-v1.astro):
warm and cold recall stay separate; no latency claim below 1,000 documents;
cache baselines start cold. Nothing here relaxes those bars or changes the
current `perf_plan.v1` schema, report, certificate hash, or verdict.

## Current threats to validity

- `PerfPlan` has no `repeats` field. `runner::execute` indexes one corpus,
  reopens one vault handle, measures cold recall first, warm recall next, then
  sessions, wake, resident memory, gated writes, precision, cache and NVMe.
  Cold-first on a *new handle* is deliberate; randomizing it behind warm work
  would invalidate the cold column. Later axes can inherit handle warming,
  telemetry writes, disk pressure, and ambient host drift from earlier axes.
- An axis's many observations within one run share a vault, host, corpus and
  time window. They are not independent run replicates. A p95 over queries or
  wake probes has sampling variation, but a CI built by treating these samples
  as independent runs would understate between-run uncertainty.
- `cache.events_path` is an operator-declared stream, not bench-observed real
  traffic. Replaying it multiple times cannot create independent trials or
  promote its advisory trust class into a blocking check.

## Proposed experiment contract (not yet supported)

1. Add a bounded positive `plan.repeats` with a default of one for existing
   single-run plans; reject zero and excessive work *at admission*, with an
   explicit limit justified by the full-run cost. Keep the supplied plan bytes
   and hash as submitted. A repeat means one **complete, independent trial**:
   re-create/index the deterministic corpus in a fresh vault directory, close
   the builder, reopen an unused handle, take cold before any warm query on that
   handle, and run all other applicable axes. Do not count sub-queries, curve
   rungs, wake probes, vector candidates, or children as repeats. Use a
   per-trial scratch path on the measured mount for NVMe; record whether it
   ran there. Capture trial id, order, timestamps, outcome, measured mount,
   artifact/child identity and environment alongside each trial's raw rows.
   Keep the corpus and seed fixed for *paired* comparisons; changing them
   requires a separate, declared experiment rather than silently mixing rows.
2. Preserve cold-first **within each trial**, but counterbalance the subsequent
   measured axes in a deterministic, recorded rotation across repeats. Fix
   safety/data dependencies explicitly: cold precedes warm on the fresh
   handle, and any axis that mutates the shared vault must either have a fresh
   axis-local vault from that trial's seeded corpus or stay in a documented
   invariant position. Wake/ready-child and NVMe scratch probes can rotate
   only if their resources and cleanup stay isolated. For two candidate
   artifacts/configurations, interleave fresh-vault trial *pairs* with AB/BA
   (or balanced ABBA) order on the **same host and mount**, recording the
   assignment before measurement. Never call a fixed sequential A-then-B
   series a controlled comparison. Cold cache events must come from distinct
   genuine traffic windows per repeat; if unavailable, leave the cache row
   single-trial/advisory and say why rather than duplicating a file.
3. Store every trial's measured axis values and completed sample counts,
   including failed/skipped/not-ready outcomes. Derive per-axis `repeats` from
   **successful, independent trials actually contributing to that axis**, not
   from the requested count. Retain requested and attempted counts separately.
   Never silently drop a failed trial to improve a CI. A full-run candidate
   with an incomplete required trial set must fail closed (or be refused at
   emission); an unavailable advisory axis remains an explicit caveat.
   Dynamically derive `single_trial_axes` from the actual per-axis trial
   count. Distinguish an unavailable interval from a zero-width interval.
4. Report an interval **per numeric headline metric, per axis and stratum**:
   cold/warm p50 and p95 separately; wake p50/p95; each session-curve rung;
   ready-child RSS; gated commits/s; each precision candidate's recall delta,
   memory and scan rate (pair its F32 baseline *within* a trial); each real
   cache rung's hit rate; sequential and random NVMe fsync latency separately.
   Keep descriptive counts and pass/fail status beside each interval. The
   independent resampling unit is the complete trial (and a paired trial
   difference for an A/B comparison), **not** a query, operation, child, or
   cache event. Predeclare a 95% two-sided trial-cluster bootstrap interval,
   a deterministic resampling seed, iteration count, point-estimate rule and
   minimum successful-trial threshold (proposed: 20, to be calibrated before
   use). Below the threshold, emit `not_ready: insufficient independent
   trials`, not a CI. Bootstrap entire trial rows, retaining their within-row
   correlation. Do not pool percentiles across runs or average p95 as if it
   were the p95 of all calls. Choose and document the trial-level estimand
   before implementation; preserve raw observations for audit. Report
   multiplicity/selection caveats for scanning many axes; an unadjusted 95%
   interval is not a simultaneous guarantee for all of them.
5. Keep the current certificate honest until the repeated-trial report exists.
   Any new report fields and digest definition need an exact external-verifier
   contract and hash tests over emitted bytes. The evaluator, not this bench,
   decides if CI width, number of trials, or a paired effect is sufficient to
   publish; no change to the existing blocking/advisory partition just because
   an interval exists. Compare paired A/B deltas with their intervals, not
   overlapping single-system intervals as a significance test. Report host
   drift, storage contention, and order effects as caveats even when an
   interval is narrow; repeats do not repair a confounded design.

## Acceptance tests for the later implementation

These are **future regression cases**, not claims of coverage in this PR:

- Admission refuses `repeats=0` and over-budget repeats; default-one plans
  still expose one actual trial. Missing/failed trials never inflate counts.
- On two or more repeats, emitted trial ids and order prove fresh vaults and
  unused cold handles. Cold always precedes warm within each trial, while
  eligible later axes rotate. A mutating axis cannot contaminate the next
  trial or a different axis's promised fresh state.
- Alternating A/B input order yields a balanced recorded schedule on the same
  host/mount. A fixed order and a duplicated cache-events file do *not* pass
  as independent evidence. A skipped NVMe probe has no numeric interval.
- A one-trial fixture reports no CI, twenty varied independent trials report
  deterministic per-metric intervals, and a paired comparison resamples
  whole pairs. A perturbation to one trial changes its CI/certificate hash;
  missing per-trial rows refuse sealing rather than becoming zero samples.
- The external verifier rejects an altered interval or trial count, retains
  cache as advisory, and does not turn an interval into a publishability gate
  without a separate eval-owned policy update.
