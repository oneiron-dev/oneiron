//! Moved from `crates/oneiron/src/drafter/evaluation.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::drafter::types::DrafterServing;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// The key under a recipe's settings that holds its qualification rule.
pub const DRAFTER_QUALIFICATION_KEY: &str = "qualification";

/// Microseconds in one second: a native decode rate is tokens per second.
pub const MICROS_PER_SECOND: f64 = 1_000_000.0;

/// One arm of an evaluation: what drafts for the target in it.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DrafterEvaluationArm {
    /// The target alone, with no draft: the output reference.
    TargetOnly,
    /// The head that serves the target when the evaluation is planned.
    Incumbent,
    /// The version under evaluation.
    Candidate,
    /// The incarnation that serves the version after its activation.
    Served,
}

/// How many held-out cases, and how much generated output, a decision needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterSampleRule {
    /// The fewest cases every arm answered.
    pub min_cases: u64,
    /// The fewest tokens the target alone generated over those cases.
    pub min_output_tokens: u64,
}

/// The paired schedule the cases are replayed on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterMeasurementSchedule {
    /// Cases each evaluator incarnation answers, unmeasured, before its
    /// measured ones.
    pub warmup_cases: u64,
    /// The drafted blocks, in order: each block is one incarnation of the
    /// arm it names answering every case once. At least one `incumbent` and
    /// one `candidate`; the target-only reference runs after them.
    pub blocks: Vec<DrafterEvaluationArm>,
    /// The cases replayed on the serving incarnation after an activation.
    pub observation_cases: u64,
}

/// What a speed comparison measures.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DrafterSpeedMetric {
    /// Generated tokens over the native generate time: higher is better.
    NativeDecodeRate,
    /// The worker's acceptance to its first generated token: lower is better.
    TimeToFirstToken,
    /// The host's send to the answer's arrival: lower is better.
    EndToEnd,
}

impl DrafterSpeedMetric {
    fn higher_is_better(self) -> bool {
        self == Self::NativeDecodeRate
    }
}

/// How the runs of one arm are folded into one value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DrafterSpeedStatistic {
    /// A rate pooled over every run (all tokens over all generate time), or
    /// a time's mean over every run.
    Pooled,
    /// The median, over the cases, of each case's candidate value over its
    /// incumbent value.
    MedianPairedRatio,
}

/// What counts as a slowdown, and so what an improvement is: the first
/// metric must improve, and no metric may be worse. No regression is
/// tolerated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterSlowdownRule {
    pub metrics: Vec<DrafterSpeedMetric>,
    pub statistic: DrafterSpeedStatistic,
}

/// Why an evaluation is unknown: nothing activates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DrafterUnknownReason {
    /// The recipe names no qualification rule.
    NoQualificationRule,
    /// The recipe's qualification rule does not read or does not hold.
    InvalidQualificationRule,
    /// The version's held-out side is gone or holds no case that reads.
    NoHeldOut,
    /// Fewer cases or fewer generated tokens than the rule's sample.
    InsufficientSample,
    /// A divergence had no target-only logits to judge it by.
    NoLogitEvidence,
    /// More divergences in one case than the evaluator follows.
    UnresolvedDivergence,
    /// The arms did not run on one target, tokenizer, runtime and template,
    /// or an arm did not load the draft it was given.
    RuntimeIdentityMismatch,
    /// No managed worker of this process serves the target's pins with a
    /// draft for this one vault.
    NoEvaluatorWorker,
    /// An evaluator incarnation did not start, or failed a case another arm
    /// answered.
    WorkerError,
    /// The policy moved while the evaluation ran.
    PolicyMoved,
    /// The vault locked while the evaluation ran.
    VaultLocked,
    /// An erase reached the version or the incumbent it is compared with,
    /// or the version moved, while the evaluation ran: replay stopped.
    VersionMoved,
}

/// Why an evaluation failed: the version is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DrafterFailReason {
    /// A case's output left the target alone's where no allowed tie
    /// accounts for it.
    OutputMismatch,
}

/// What an evaluation decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DrafterEvaluationDecision {
    /// Token-identical to the target alone, up to allowed ties, on an
    /// adequate sample.
    Qualified,
    Failed {
        reason: DrafterFailReason,
    },
    Unknown {
        reason: DrafterUnknownReason,
    },
}

/// How one metric compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DrafterSpeedOutcome {
    Better,
    Equal,
    Worse,
    /// A run of either arm did not measure it.
    Unmeasured,
}

/// What the speed comparison says, under the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DrafterSpeedVerdict {
    /// The first metric is better and none is worse.
    Improved,
    /// No metric is worse and the first is not better.
    NotImproved,
    /// A metric is worse.
    Slowdown,
    /// A metric was not measured, or nothing was compared.
    Unmeasured,
}

/// One metric's comparison of two arms.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterSpeedComparison {
    pub metric: DrafterSpeedMetric,
    pub statistic: DrafterSpeedStatistic,
    /// The baseline arm's pooled value; `None` for a paired ratio.
    pub baseline: Option<f64>,
    /// The compared arm's pooled value; `None` for a paired ratio.
    pub compared: Option<f64>,
    /// The median paired ratio, compared over baseline; `None` when pooled.
    pub ratio: Option<f64>,
    pub outcome: DrafterSpeedOutcome,
}

/// One arm incarnation's identity, as its worker proved it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterArmIdentity {
    pub arm: DrafterEvaluationArm,
    /// The block it answered, in the schedule's order; the target-only
    /// reference's is the number of blocks.
    pub block: u32,
    /// What drafted in it: stock or a version; `None` for the target alone.
    pub serving: Option<DrafterServing>,
    /// The draft identity its answers named.
    pub draft_digest: Option<String>,
    pub model: Option<String>,
    pub tokenizer: Option<String>,
    pub runtime: Option<String>,
    pub template: Option<String>,
    pub epoch: Option<String>,
    /// The digest of its launch manifest.
    pub launch_manifest: Option<String>,
}

/// One case's run on one arm: counts and times, and the BLAKE3 of the
/// generated token ids, never the ids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterCaseMeasure {
    /// The case's place in the held-out side.
    pub case: u32,
    pub arm: DrafterEvaluationArm,
    pub block: u32,
    pub prompt_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    /// Waits before the work ran: the worker's queue and the engine's.
    pub queue_us: Option<u64>,
    pub prefill_us: Option<u64>,
    /// The native generate time over every pass.
    pub generate_us: Option<u64>,
    pub ttft_us: Option<u64>,
    /// The host's send to the answer's arrival.
    pub end_to_end_us: Option<u64>,
    pub drafts_proposed: Option<u64>,
    pub drafts_accepted: Option<u64>,
    /// BLAKE3 of the canonical JSON of the run's passes' token ids.
    pub output_blake3: [u8; 32],
}

impl DrafterCaseMeasure {
    fn value(&self, metric: DrafterSpeedMetric) -> Option<f64> {
        match metric {
            DrafterSpeedMetric::NativeDecodeRate => {
                let tokens = self.output_tokens?;
                let micros = self.generate_us.filter(|micros| *micros > 0)?;
                Some(tokens as f64 * MICROS_PER_SECOND / micros as f64)
            }
            DrafterSpeedMetric::TimeToFirstToken => self.ttft_us.map(|micros| micros as f64),
            DrafterSpeedMetric::EndToEnd => self.end_to_end_us.map(|micros| micros as f64),
        }
    }
}

/// One allowed divergence: where it fell and the target alone's top two raw
/// logits on the shared prefix. Never the tokens.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterTieEvidence {
    pub case: u32,
    /// `reason` or `answer`: the pass it fell in.
    pub phase: String,
    /// Its place among the pass's generated tokens.
    pub position: u64,
    pub top1_logit: f64,
    pub top2_logit: f64,
}

/// The candidate's output against the target alone's, case by case.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterTokenIdentity {
    /// Cases every arm answered and the comparison covered.
    pub cases: u64,
    /// Cases whose output is the target alone's, token for token.
    pub exact: u64,
    /// Cases whose output is the target alone's up to allowed ties, each
    /// continuation checked under its actual prefix.
    pub tied: u64,
    /// Cases with a divergence no allowed tie accounts for.
    pub mismatched: u64,
    /// Cases with more divergences than the evaluator follows.
    pub unresolved: u64,
    /// Cases whose divergence had no target-only logits to judge it by.
    pub without_logits: u64,
    /// Cases the incumbent answered token for token as the target alone.
    pub incumbent_exact: u64,
    /// Target-only continuations run under a drafted arm's prefix.
    pub continuations: u64,
    pub ties: Vec<DrafterTieEvidence>,
}

/// The held-out side the evaluation read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterEvaluationCorpus {
    /// The held-out side's plaintext BLAKE3, as the version pins it.
    pub held_out_blake3: [u8; 32],
    pub held_out_families_blake3: [u8; 32],
    /// The examples the side holds.
    pub examples: u64,
    /// The cases the evaluator opened and replayed: its exposure.
    pub opened: u64,
    /// Lines that did not read as a case.
    pub unreadable: u64,
}

/// `values`' median; `None` when there are none.
pub fn median(mut values: Vec<f64>) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    Some(if values.len() % 2 == 0 {
        f64::midpoint(values[middle - 1], values[middle])
    } else {
        values[middle]
    })
}

/// The mean of `metric` over `runs`; `None` when there are none or one did
/// not measure it.
pub fn mean_of(runs: &[&DrafterCaseMeasure], metric: DrafterSpeedMetric) -> Option<f64> {
    if runs.is_empty() {
        return None;
    }
    let values: Option<Vec<f64>> = runs.iter().map(|run| run.value(metric)).collect();
    let values = values?;
    Some(values.iter().sum::<f64>() / values.len() as f64)
}

/// One arm's pooled `metric` over `runs`: every token over every generate
/// microsecond for a rate, the mean for a time.
pub fn pooled(runs: &[&DrafterCaseMeasure], metric: DrafterSpeedMetric) -> Option<f64> {
    if metric != DrafterSpeedMetric::NativeDecodeRate {
        return mean_of(runs, metric);
    }
    if runs.is_empty() {
        return None;
    }
    let mut tokens = 0_u64;
    let mut micros = 0_u64;
    for run in runs {
        tokens = tokens.saturating_add(run.output_tokens?);
        micros = micros.saturating_add(run.generate_us?);
    }
    (micros > 0).then(|| tokens as f64 * MICROS_PER_SECOND / micros as f64)
}

/// Whether `compared` beats, equals or loses to `baseline` for `metric`.
pub fn outcome(metric: DrafterSpeedMetric, baseline: f64, compared: f64) -> DrafterSpeedOutcome {
    let order = compared.total_cmp(&baseline);
    let order = if metric.higher_is_better() {
        order
    } else {
        order.reverse()
    };
    match order {
        std::cmp::Ordering::Greater => DrafterSpeedOutcome::Better,
        std::cmp::Ordering::Equal => DrafterSpeedOutcome::Equal,
        std::cmp::Ordering::Less => DrafterSpeedOutcome::Worse,
    }
}

/// Every run of `runs` for one of `cases`.
pub fn runs_of<'r>(
    runs: &BTreeMap<u32, Vec<&'r DrafterCaseMeasure>>,
    cases: &[u32],
) -> Vec<&'r DrafterCaseMeasure> {
    cases
        .iter()
        .filter_map(|case| runs.get(case))
        .flatten()
        .copied()
        .collect()
}

/// One metric's comparison of arm `compared` with arm `baseline` over the
/// cases both answered.
pub fn compare_metric(
    statistic: DrafterSpeedStatistic,
    metric: DrafterSpeedMetric,
    baseline: &BTreeMap<u32, Vec<&DrafterCaseMeasure>>,
    compared: &BTreeMap<u32, Vec<&DrafterCaseMeasure>>,
) -> DrafterSpeedComparison {
    let mut row = DrafterSpeedComparison {
        metric,
        statistic,
        baseline: None,
        compared: None,
        ratio: None,
        outcome: DrafterSpeedOutcome::Unmeasured,
    };
    let cases: Vec<u32> = baseline
        .keys()
        .filter(|case| compared.contains_key(*case))
        .copied()
        .collect();
    match statistic {
        DrafterSpeedStatistic::Pooled => {
            row.baseline = pooled(&runs_of(baseline, &cases), metric);
            row.compared = pooled(&runs_of(compared, &cases), metric);
            if let (Some(base), Some(other)) = (row.baseline, row.compared) {
                row.outcome = outcome(metric, base, other);
            }
        }
        DrafterSpeedStatistic::MedianPairedRatio => {
            let ratios: Option<Vec<f64>> = cases
                .iter()
                .map(|case| {
                    let base = mean_of(baseline.get(case)?, metric)?;
                    let other = mean_of(compared.get(case)?, metric)?;
                    (base > 0.0).then(|| other / base)
                })
                .collect();
            row.ratio = ratios.and_then(median);
            if let Some(ratio) = row.ratio {
                row.outcome = outcome(metric, 1.0, ratio);
            }
        }
    }
    row
}

/// Compares arm `compared`'s runs with arm `baseline`'s under `rule`, over
/// the cases both answered: a slowdown when any metric is worse, unmeasured
/// when any is unmeasured or no case was compared, improved when the first
/// metric is better, not improved otherwise.
#[must_use]
pub fn compare_speed(
    rule: &DrafterSlowdownRule,
    runs: &[DrafterCaseMeasure],
    baseline: DrafterEvaluationArm,
    compared: DrafterEvaluationArm,
) -> (DrafterSpeedVerdict, Vec<DrafterSpeedComparison>) {
    let by_case = |arm: DrafterEvaluationArm| {
        let mut cases: BTreeMap<u32, Vec<&DrafterCaseMeasure>> = BTreeMap::new();
        for run in runs.iter().filter(|run| run.arm == arm) {
            cases.entry(run.case).or_default().push(run);
        }
        cases
    };
    let (base, other) = (by_case(baseline), by_case(compared));
    let comparisons: Vec<DrafterSpeedComparison> = rule
        .metrics
        .iter()
        .map(|metric| compare_metric(rule.statistic, *metric, &base, &other))
        .collect();
    let outcomes: Vec<DrafterSpeedOutcome> = comparisons.iter().map(|row| row.outcome).collect();
    let verdict = if outcomes.contains(&DrafterSpeedOutcome::Worse) {
        DrafterSpeedVerdict::Slowdown
    } else if outcomes.is_empty() || outcomes.contains(&DrafterSpeedOutcome::Unmeasured) {
        DrafterSpeedVerdict::Unmeasured
    } else if outcomes.first() == Some(&DrafterSpeedOutcome::Better) {
        DrafterSpeedVerdict::Improved
    } else {
        DrafterSpeedVerdict::NotImproved
    };
    (verdict, comparisons)
}

/// Why an activation did not happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DrafterActivationRefusal {
    /// The evaluation did not qualify the version.
    NotQualified,
    /// The version did not beat the incumbent, or a metric was slower or
    /// unmeasured.
    NotImproved,
    /// The version is no longer the one evaluated: erased, reverted to, or
    /// evaluated again; or an ancestor of it is erased.
    VersionMoved,
    /// The policy moved since the evaluation, is off, or excludes a world
    /// in the version's ancestry.
    PolicyMoved,
    /// The binding moved since the evaluation read it.
    BindingMoved,
    /// A rollback stopped further candidates for this target.
    CandidatesStopped,
    /// The vault is locked.
    VaultLocked,
}
