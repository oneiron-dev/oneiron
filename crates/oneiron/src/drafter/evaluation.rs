//! The drafter evaluator's engine half (FIX 14975, FIX 12569 slice 5;
//! DRAFTER-ACTIVATE = A + revert: "a new nightly drafter goes into service on
//! its own if it beats the current one on held-out turns with token-identical
//! output. Token-identical allows differences only where the target's top-2
//! logits are within a small epsilon. Any slowdown rolls it back
//! automatically, and the rollback shows in the morning report.").
//!
//! **The rule is recipe data.** A recipe names its qualification rule under
//! its settings' [`DRAFTER_QUALIFICATION_KEY`]: the logit epsilon, the sample
//! adequacy rule, the measurement schedule and the slowdown metric
//! ([`DrafterQualificationRule`]). The engine supplies none of these numbers.
//! With the rule absent or invalid, an evaluation is `unknown` and nothing
//! activates.
//!
//! **The doors.** A host that serves the vault's drafter reads what to
//! evaluate ([`Vault::drafter_evaluation_plan`]: the version, the head that
//! serves now, the rule and the held-out cases, opened from the version's
//! sealed held-out side), materialises the two heads' load sets for its
//! evaluator workers ([`Vault::materialize_drafter_evaluation_load_set`]),
//! replays the cases and records what it measured
//! ([`Vault::record_drafter_evaluation`]). The decision is the engine's, from
//! that evidence ([`DrafterEvaluationEvidence::decide`]): host evidence
//! decides, never the trainer. A qualified version is `qualified`, a version
//! whose output broke token identity is `rejected`, and an unknown one stays
//! `returned`. The record writes a `qualify` event.
//!
//! [`Vault::try_activate_drafter`] puts a qualified version into service when
//! it beat the head that served when it was evaluated, under the recipe's
//! rule, with no measured slowdown. In one write it checks the version, its
//! ancestry, the policy and the binding's generation again: a revert, an
//! erase or a policy set that landed meanwhile wins. It writes an `activate`
//! event and tells the serving host, which serves the version through its
//! one seam. [`Vault::observe_drafter_serving`] records what the host
//! measured on the incarnation that serves it; any slowdown, output
//! violation or worker error rolls the binding back to the previous clean
//! head (stock where there is none), with a `rollback` event. After a
//! rollback no candidate activates for that target until the owner sets the
//! policy or someone reverts it.
//!
//! Every record here is content-free: ids, digests, counts, logits and times,
//! never a token, a text or a key.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::{
    BINDINGS, BindingMove, DrafterActor, DrafterBinding, DrafterEvent, DrafterEventKind,
    DrafterMaterialized, DrafterPolicy, DrafterRecipe, DrafterRollbackReason, DrafterServedView,
    DrafterServing, DrafterTarget, DrafterVersion, DrafterVersionState, EVENTS, VERSIONS, ancestry,
    ancestry_names_world, drafter_load_set_blake3, invalid, move_binding_in_txn, policy_in_txn,
    record_event_in_txn, versions_by_id,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideKey, SideTable, SideTableDbs};
use crate::store::Store;
use crate::store::drafter_custody::drafter_artifact_retained_in_txn;
use crate::training_pack::SourcePin;
use crate::world_keys::VaultKeyStatus;
use crate::{LlmRequest, Vault};

/// The key under a recipe's settings that holds its qualification rule.
pub const DRAFTER_QUALIFICATION_KEY: &str = "qualification";

/// Microseconds in one second: a native decode rate is tokens per second.
const MICROS_PER_SECOND: f64 = 1_000_000.0;

const EVALUATIONS: SideTable<EntityId, DrafterEvaluation, Named> =
    SideTable::new(&side_table::DRAFTER_EVALUATION);

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

/// A recipe's qualification rule: the owner's numbers, none the engine's.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterQualificationRule {
    /// The largest gap between the target's top two raw logits at which a
    /// divergence between the target alone and a drafted arm is a tie.
    pub logit_epsilon: f64,
    pub sample: DrafterSampleRule,
    pub schedule: DrafterMeasurementSchedule,
    pub slowdown: DrafterSlowdownRule,
}

impl DrafterQualificationRule {
    /// The rule `recipe` names under its settings'
    /// [`DRAFTER_QUALIFICATION_KEY`].
    ///
    /// # Errors
    /// [`DrafterUnknownReason::NoQualificationRule`] when the recipe names
    /// none, [`DrafterUnknownReason::InvalidQualificationRule`] when it does
    /// not read or does not hold together.
    pub fn of_recipe(recipe: &DrafterRecipe) -> std::result::Result<Self, DrafterUnknownReason> {
        let value = recipe
            .settings
            .get(DRAFTER_QUALIFICATION_KEY)
            .ok_or(DrafterUnknownReason::NoQualificationRule)?;
        let rule: Self = serde_json::from_value(value.clone())
            .map_err(|_| DrafterUnknownReason::InvalidQualificationRule)?;
        if rule.holds() {
            Ok(rule)
        } else {
            Err(DrafterUnknownReason::InvalidQualificationRule)
        }
    }

    /// Whether the rule holds together: a finite epsilon, at least one case,
    /// both drafted arms and nothing else in the blocks, an observation, and
    /// each metric once.
    fn holds(&self) -> bool {
        let blocks = &self.schedule.blocks;
        let metrics: BTreeSet<DrafterSpeedMetric> = self.slowdown.metrics.iter().copied().collect();
        self.logit_epsilon.is_finite()
            && self.logit_epsilon >= 0.0
            && self.sample.min_cases >= 1
            && blocks.contains(&DrafterEvaluationArm::Incumbent)
            && blocks.contains(&DrafterEvaluationArm::Candidate)
            && blocks.iter().all(|arm| {
                matches!(
                    arm,
                    DrafterEvaluationArm::Incumbent | DrafterEvaluationArm::Candidate
                )
            })
            && self.schedule.observation_cases >= 1
            && !self.slowdown.metrics.is_empty()
            && metrics.len() == self.slowdown.metrics.len()
    }
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

/// What a host measured for one version, before the engine decides.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterEvaluationEvidence {
    pub version: EntityId,
    /// The version's generation the plan read.
    pub version_generation: u64,
    pub target: DrafterTarget,
    /// The head that served when the plan was read.
    pub incumbent: DrafterServing,
    /// The binding's generation the plan was read at.
    pub binding_generation: u64,
    pub corpus: DrafterEvaluationCorpus,
    pub policy_revision: u64,
    /// The recipe's name and revision.
    pub recipe: String,
    pub recipe_revision: SourcePin,
    /// The rule it was judged under; `None` when the recipe names none.
    pub rule: Option<DrafterQualificationRule>,
    pub arms: Vec<DrafterArmIdentity>,
    pub runs: Vec<DrafterCaseMeasure>,
    pub identity: DrafterTokenIdentity,
    /// Each metric's comparison of the candidate with the incumbent.
    pub comparisons: Vec<DrafterSpeedComparison>,
    pub speed: DrafterSpeedVerdict,
    /// Faults by code: a worker's refusal, an unreadable answer.
    pub errors: BTreeMap<String, u64>,
    pub decision: DrafterEvaluationDecision,
}

/// How an observation after an activation ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DrafterObservationVerdict {
    /// No slowdown, every output as qualified, no error.
    Clean,
    Slowdown,
    OutputMismatch,
    WorkerError,
}

impl DrafterObservationVerdict {
    fn rollback(self) -> Option<DrafterRollbackReason> {
        match self {
            Self::Clean => None,
            Self::Slowdown => Some(DrafterRollbackReason::Slowdown),
            Self::OutputMismatch => Some(DrafterRollbackReason::OutputMismatch),
            Self::WorkerError => Some(DrafterRollbackReason::WorkerError),
        }
    }
}

/// Identity-pinned reference measurements on the incarnation that serves an
/// activated version, against the incumbent's runs of its evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterObservation {
    /// The binding generation the activation set.
    pub generation: u64,
    /// The draft identity and epoch the serving incarnation's answers named.
    pub draft_digest: Option<String>,
    pub epoch: Option<String>,
    pub runs: Vec<DrafterCaseMeasure>,
    pub comparisons: Vec<DrafterSpeedComparison>,
    pub errors: BTreeMap<String, u64>,
    pub verdict: DrafterObservationVerdict,
    pub observed_at: u64,
}

/// One version's evaluation: the host's evidence, the engine's decision, and
/// what the serving incarnation showed after an activation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterEvaluation {
    pub id: EntityId,
    pub evidence: DrafterEvaluationEvidence,
    pub observation: Option<DrafterObservation>,
    /// The vault's recorded clock when it was recorded.
    pub evaluated_at: u64,
}

impl DrafterEvaluationEvidence {
    /// Decides the evaluation from its evidence. `fault` is what the host
    /// found that leaves it unknown (a missing rule, no evaluator worker, a
    /// worker fault, a mismatched identity). Then, in order: a divergence
    /// with no logit evidence or more divergences than followed is unknown,
    /// a divergence no allowed tie accounts for fails, a sample below the
    /// rule's is unknown, and otherwise it qualifies. A qualified version's
    /// candidate runs are compared with the incumbent's under the rule.
    pub fn decide(&mut self, fault: Option<DrafterUnknownReason>) {
        self.decision = self.decision_for(fault);
        let (speed, comparisons) = match (&self.decision, &self.rule) {
            (DrafterEvaluationDecision::Qualified, Some(rule)) => compare_speed(
                &rule.slowdown,
                &self.runs,
                DrafterEvaluationArm::Incumbent,
                DrafterEvaluationArm::Candidate,
            ),
            _ => (DrafterSpeedVerdict::Unmeasured, Vec::new()),
        };
        self.speed = speed;
        self.comparisons = comparisons;
    }

    fn decision_for(&self, fault: Option<DrafterUnknownReason>) -> DrafterEvaluationDecision {
        let unknown = |reason| DrafterEvaluationDecision::Unknown { reason };
        let Some(rule) = self.rule.as_ref() else {
            return unknown(fault.unwrap_or(DrafterUnknownReason::NoQualificationRule));
        };
        if let Some(reason) = fault {
            return unknown(reason);
        }
        let identity = &self.identity;
        if identity.without_logits > 0 {
            return unknown(DrafterUnknownReason::NoLogitEvidence);
        }
        if identity.unresolved > 0 {
            return unknown(DrafterUnknownReason::UnresolvedDivergence);
        }
        if identity.mismatched > 0 {
            return DrafterEvaluationDecision::Failed {
                reason: DrafterFailReason::OutputMismatch,
            };
        }
        let reference_tokens: u64 = self
            .runs
            .iter()
            .filter(|run| run.arm == DrafterEvaluationArm::TargetOnly)
            .map(|run| run.output_tokens.unwrap_or(0))
            .sum();
        if identity.cases < rule.sample.min_cases
            || reference_tokens < rule.sample.min_output_tokens
        {
            return unknown(DrafterUnknownReason::InsufficientSample);
        }
        DrafterEvaluationDecision::Qualified
    }
}

/// `values`' median; `None` when there are none.
fn median(mut values: Vec<f64>) -> Option<f64> {
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
fn mean_of(runs: &[&DrafterCaseMeasure], metric: DrafterSpeedMetric) -> Option<f64> {
    if runs.is_empty() {
        return None;
    }
    let values: Option<Vec<f64>> = runs.iter().map(|run| run.value(metric)).collect();
    let values = values?;
    Some(values.iter().sum::<f64>() / values.len() as f64)
}

/// One arm's pooled `metric` over `runs`: every token over every generate
/// microsecond for a rate, the mean for a time.
fn pooled(runs: &[&DrafterCaseMeasure], metric: DrafterSpeedMetric) -> Option<f64> {
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
fn outcome(metric: DrafterSpeedMetric, baseline: f64, compared: f64) -> DrafterSpeedOutcome {
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
fn runs_of<'r>(
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
fn compare_metric(
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

/// One held-out case as the evaluator replays it: its place in the side, the
/// wire model its rung named and the request exactly as the rung was sent
/// it.
#[derive(Debug, Clone)]
pub struct DrafterHeldOutCase {
    pub index: u32,
    pub wire_model: String,
    pub request: LlmRequest,
}

#[derive(Deserialize)]
struct HeldOutRung {
    wire_model: String,
}

/// The fields of one held-out line the evaluator reads; the answer text is
/// never read.
#[derive(Deserialize)]
struct HeldOutLine {
    form: String,
    rung: HeldOutRung,
    request: LlmRequest,
}

/// What a host evaluates for one version, read in one snapshot.
#[derive(Debug, Clone)]
pub struct DrafterEvaluationPlan {
    pub version: EntityId,
    pub version_generation: u64,
    pub target: DrafterTarget,
    pub recipe: String,
    pub recipe_revision: SourcePin,
    pub policy_revision: u64,
    /// The head that serves the target now: a version only where it may
    /// serve, else stock.
    pub incumbent: DrafterServing,
    /// The incumbent version's generation, for its load set's door.
    pub incumbent_generation: Option<u64>,
    pub binding_generation: u64,
    pub rule: std::result::Result<DrafterQualificationRule, DrafterUnknownReason>,
    pub cases: Vec<DrafterHeldOutCase>,
    pub corpus: DrafterEvaluationCorpus,
}

impl DrafterEvaluationPlan {
    /// The evidence of an evaluation of this plan, nothing measured yet.
    #[must_use]
    pub fn evidence(&self) -> DrafterEvaluationEvidence {
        DrafterEvaluationEvidence {
            version: self.version,
            version_generation: self.version_generation,
            target: self.target.clone(),
            incumbent: self.incumbent,
            binding_generation: self.binding_generation,
            corpus: self.corpus.clone(),
            policy_revision: self.policy_revision,
            recipe: self.recipe.clone(),
            recipe_revision: self.recipe_revision.clone(),
            rule: self.rule.as_ref().ok().cloned(),
            arms: Vec::new(),
            runs: Vec::new(),
            identity: DrafterTokenIdentity::default(),
            comparisons: Vec::new(),
            speed: DrafterSpeedVerdict::Unmeasured,
            errors: BTreeMap::new(),
            decision: DrafterEvaluationDecision::Unknown {
                reason: DrafterUnknownReason::NoQualificationRule,
            },
        }
    }
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

/// What [`Vault::try_activate_drafter`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrafterActivation {
    Activated {
        binding: DrafterBinding,
        event: DrafterEvent,
    },
    Refused {
        reason: DrafterActivationRefusal,
    },
}

/// What [`Vault::observe_drafter_serving`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrafterObserveOutcome {
    /// The observation was clean; the version keeps serving.
    Clean,
    /// The binding went back to `to`.
    RolledBack {
        to: DrafterServing,
        event: DrafterEvent,
    },
    /// The binding moved since the activation; nothing was rolled back.
    Moved,
}

/// Where an activation's serving stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrafterActivationServing {
    /// The serving host recorded a new incarnation serving the version at
    /// the activation's generation, naming this draft identity.
    Served { draft_digest: Option<String> },
    /// Not yet; what the serving host shows now.
    Pending { view: Option<DrafterServedView> },
    /// The binding moved since the activation.
    Moved,
}

/// Whether `version` and its ancestry may serve under `policy` in `txn`: the
/// version in one of `states`, its artifact kept and its key live, no
/// ancestor erased and no excluded world reached.
fn usable_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    policy: &DrafterPolicy,
    versions: &BTreeMap<EntityId, DrafterVersion>,
    version: &DrafterVersion,
    states: &[DrafterVersionState],
) -> Result<bool> {
    if !policy.enabled || !states.contains(&version.state) {
        return Ok(false);
    }
    let Some(artifact) = version.artifact.as_ref() else {
        return Ok(false);
    };
    let chain = ancestry(versions, version);
    let ancestors_live = chain
        .iter()
        .all(|step| step.state != DrafterVersionState::Erased)
        && chain
            .last()
            .is_some_and(|root| root.parent == DrafterServing::Stock);
    Ok(ancestors_live
        && !ancestry_names_world(versions, version, &policy.excluded_worlds)
        && drafter_artifact_retained_in_txn(store, txn, &version.id, &artifact.key_ref)?)
}

/// The head `binding` serves in `txn`: its version where it may serve, else
/// stock.
fn effective_serving_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    policy: &DrafterPolicy,
    versions: &BTreeMap<EntityId, DrafterVersion>,
    binding: &DrafterBinding,
) -> Result<DrafterServing> {
    let DrafterServing::Version(id) = binding.serving else {
        return Ok(DrafterServing::Stock);
    };
    let Some(version) = versions
        .get(&id)
        .filter(|version| version.target == binding.target)
    else {
        return Ok(DrafterServing::Stock);
    };
    Ok(
        if usable_in_txn(
            store,
            txn,
            policy,
            versions,
            version,
            &[DrafterVersionState::Qualified],
        )? {
            binding.serving
        } else {
            DrafterServing::Stock
        },
    )
}

/// The binding of `target` in `txn`; stock at generation 0 when unbound.
fn binding_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    target: &DrafterTarget,
) -> Result<([u8; 32], DrafterBinding)> {
    let key = target.key()?;
    let binding = BINDINGS
        .get(store, txn, &key)?
        .unwrap_or_else(|| DrafterBinding::stock(target.clone()));
    Ok((key, binding))
}

/// Whether a rollback stopped candidates for `target`: the last rollback of
/// it came after the last revert of it and the last policy set.
fn candidates_stopped_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    target: &DrafterTarget,
) -> Result<bool> {
    let mut stopped = false;
    for row in EVENTS.iter_raw_from(store, txn, &[])? {
        let (_, value) = row?;
        let Ok(event) = EVENTS.decode_value(&value) else {
            continue;
        };
        let names_target = event
            .change
            .as_ref()
            .is_some_and(|change| change.target == *target);
        match event.kind {
            DrafterEventKind::Rollback { .. } if names_target => stopped = true,
            DrafterEventKind::Revert { .. } if names_target => stopped = false,
            DrafterEventKind::Policy { .. } => stopped = false,
            _ => {}
        }
    }
    Ok(stopped)
}

/// The previous clean head of `binding` in `txn`: its previous version where
/// that may still serve, else stock.
fn previous_clean_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    policy: &DrafterPolicy,
    versions: &BTreeMap<EntityId, DrafterVersion>,
    binding: &DrafterBinding,
) -> Result<DrafterServing> {
    let DrafterServing::Version(id) = binding.previous else {
        return Ok(DrafterServing::Stock);
    };
    let Some(version) = versions
        .get(&id)
        .filter(|version| version.target == binding.target)
    else {
        return Ok(DrafterServing::Stock);
    };
    Ok(
        if usable_in_txn(
            store,
            txn,
            policy,
            versions,
            version,
            &[DrafterVersionState::Qualified],
        )? {
            binding.previous
        } else {
            DrafterServing::Stock
        },
    )
}

/// `bytes`, the held-out side, as cases: one per line that reads as this
/// corpus's form; how many did not.
fn held_out_cases(bytes: &[u8]) -> (Vec<DrafterHeldOutCase>, u64) {
    let mut cases = Vec::new();
    let mut unreadable = 0_u64;
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        match serde_json::from_slice::<HeldOutLine>(line) {
            Ok(read) if read.form == super::corpus::DRAFTER_CORPUS_FORM => {
                let Ok(index) = u32::try_from(cases.len()) else {
                    unreadable += 1;
                    continue;
                };
                cases.push(DrafterHeldOutCase {
                    index,
                    wire_model: read.rung.wire_model,
                    request: read.request,
                });
            }
            _ => unreadable += 1,
        }
    }
    (cases, unreadable)
}

/// The plan of `version` in `txn`, before its held-out side is opened.
fn plan_head_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    version: &EntityId,
) -> Result<Option<DrafterEvaluationPlan>> {
    let policy = policy_in_txn(store, txn)?;
    let versions = versions_by_id(store, txn)?;
    let Some(row) = versions.get(version) else {
        return Ok(None);
    };
    if !usable_in_txn(
        store,
        txn,
        &policy,
        &versions,
        row,
        &[DrafterVersionState::Returned],
    )? {
        return Ok(None);
    }
    let Some(corpus) = row.corpus.as_ref() else {
        return Ok(None);
    };
    let (_, binding) = binding_in_txn(store, txn, &row.target)?;
    let incumbent = effective_serving_in_txn(store, txn, &policy, &versions, &binding)?;
    let incumbent_generation = incumbent
        .version()
        .and_then(|id| versions.get(&id))
        .map(|found| found.generation);
    let pin = DrafterEvaluationCorpus {
        held_out_blake3: corpus.held_out.blake3,
        held_out_families_blake3: corpus.held_out_families_blake3,
        examples: corpus.held_out.examples,
        opened: 0,
        unreadable: 0,
    };
    Ok(Some(DrafterEvaluationPlan {
        version: row.id,
        version_generation: row.generation,
        target: row.target.clone(),
        recipe: row.recipe.id.clone(),
        recipe_revision: row.recipe.revision.clone(),
        policy_revision: policy.revision,
        incumbent,
        incumbent_generation,
        binding_generation: binding.generation,
        rule: DrafterQualificationRule::of_recipe(&row.recipe),
        cases: Vec::new(),
        corpus: pin,
    }))
}

/// Activates the evaluation `id`'s version in `txn`, every check of
/// [`Vault::try_activate_drafter`] made again here.
fn activate_in_txn(vault: &Vault, txn: &mut RwTxn<'_>, id: &EntityId) -> Result<DrafterActivation> {
    let store = &vault.store;
    let refused = |reason| Ok(DrafterActivation::Refused { reason });
    let evaluation = EVALUATIONS
        .get(store, txn, id)?
        .ok_or(Error::EntityNotFound)?;
    let evidence = &evaluation.evidence;
    if evidence.decision != DrafterEvaluationDecision::Qualified {
        return refused(DrafterActivationRefusal::NotQualified);
    }
    if evidence.speed != DrafterSpeedVerdict::Improved {
        return refused(DrafterActivationRefusal::NotImproved);
    }
    let policy = policy_in_txn(store, txn)?;
    let versions = versions_by_id(store, txn)?;
    let Some(version) = versions.get(&evidence.version) else {
        return refused(DrafterActivationRefusal::VersionMoved);
    };
    if version.evaluation != Some(*id) || version.target != evidence.target {
        return refused(DrafterActivationRefusal::VersionMoved);
    }
    if policy.revision != evidence.policy_revision {
        return refused(DrafterActivationRefusal::PolicyMoved);
    }
    if !usable_in_txn(
        store,
        txn,
        &policy,
        &versions,
        version,
        &[DrafterVersionState::Qualified],
    )? {
        let reason = if policy.enabled
            && !ancestry_names_world(&versions, version, &policy.excluded_worlds)
        {
            DrafterActivationRefusal::VersionMoved
        } else {
            DrafterActivationRefusal::PolicyMoved
        };
        return refused(reason);
    }
    let (key, binding) = binding_in_txn(store, txn, &evidence.target)?;
    if binding.generation != evidence.binding_generation {
        return refused(DrafterActivationRefusal::BindingMoved);
    }
    if candidates_stopped_in_txn(store, txn, &evidence.target)? {
        return refused(DrafterActivationRefusal::CandidatesStopped);
    }
    let previous = binding.serving;
    let (binding, event) = move_binding_in_txn(
        store,
        txn,
        &key,
        binding,
        BindingMove {
            to: DrafterServing::Version(version.id),
            previous,
            by: DrafterActor::Coach,
            kind: DrafterEventKind::Activate {
                version: version.id,
            },
            at: vault.now_recorded_at(),
        },
    )?;
    Ok(DrafterActivation::Activated { binding, event })
}

/// Records `observation` on evaluation `id` in `txn` and, when it is not
/// clean and the binding still serves the version at the observation's
/// generation, rolls the binding back to its previous clean head.
fn observe_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    mut observation: DrafterObservation,
) -> Result<DrafterObserveOutcome> {
    let store = &vault.store;
    let at = vault.now_recorded_at();
    let mut evaluation = EVALUATIONS
        .get(store, txn, id)?
        .ok_or(Error::EntityNotFound)?;
    observation.observed_at = at;
    let verdict = observation.verdict;
    let generation = observation.generation;
    evaluation.observation = Some(observation);
    EVALUATIONS.put(store, txn, id, &evaluation)?;
    let Some(reason) = verdict.rollback() else {
        return Ok(DrafterObserveOutcome::Clean);
    };
    let version = evaluation.evidence.version;
    let (key, binding) = binding_in_txn(store, txn, &evaluation.evidence.target)?;
    if binding.generation != generation || binding.serving != DrafterServing::Version(version) {
        return Ok(DrafterObserveOutcome::Moved);
    }
    let policy = policy_in_txn(store, txn)?;
    let versions = versions_by_id(store, txn)?;
    let to = previous_clean_in_txn(store, txn, &policy, &versions, &binding)?;
    let previous = binding.serving;
    let (_, event) = move_binding_in_txn(
        store,
        txn,
        &key,
        binding,
        BindingMove {
            to,
            previous,
            by: DrafterActor::Host,
            kind: DrafterEventKind::Rollback { version, reason },
            at,
        },
    )?;
    Ok(DrafterObserveOutcome::RolledBack { to, event })
}

/// Drops, in an erase's own transaction, every evaluation that names a
/// version of `reach` as its candidate or its incumbent, and every row that
/// does not decode. Its per-case digests go with it.
///
/// # Errors
/// Storage faults.
pub(super) fn erase_evaluations_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    reach: &BTreeSet<EntityId>,
) -> Result<()> {
    let mut gone = Vec::new();
    for row in EVALUATIONS.iter_raw_from(store, &*wtxn, &[])? {
        let (key, value) = row?;
        let names = |evaluation: &DrafterEvaluation| {
            let evidence = &evaluation.evidence;
            reach.contains(&evidence.version)
                || evidence
                    .incumbent
                    .version()
                    .is_some_and(|incumbent| reach.contains(&incumbent))
        };
        match (
            <EntityId as SideKey>::decode_key(&key),
            EVALUATIONS.decode_value(&value),
        ) {
            (Some(_), Ok(evaluation)) if !names(&evaluation) => {}
            _ => gone.push(key),
        }
    }
    for key in gone {
        store
            .side_vault_meta()
            .delete(wtxn, &[EVALUATIONS.decl().prefix, key.as_slice()].concat())?;
    }
    Ok(())
}

impl Vault {
    /// The host's read of what to evaluate for `version`: the version
    /// trained (`returned`), its artifact key live, the policy on and no
    /// excluded world or erased ancestor in its ancestry; the head that
    /// serves its target now and the binding's generation; the recipe's
    /// rule; and the version's held-out side, opened in this process and
    /// read as cases (never the trainer's). `None` when the version may not
    /// be evaluated now. A plan whose held-out side is gone has no cases.
    ///
    /// # Errors
    /// A damaged held-out file or key, and custody, storage and I/O faults.
    pub fn drafter_evaluation_plan(
        &self,
        version: &EntityId,
    ) -> Result<Option<DrafterEvaluationPlan>> {
        if self.vault_key_status()? == VaultKeyStatus::Locked {
            return Ok(None);
        }
        let head = {
            let txn = self.store.env.read_txn()?;
            plan_head_in_txn(&self.store, &txn, version)?
        };
        let Some(mut plan) = head else {
            return Ok(None);
        };
        if let Some(bytes) = self.drafter_held_out_corpus(version)? {
            let (cases, unreadable) = held_out_cases(&bytes);
            plan.corpus.opened = cases.len() as u64;
            plan.corpus.unreadable = unreadable;
            plan.cases = cases;
        }
        Ok(Some(plan))
    }

    /// The newest version of `target` a host should evaluate: trained
    /// (`returned`) and either never evaluated, or evaluated `unknown` for a
    /// reason a later night may not repeat (a missing or invalid rule only
    /// once the policy moved since). `None` when there is none.
    ///
    /// # Errors
    /// Storage faults.
    pub fn drafter_evaluation_candidate(&self, target: &DrafterTarget) -> Result<Option<EntityId>> {
        let store = &self.store;
        let txn = store.env.read_txn()?;
        let policy = policy_in_txn(store, &txn)?;
        let versions = versions_by_id(store, &txn)?;
        let mut newest: Option<&DrafterVersion> = None;
        for version in versions.values() {
            if version.target != *target || version.state != DrafterVersionState::Returned {
                continue;
            }
            let retry = match version.evaluation {
                None => true,
                Some(id) => match EVALUATIONS.get(store, &txn, &id)? {
                    None => true,
                    Some(evaluation) => match evaluation.evidence.decision {
                        DrafterEvaluationDecision::Unknown {
                            reason:
                                DrafterUnknownReason::NoQualificationRule
                                | DrafterUnknownReason::InvalidQualificationRule,
                        } => evaluation.evidence.policy_revision != policy.revision,
                        DrafterEvaluationDecision::Unknown { .. } => true,
                        _ => false,
                    },
                },
            };
            if retry && newest.is_none_or(|seen| version.created_at >= seen.created_at) {
                newest = Some(version);
            }
        }
        Ok(newest.map(|version| version.id))
    }

    /// The host's door to materialise `version`'s sealed load set into the
    /// new private directory `dir` (one [`Self::new_drafter_evaluation_dir`]
    /// named) for an evaluator worker: the version still at
    /// `expected_generation`, trained (`returned`, the candidate) or
    /// qualified (`qualified`, the incumbent), its key live, the policy on,
    /// no excluded world or erased ancestor, and the vault unlocked. Every
    /// file's length and BLAKE3 and the load set's digest are checked; on
    /// any failure nothing stays in `dir`.
    ///
    /// # Errors
    /// A version that may not be evaluated now, a damaged load set, and
    /// storage, custody and I/O faults.
    pub fn materialize_drafter_evaluation_load_set(
        &self,
        version: &EntityId,
        expected_generation: u64,
        dir: &Path,
    ) -> Result<DrafterMaterialized> {
        if self.vault_key_status()? == VaultKeyStatus::Locked {
            return Err(invalid("the vault is locked: no private drafter loads"));
        }
        let artifact = {
            let store = &self.store;
            let txn = store.env.read_txn()?;
            let policy = policy_in_txn(store, &txn)?;
            let versions = versions_by_id(store, &txn)?;
            let row = versions.get(version).ok_or(Error::EntityNotFound)?;
            let states = [
                DrafterVersionState::Returned,
                DrafterVersionState::Qualified,
            ];
            if row.generation != expected_generation
                || !usable_in_txn(store, &txn, &policy, &versions, row, &states)?
            {
                return Err(invalid("the drafter version may not be evaluated now"));
            }
            row.artifact
                .clone()
                .ok_or_else(|| invalid("the drafter version keeps no artifact"))?
        };
        if drafter_load_set_blake3(&artifact.files)? != artifact.load_set_blake3 {
            return Err(Error::CorruptedIndex("drafter load set"));
        }
        let sealing = self
            .drafter_artifact_sealing(version)?
            .ok_or_else(|| invalid("the drafter version's artifact key is no longer live"))?;
        if sealing.artifact() != artifact.id {
            return Err(invalid("the drafter version's artifact moved"));
        }
        self.open_drafter_load_set(&sealing, &artifact.files, dir)?;
        Ok(DrafterMaterialized {
            dir: dir.to_path_buf(),
            files: artifact.files,
            load_set_blake3: artifact.load_set_blake3,
        })
    }

    /// The host's door to record what it measured for one version. The
    /// engine decides from `evidence` and `fault`
    /// ([`DrafterEvaluationEvidence::decide`]); then, in one write, the
    /// version must still be `returned` at the generation the plan read, for
    /// the same target. A policy that moved meanwhile leaves the evaluation
    /// `unknown`. The record is written, the version points at it and moves
    /// to `qualified` (qualified), `rejected` (failed) or stays `returned`
    /// (unknown), its generation bumps, and one `qualify` event is written.
    /// `None`, with nothing written, when the version moved.
    ///
    /// # Errors
    /// Storage faults.
    pub fn record_drafter_evaluation(
        &self,
        mut evidence: DrafterEvaluationEvidence,
        fault: Option<DrafterUnknownReason>,
    ) -> Result<Option<DrafterEvaluation>> {
        evidence.decide(fault);
        let at = self.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
            let store = &self.store;
            let Some(mut version) = VERSIONS.get(store, txn, &evidence.version)? else {
                return Ok(None);
            };
            if version.state != DrafterVersionState::Returned
                || version.generation != evidence.version_generation
                || version.target != evidence.target
            {
                return Ok(None);
            }
            let policy = policy_in_txn(store, txn)?;
            if policy.revision != evidence.policy_revision || !policy.enabled {
                evidence.decide(Some(DrafterUnknownReason::PolicyMoved));
            }
            let evaluation = DrafterEvaluation {
                id: store.clock.entity_id()?,
                evidence: evidence.clone(),
                observation: None,
                evaluated_at: at,
            };
            let passed = evidence.decision == DrafterEvaluationDecision::Qualified;
            version.state = match evidence.decision {
                DrafterEvaluationDecision::Qualified => DrafterVersionState::Qualified,
                DrafterEvaluationDecision::Failed { .. } => DrafterVersionState::Rejected,
                DrafterEvaluationDecision::Unknown { .. } => DrafterVersionState::Returned,
            };
            version.evaluation = Some(evaluation.id);
            version.generation += 1;
            version.updated_at = at;
            VERSIONS.put(store, txn, &version.id, &version)?;
            EVALUATIONS.put(store, txn, &evaluation.id, &evaluation)?;
            record_event_in_txn(
                store,
                txn,
                DrafterActor::Host,
                DrafterEventKind::Qualify {
                    version: version.id,
                    passed,
                    evaluation: Some(evaluation.id),
                },
                None,
                at,
            )?;
            Ok(Some(evaluation))
        })
    }

    /// Whether `plan`'s evaluation may replay another case: `None` while it
    /// may. [`DrafterUnknownReason::VersionMoved`] once its version is
    /// erased or no longer returned at the plan's generation, or its
    /// incumbent version is erased; [`DrafterUnknownReason::PolicyMoved`]
    /// once the policy is off or excludes a world the version's or the
    /// incumbent's ancestry read. The host reads it before every case, so no
    /// erased head and no held-out case of an erased source is replayed once
    /// the erase landed.
    ///
    /// # Errors
    /// Storage faults.
    pub fn drafter_evaluation_watch(
        &self,
        plan: &DrafterEvaluationPlan,
    ) -> Result<Option<DrafterUnknownReason>> {
        let txn = self.store.env.read_txn()?;
        let versions = versions_by_id(&self.store, &txn)?;
        let Some(row) = versions.get(&plan.version) else {
            return Ok(Some(DrafterUnknownReason::VersionMoved));
        };
        if row.state != DrafterVersionState::Returned || row.generation != plan.version_generation {
            return Ok(Some(DrafterUnknownReason::VersionMoved));
        }
        let incumbent = match plan.incumbent {
            DrafterServing::Stock => None,
            DrafterServing::Version(id) => match versions.get(&id) {
                Some(found) if found.state != DrafterVersionState::Erased => Some(found),
                _ => return Ok(Some(DrafterUnknownReason::VersionMoved)),
            },
        };
        let policy = policy_in_txn(&self.store, &txn)?;
        if !policy.enabled
            || std::iter::once(row)
                .chain(incumbent)
                .any(|head| ancestry_names_world(&versions, head, &policy.excluded_worlds))
        {
            return Ok(Some(DrafterUnknownReason::PolicyMoved));
        }
        Ok(None)
    }

    /// The evaluation `id`; `None` when there is none.
    ///
    /// # Errors
    /// Storage faults.
    pub fn drafter_evaluation(&self, id: &EntityId) -> Result<Option<DrafterEvaluation>> {
        let txn = self.store.env.read_txn()?;
        EVALUATIONS.get(&self.store, &txn, id)
    }

    /// Puts evaluation `id`'s version into service on its own: it must have
    /// qualified and beaten the head that served when it was evaluated, with
    /// no measured slowdown, under the recipe's rule. In one write: the
    /// version still points at this evaluation, is `qualified`, keeps its
    /// key, and no ancestor of it is erased; the policy is on at the same
    /// revision and excludes no world in its ancestry; the binding sits at
    /// the generation the evaluation read; and no rollback stopped
    /// candidates for the target. Then the binding moves to the version by
    /// compare-and-swap on its generation, with an `activate` event, and the
    /// serving host is told after commit. A revert, an erase or a policy set
    /// that landed meanwhile wins: the activation is refused.
    ///
    /// # Errors
    /// An unknown evaluation, and storage and custody faults.
    pub fn try_activate_drafter(&self, id: &EntityId) -> Result<DrafterActivation> {
        if self.vault_key_status()? == VaultKeyStatus::Locked {
            return Ok(DrafterActivation::Refused {
                reason: DrafterActivationRefusal::VaultLocked,
            });
        }
        let outcome = self.with_write_txn_grouped(|txn| activate_in_txn(self, txn, id))?;
        if matches!(outcome, DrafterActivation::Activated { .. }) {
            self.notify_drafter_serving();
        }
        Ok(outcome)
    }

    /// Where an activation of `version` for `target` at binding generation
    /// `generation` stands: served once the serving host recorded an
    /// incarnation serving it there; moved once the binding left that
    /// generation; pending otherwise, with the serving host's view.
    ///
    /// # Errors
    /// Storage faults.
    pub fn drafter_activation_serving(
        &self,
        target: &DrafterTarget,
        generation: u64,
        version: &EntityId,
    ) -> Result<DrafterActivationServing> {
        let binding = {
            let store = &self.store;
            let txn = store.env.read_txn()?;
            let (_, binding) = binding_in_txn(store, &txn, target)?;
            if binding.generation != generation
                || binding.serving != DrafterServing::Version(*version)
            {
                return Ok(DrafterActivationServing::Moved);
            }
            for row in EVENTS.iter_raw_from(store, &txn, &[])? {
                let (_, value) = row?;
                let Ok(event) = EVENTS.decode_value(&value) else {
                    continue;
                };
                if let DrafterEventKind::Served {
                    target: served,
                    serving,
                    generation: at,
                    draft_digest,
                } = event.kind
                    && served == *target
                    && at == generation
                    && serving == DrafterServing::Version(*version)
                {
                    return Ok(DrafterActivationServing::Served { draft_digest });
                }
            }
            binding
        };
        let view = self
            .drafter_served(std::slice::from_ref(&binding))
            .into_iter()
            .find(|row| row.target == *target);
        Ok(DrafterActivationServing::Pending { view })
    }

    /// Records the host's `observation` of the incarnation that serves
    /// evaluation `id`'s activated version. A slowdown under the recipe's
    /// rule, an output violation or a worker error rolls the binding back,
    /// in the same write, to its previous clean head (stock where there is
    /// none), with a `rollback` event and its reason, and the serving host
    /// is told after commit; a binding that moved since the activation is
    /// left as it is. The observation stays on the evaluation either way,
    /// the morning report's evidence.
    ///
    /// # Errors
    /// An unknown evaluation, and storage and custody faults.
    pub fn observe_drafter_serving(
        &self,
        id: &EntityId,
        observation: DrafterObservation,
    ) -> Result<DrafterObserveOutcome> {
        let outcome =
            self.with_write_txn_grouped(|txn| observe_in_txn(self, txn, id, observation))?;
        if matches!(outcome, DrafterObserveOutcome::RolledBack { .. }) {
            self.notify_drafter_serving();
        }
        Ok(outcome)
    }
}
