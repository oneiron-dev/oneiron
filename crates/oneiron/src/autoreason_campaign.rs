//! Engine-side AR-3 autoreason campaign configuration and report join.
//!
//! The campaign compares the incumbent single-pass claim-authoring arm against
//! the tournament arm over a pinned corpus. This module is a validated serde
//! config plus a report join over two already-landed surfaces: the OF-366
//! claim-authoring admission machinery (`dreamer_runner::claim_authoring`,
//! `dreamer_tournament`) and the OF-360 AR-3 metric tier
//! (`extraction_eval::of360_ar3_metric_tier`).
//!
//! It owns no storage, mints no entity, and performs no writes. Every metric
//! number is produced by the landed OF-360 evaluator and carried verbatim;
//! every admission decision is produced by the landed OF-366 gate. The only
//! numbers this module derives are the held-out comparison scalars, and each
//! of them is recomputed from the reports rather than trusted on input, so a
//! deserialized report cannot smuggle a fabricated verdict past
//! [`CampaignComparisonReport::validate`].
//!
//! A third arm (`strong critic`) is declared but design-only: the executable
//! boundary is a separate type ([`CampaignExecutableArm`]) that has no
//! strong-critic variant, so no invocation path can select a stronger model.

use serde::{Deserialize, Deserializer, Serialize};

use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::{
    DEFAULT_DREAMER_TOURNAMENT_DEPTH_K, DEFAULT_DREAMER_TOURNAMENT_FANOUT_M,
    DreamerClaimAuthoringAdmission, DreamerTournamentAdmission, DreamerTournamentBudgetAxes,
    DreamerTournamentClaim,
};
use crate::dreamer_tournament::{
    DREAMER_TOURNAMENT_MAX_FANOUT_M, DREAMER_TOURNAMENT_MAX_ROUNDS_K,
    DREAMER_TOURNAMENT_MIN_FANOUT_M,
};
use crate::extraction_eval::{
    Of360Ar3MetricTier, Of360DerivationEnvelope, Of360EvalError, Of360ExtractionRun,
    Of360GoldDataset, Of360MetricDefinitionSet, of360_ar3_metric_tier, of360_metric_definitions,
};

/// Schema version of the campaign config and of the reports joined here.
pub const AUTOREASON_CAMPAIGN_SCHEMA_VERSION: u32 = 1;
/// Stable id of the claim-authoring autoreason campaign.
pub const AUTOREASON_CAMPAIGN_ID: &str = "autoreason-claim-authoring";
/// Predicate emitted when the campaign keeps the experiment.
pub const EXPERIMENT_VERDICT_KEEP: &str = "experiment.verdict.keep";
/// Predicate emitted when the campaign discards the experiment.
pub const EXPERIMENT_VERDICT_DISCARD: &str = "experiment.verdict.discard";

/// Incumbent-confidence threshold handed to the landed OF-366 gate.
const OF366_UNCERTAINTY_TAU: f32 = 0.5;
/// Minimum net held-out gain that still counts as a win.
const OF366_VERDICT_EPSILON: f64 = 0.05;
/// Minimum incumbent sample count admitted into the campaign corpus.
const OF366_MIN_SAMPLE_COUNT: u32 = 3;
/// Claim-predicate prefix the campaign corpus is restricted to.
const OF366_PATTERN_PREDICATE_PREFIX: &str = "pattern.";

/// Campaign-local failure modes. Deliberately module-local: nothing here
/// widens the crate error enum.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CampaignError {
    /// A config field is outside the pinned campaign shape.
    #[error("invalid campaign config field `{field}`: {reason}")]
    InvalidConfig {
        /// Offending config field.
        field: &'static str,
        /// Why the value is refused.
        reason: &'static str,
    },
    /// Two joined reports do not describe the same arm/split pair.
    #[error("campaign split report mismatch: {reason}")]
    ReportMismatch {
        /// Why the join is refused.
        reason: &'static str,
    },
    /// The evaluated metric definitions differ from the config pin.
    #[error("campaign metric pin does not match the landed OF-360 definitions")]
    MetricPinMismatch,
    /// The supplied gold anchor is not the configured held-out dataset.
    #[error("campaign held-out anchor does not match the configured held-out dataset")]
    HeldOutAnchorMismatch,
    /// A decision field does not match the value recomputed from the reports.
    #[error("invalid campaign decision field `{field}`: {reason}")]
    InvalidDecision {
        /// Offending decision field.
        field: &'static str,
        /// Why the value is refused.
        reason: &'static str,
    },
    /// The landed OF-360 evaluator refused the dataset or run.
    #[error(transparent)]
    Of360(#[from] Of360EvalError),
}

/// Result alias for campaign operations.
pub type CampaignResult<T> = std::result::Result<T, CampaignError>;

/// Every declared campaign arm, including the design-only one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignArmId {
    /// Incumbent single-pass claim authoring.
    SinglePass,
    /// OF-366 tournament claim authoring.
    Tournament,
    /// Design-only arm: same author, stronger critic. Never invoked.
    StrongCritic,
}

/// Arms the campaign can actually invoke.
///
/// The strong-critic arm has no variant here, so the compiler — not a runtime
/// check — is what stops an invocation path from selecting a stronger model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignExecutableArm {
    /// Incumbent single-pass claim authoring.
    SinglePass,
    /// OF-366 tournament claim authoring.
    Tournament,
}

impl From<CampaignExecutableArm> for CampaignArmId {
    fn from(arm: CampaignExecutableArm) -> Self {
        match arm {
            CampaignExecutableArm::SinglePass => Self::SinglePass,
            CampaignExecutableArm::Tournament => Self::Tournament,
        }
    }
}

/// Whether a declared arm is invoked or documented only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignArmExecution {
    /// The arm runs.
    Executable,
    /// The arm is declared for the record and never runs.
    DesignOnly,
}

/// Critic strength declared for an arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignCriticTier {
    /// Critic tier equals the authoring tier.
    SameAsAuthor,
    /// Stronger critic tier. Only legal on a design-only arm.
    Stronger,
}

/// One declared campaign arm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignArmConfig {
    /// Arm identity.
    pub arm: CampaignArmId,
    /// Whether the arm is invoked.
    pub execution: CampaignArmExecution,
    /// Critic strength for the arm.
    pub critic_tier: CampaignCriticTier,
}

/// Corpus restriction applied before an incumbent claim enters the campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignCorpusFilter {
    /// Claim-predicate prefix the corpus is restricted to.
    pub predicate_prefix: String,
    /// Minimum incumbent sample count.
    pub min_sample_count: u32,
}

/// Identity of one evaluation dataset revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignDatasetRef {
    /// Dataset id.
    pub dataset_id: String,
    /// Dataset revision.
    pub revision: String,
}

/// The three campaign splits.
///
/// The sealed split is pinned here so it can be reserved, never evaluated:
/// [`CampaignEvaluationSplit`] has no sealed variant and no report constructor
/// can select this ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignSplits {
    /// Split used while searching for a configuration.
    pub search: CampaignDatasetRef,
    /// Split the verdict is decided on.
    pub held_out: CampaignDatasetRef,
    /// Reserved split. Never evaluated by this module.
    pub sealed: CampaignDatasetRef,
}

/// Tournament axes handed to the landed OF-366 admission gate.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignTournamentConfig {
    /// Candidate fan-out per round.
    pub fanout_m: u16,
    /// Refinement round cap.
    pub max_rounds_k: u16,
    /// Incumbent-confidence threshold below which the tournament is admitted.
    pub uncertainty_tau: f32,
}

/// The single budget lease line the campaign reserves against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignBudgetLine {
    /// Budget line id.
    pub budget_id: String,
    /// Units reserved per tournament step.
    pub reserve_units_per_step: u64,
}

/// The OF-360 metric definitions the campaign is pinned to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignMetricPin {
    /// Metric definition set id.
    pub set_id: String,
    /// Metric definition set revision.
    pub revision: String,
    /// Derivation envelope of the pinned set, carried verbatim.
    pub derivation_envelope: Of360DerivationEnvelope,
}

/// Validated campaign configuration.
///
/// The type deserializes even when the values are wrong — `budget` stays an
/// `Option` and `default_arm` admits the design-only arm — so a bad config
/// surfaces as a typed [`CampaignError::InvalidConfig`] from [`Self::validate`]
/// rather than as a serde accident.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignConfig {
    /// Config schema version.
    pub schema_version: u32,
    /// Campaign id.
    pub campaign_id: String,
    /// Arm used when nothing escalates.
    pub default_arm: CampaignArmId,
    /// Declared arms.
    pub arms: Vec<CampaignArmConfig>,
    /// Corpus restriction.
    pub corpus: CampaignCorpusFilter,
    /// Dataset splits.
    pub splits: CampaignSplits,
    /// Tournament axes.
    pub tournament: CampaignTournamentConfig,
    /// Budget lease line.
    pub budget: Option<CampaignBudgetLine>,
    /// Pinned OF-360 metric definitions this config was built against.
    pub metric_pin: CampaignMetricPin,
    /// Minimum net held-out gain that still counts as a win.
    pub verdict_epsilon: f64,
}

impl CampaignConfig {
    /// Builds the pinned OF-366 campaign over the supplied dataset splits.
    ///
    /// The metric pin is copied from the landed OF-360 definitions, so a
    /// config can never claim a metric revision the engine does not carry.
    pub fn of366(
        search: CampaignDatasetRef,
        held_out: CampaignDatasetRef,
        sealed: CampaignDatasetRef,
        budget: CampaignBudgetLine,
    ) -> CampaignResult<Self> {
        let definitions = of360_metric_definitions()?;
        let config = Self {
            schema_version: AUTOREASON_CAMPAIGN_SCHEMA_VERSION,
            campaign_id: AUTOREASON_CAMPAIGN_ID.to_owned(),
            default_arm: CampaignArmId::SinglePass,
            arms: vec![
                CampaignArmConfig {
                    arm: CampaignArmId::SinglePass,
                    execution: CampaignArmExecution::Executable,
                    critic_tier: CampaignCriticTier::SameAsAuthor,
                },
                CampaignArmConfig {
                    arm: CampaignArmId::Tournament,
                    execution: CampaignArmExecution::Executable,
                    critic_tier: CampaignCriticTier::SameAsAuthor,
                },
                CampaignArmConfig {
                    arm: CampaignArmId::StrongCritic,
                    execution: CampaignArmExecution::DesignOnly,
                    critic_tier: CampaignCriticTier::Stronger,
                },
            ],
            corpus: CampaignCorpusFilter {
                predicate_prefix: OF366_PATTERN_PREDICATE_PREFIX.to_owned(),
                min_sample_count: OF366_MIN_SAMPLE_COUNT,
            },
            splits: CampaignSplits {
                search,
                held_out,
                sealed,
            },
            tournament: CampaignTournamentConfig {
                fanout_m: DEFAULT_DREAMER_TOURNAMENT_FANOUT_M,
                max_rounds_k: DEFAULT_DREAMER_TOURNAMENT_DEPTH_K,
                uncertainty_tau: OF366_UNCERTAINTY_TAU,
            },
            budget: Some(budget),
            metric_pin: CampaignMetricPin {
                set_id: definitions.set_id,
                revision: definitions.revision,
                derivation_envelope: definitions.derivation_envelope,
            },
            verdict_epsilon: OF366_VERDICT_EPSILON,
        };
        config.validate()?;
        Ok(config)
    }

    /// Refuses any config outside the pinned campaign shape.
    pub fn validate(&self) -> CampaignResult<()> {
        if self.schema_version != AUTOREASON_CAMPAIGN_SCHEMA_VERSION {
            return Err(CampaignError::InvalidConfig {
                field: "schema_version",
                reason: "unsupported campaign schema version",
            });
        }
        if self.campaign_id != AUTOREASON_CAMPAIGN_ID {
            return Err(CampaignError::InvalidConfig {
                field: "campaign_id",
                reason: "not the claim-authoring autoreason campaign",
            });
        }
        if self.default_arm != CampaignArmId::SinglePass {
            return Err(CampaignError::InvalidConfig {
                field: "default_arm",
                reason: "default arm must be the incumbent single-pass arm",
            });
        }
        validate_arms(&self.arms)?;
        validate_corpus(&self.corpus)?;
        validate_splits(&self.splits)?;
        validate_tournament(&self.tournament)?;
        validate_budget(self.budget.as_ref())?;
        validate_metric_pin(&self.metric_pin)?;
        if !self.verdict_epsilon.is_finite() || self.verdict_epsilon < 0.0 {
            return Err(CampaignError::InvalidConfig {
                field: "verdict_epsilon",
                reason: "must be finite and non-negative",
            });
        }
        Ok(())
    }

    /// Incumbent arm admission: the landed single-pass value, unchanged.
    #[must_use]
    pub const fn single_pass_admission(&self) -> DreamerClaimAuthoringAdmission {
        DreamerClaimAuthoringAdmission::single_pass()
    }

    /// Tournament arm admission for one incumbent claim.
    ///
    /// The class and uncertainty gates are NOT duplicated here: the returned
    /// value is handed to the landed
    /// `DreamerClaimAuthoringAdmission::gate_decision`, which owns them.
    pub fn tournament_admission(
        &self,
        claim: DreamerTournamentClaim,
    ) -> CampaignResult<DreamerClaimAuthoringAdmission> {
        let budget_axes = self.tournament_budget_axes()?;
        Ok(DreamerClaimAuthoringAdmission::Tournament(
            DreamerTournamentAdmission {
                claim,
                uncertainty_tau: self.tournament.uncertainty_tau,
                budget_axes,
            },
        ))
    }

    /// The only config-to-Dreamer budget-axis conversion in the module.
    pub fn tournament_budget_axes(&self) -> CampaignResult<DreamerTournamentBudgetAxes> {
        self.validate()?;
        let budget = self.budget.as_ref().ok_or(CampaignError::InvalidConfig {
            field: "budget",
            reason: "absent",
        })?;
        Ok(DreamerTournamentBudgetAxes {
            fanout_m: self.tournament.fanout_m,
            depth_k: self.tournament.max_rounds_k,
            reserve_units_per_step: budget.reserve_units_per_step,
        })
    }
}

/// Splits an AR-3 report may be produced for.
///
/// There is deliberately no sealed variant: the sealed split is reserved by
/// the config and unreachable from every report constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignEvaluationSplit {
    /// Configuration-search split.
    Search,
    /// Verdict-deciding split.
    HeldOut,
}

/// External gold anchor a taste judgment was scored against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignGoldAnchor {
    /// Dataset id of the anchor.
    pub dataset_id: String,
    /// Dataset revision of the anchor.
    pub revision: String,
    /// Digest of the anchored gold content.
    pub gold_digest: String,
}

/// The only payload a campaign judge is shown.
///
/// It carries no arm, strategy, round, run id, candidate ref, model tier or
/// campaign ref, and `deny_unknown_fields` keeps a caller from smuggling one
/// back in through a decoded payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct BlindCampaignJudgeInput {
    /// Claim text under judgment.
    pub claim: String,
    /// Evidence references backing the claim.
    pub evidence_refs: Vec<String>,
    /// Held-out gold anchor the judge scores against.
    pub held_out_gold: CampaignGoldAnchor,
}

/// One judge's scoring of an arm on a split.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignTasteJudgment {
    /// Quality score, finite in `[0, 1]`.
    pub score: f64,
    /// Judge's binary usefulness note; audit-only — never read by verdict or
    /// validation logic.
    pub useful: bool,
    /// Digest of the external gold anchor the judge scored against.
    pub external_anchor_digest: String,
}

/// Smoke-gate outcome for one arm on one split.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignSmokeOutcome {
    /// The arm survived the smoke gate.
    Passed,
    /// The arm was killed by the smoke gate.
    Killed {
        /// Why the arm was killed.
        reason: String,
    },
}

/// Observed cost row for one arm on one split.
///
/// The module records what the run reported and never recalculates a provider
/// price table.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignCost {
    /// Input tokens observed.
    pub input_tokens: u64,
    /// Output tokens observed.
    pub output_tokens: u64,
    /// Cache-read tokens observed.
    pub cache_read_tokens: u64,
    /// Cache-write tokens observed.
    pub cache_write_tokens: u64,
    /// Observed cost in USD.
    pub cost_usd: f64,
    /// Observed wall-clock duration.
    pub elapsed_ms: u64,
}

/// One arm evaluated on one split.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignSplitReport {
    /// Arm this report belongs to.
    pub arm: CampaignExecutableArm,
    /// Split this report belongs to.
    pub split: CampaignEvaluationSplit,
    /// Dataset ref evaluated, copied from the config split.
    pub dataset: CampaignDatasetRef,
    /// Content hash of the evaluated metric definitions, carried verbatim.
    pub metric_definition_digest: String,
    /// Raw OF-360 AR-3 metric tier, retained unmodified.
    pub of360: Of360Ar3MetricTier,
    /// Raw observed cost row, retained unmodified.
    pub cost: CampaignCost,
    /// Raw taste judgment, retained unmodified.
    pub taste: CampaignTasteJudgment,
    /// Smoke-gate outcome.
    pub smoke: CampaignSmokeOutcome,
    /// Taste score after the smoke gate: zero when killed, raw when passed.
    pub effective_taste_score: f64,
}

impl CampaignSplitReport {
    /// Refuses a report whose derived score does not follow its own inputs.
    pub fn validate(&self) -> CampaignResult<()> {
        if self.dataset.dataset_id.is_empty() || self.dataset.revision.is_empty() {
            return Err(CampaignError::ReportMismatch {
                reason: "split dataset ref is incomplete",
            });
        }
        if self.metric_definition_digest.is_empty() {
            return Err(CampaignError::ReportMismatch {
                reason: "metric definition digest is empty",
            });
        }
        if self.metric_definition_digest
            != self
                .of360
                .metric_definitions
                .derivation_envelope
                .content_hash
        {
            return Err(CampaignError::ReportMismatch {
                reason: "metric definition digest differs from the evaluated envelope",
            });
        }
        if self.of360.report.dataset_id != self.dataset.dataset_id
            || self.of360.report.dataset_revision != self.dataset.revision
        {
            return Err(CampaignError::ReportMismatch {
                reason: "evaluated dataset differs from the split dataset ref",
            });
        }
        validate_cost(&self.cost)?;
        validate_taste(&self.taste)?;
        validate_smoke(&self.smoke)?;
        if self.effective_taste_score != effective_taste_score(&self.smoke, &self.taste) {
            return Err(CampaignError::ReportMismatch {
                reason: "effective taste score does not follow the smoke outcome",
            });
        }
        Ok(())
    }
}

/// Evaluates one arm on one split through the landed OF-360 metric tier.
///
/// This is the module's only OF-360 call site.
#[expect(clippy::too_many_arguments)]
pub fn build_campaign_split_report(
    config: &CampaignConfig,
    arm: CampaignExecutableArm,
    split: CampaignEvaluationSplit,
    dataset: &Of360GoldDataset,
    run: &Of360ExtractionRun,
    cost: CampaignCost,
    taste: CampaignTasteJudgment,
    smoke: CampaignSmokeOutcome,
) -> CampaignResult<CampaignSplitReport> {
    config.validate()?;
    let dataset_ref = campaign_split_dataset_ref(config, split);
    if dataset.dataset_id != dataset_ref.dataset_id || dataset.revision != dataset_ref.revision {
        return Err(CampaignError::ReportMismatch {
            reason: "gold dataset is not the configured split",
        });
    }
    if run.dataset_id != dataset_ref.dataset_id || run.dataset_revision != dataset_ref.revision {
        return Err(CampaignError::ReportMismatch {
            reason: "extraction run is not the configured split",
        });
    }
    validate_cost(&cost)?;
    validate_taste(&taste)?;
    validate_smoke(&smoke)?;

    let of360 = of360_ar3_metric_tier(dataset, run)?;
    check_metric_pin(&config.metric_pin, &of360.metric_definitions)?;
    let metric_definition_digest = of360
        .metric_definitions
        .derivation_envelope
        .content_hash
        .clone();
    let effective = effective_taste_score(&smoke, &taste);
    let report = CampaignSplitReport {
        arm,
        split,
        dataset: dataset_ref.clone(),
        metric_definition_digest,
        of360,
        cost,
        taste,
        smoke,
        effective_taste_score: effective,
    };
    report.validate()?;
    Ok(report)
}

/// One arm evaluated on both reportable splits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignArmReport {
    /// Arm both split reports belong to.
    pub arm: CampaignExecutableArm,
    /// Search-split report.
    pub search: CampaignSplitReport,
    /// Held-out-split report.
    pub held_out: CampaignSplitReport,
}

/// Joins one arm's two split reports, revalidating both.
pub fn merge_campaign_arm_report(
    search: CampaignSplitReport,
    held_out: CampaignSplitReport,
) -> CampaignResult<CampaignArmReport> {
    search.validate()?;
    held_out.validate()?;
    if search.arm != held_out.arm {
        return Err(CampaignError::ReportMismatch {
            reason: "search and held-out reports belong to different arms",
        });
    }
    if search.split != CampaignEvaluationSplit::Search {
        return Err(CampaignError::ReportMismatch {
            reason: "search slot holds a non-search split report",
        });
    }
    if held_out.split != CampaignEvaluationSplit::HeldOut {
        return Err(CampaignError::ReportMismatch {
            reason: "held-out slot holds a non-held-out split report",
        });
    }
    if search.metric_definition_digest != held_out.metric_definition_digest {
        return Err(CampaignError::ReportMismatch {
            reason: "search and held-out reports have different metric definition digests",
        });
    }
    Ok(CampaignArmReport {
        arm: search.arm,
        search,
        held_out,
    })
}

/// Held-out comparison between the two executable arms.
///
/// Every report-derived field is recomputed from the two held-out reports and
/// never trusted on input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignHeldOutDecision {
    /// Whether the tournament arm scored above the incumbent on held-out.
    pub tournament_wins_held_out: bool,
    /// Whether the incumbent is at least as good and no more expensive.
    pub ab_dominated: bool,
    /// Tournament minus incumbent effective held-out score.
    pub quality_delta: f64,
    /// External cost penalty in quality units. Supplied, never converted here.
    pub cost_penalty: f64,
    /// External gold anchor both held-out judgments were scored against.
    pub external_anchor: CampaignGoldAnchor,
}

/// Builds the held-out decision from two validated arm reports.
///
/// `cost_penalty` is supplied external decision evidence: this module does not
/// convert USD into quality units. A self-generated anchor is caught
/// structurally — an anchor whose dataset ref is not the held-out split the
/// reports were built against fails.
pub fn build_campaign_held_out_decision(
    single_pass: &CampaignArmReport,
    tournament: &CampaignArmReport,
    cost_penalty: f64,
    external_anchor: CampaignGoldAnchor,
) -> CampaignResult<CampaignHeldOutDecision> {
    validate_arm_pairing(single_pass, tournament)?;
    if !cost_penalty.is_finite() || cost_penalty < 0.0 {
        return Err(CampaignError::InvalidDecision {
            field: "cost_penalty",
            reason: "must be finite and non-negative",
        });
    }
    check_held_out_anchor(
        &external_anchor,
        &single_pass.held_out,
        &tournament.held_out,
    )?;
    let derived = derive_held_out_fields(&single_pass.held_out, &tournament.held_out);
    Ok(CampaignHeldOutDecision {
        tournament_wins_held_out: derived.tournament_wins_held_out,
        ab_dominated: derived.ab_dominated,
        quality_delta: derived.quality_delta,
        cost_penalty,
        external_anchor,
    })
}

/// Outcome of the campaign experiment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExperimentVerdict {
    /// Keep the tournament arm.
    Keep,
    /// Discard the tournament arm.
    Discard,
}

impl ExperimentVerdict {
    /// Stable claim predicate for this verdict.
    #[must_use]
    pub const fn predicate(self) -> &'static str {
        match self {
            Self::Keep => EXPERIMENT_VERDICT_KEEP,
            Self::Discard => EXPERIMENT_VERDICT_DISCARD,
        }
    }
}

/// Why the campaign reached its verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignVerdictReason {
    /// Held-out win survived the cost penalty.
    HeldOutWinNetOfCost,
    /// An arm's held-out row was killed by the smoke gate.
    SmokeKilled,
    /// The incumbent was at least as good and no more expensive.
    AbDominated,
    /// The tournament arm did not win held-out.
    NoHeldOutWin,
    /// The net held-out gain fell below the campaign epsilon.
    QualityDeltaBelowEpsilon,
}

/// The campaign verdict with the numerics it was derived from.
///
/// `quality_delta` and `cost_penalty` are the raw numbers the ladder was
/// applied to. `net_delta` is not a third number: it is their difference, so
/// it is derived on construction and derived again on decode rather than read
/// back from the wire. A decimal encoding of an `f64` is not guaranteed to
/// decode to the bits it was encoded from, and a decoded difference that lands
/// one unit in the last place away from the difference of the decoded operands
/// would make an untouched report disagree with the ladder replayed over its
/// own numbers in [`CampaignComparisonReport::validate`].
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CampaignVerdict {
    /// Keep or discard.
    pub verdict: ExperimentVerdict,
    /// Precedence rule that decided the verdict.
    pub reason: CampaignVerdictReason,
    /// Raw held-out quality delta, carried on every reason.
    pub quality_delta: f64,
    /// Raw cost penalty, carried on every reason.
    pub cost_penalty: f64,
    /// `quality_delta - cost_penalty`, carried on every reason. Derived from
    /// the two fields above, never trusted on input.
    pub net_delta: f64,
}

impl CampaignVerdict {
    /// Assembles a verdict whose `net_delta` follows its own numerics.
    fn new(
        verdict: ExperimentVerdict,
        reason: CampaignVerdictReason,
        quality_delta: f64,
        cost_penalty: f64,
    ) -> Self {
        Self {
            verdict,
            reason,
            quality_delta,
            cost_penalty,
            net_delta: net_delta(quality_delta, cost_penalty),
        }
    }
}

/// Decoded shape of [`CampaignVerdict`].
///
/// The encoded `net_delta` is still required — the field set this module emits
/// round-trips unchanged, and an unknown field is still refused — but the
/// value is dropped in favour of the re-derived difference.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
struct CampaignVerdictWire {
    verdict: ExperimentVerdict,
    reason: CampaignVerdictReason,
    quality_delta: f64,
    cost_penalty: f64,
    net_delta: f64,
}

impl<'de> Deserialize<'de> for CampaignVerdict {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let CampaignVerdictWire {
            verdict,
            reason,
            quality_delta,
            cost_penalty,
            net_delta: _encoded_net_delta,
        } = CampaignVerdictWire::deserialize(deserializer)?;
        Ok(Self::new(verdict, reason, quality_delta, cost_penalty))
    }
}

/// Full campaign comparison, re-derivable from its own contents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignComparisonReport {
    /// Echoed from the validated config budget line for audit.
    pub campaign_ref: AttemptId,
    /// Echoed from the validated config so verdict precedence is re-derivable
    /// after serde.
    pub budget_id: String,
    /// Epsilon the verdict ladder was applied with.
    pub verdict_epsilon: f64,
    /// Metric definition digest shared by all four split reports.
    pub metric_definition_digest: String,
    /// Incumbent arm reports.
    pub single_pass: CampaignArmReport,
    /// Tournament arm reports.
    pub tournament: CampaignArmReport,
    /// Held-out decision.
    pub decision: CampaignHeldOutDecision,
    /// Verdict derived from the precedence ladder.
    pub verdict: CampaignVerdict,
}

impl CampaignComparisonReport {
    /// Re-derives everything derivable and refuses any drift.
    ///
    /// A decoded report carries its own epsilon and smoke outcomes, so the
    /// full precedence ladder is replayed here: a forged keep after a
    /// smoke-killed baseline cannot survive a round trip.
    pub fn validate(&self) -> CampaignResult<()> {
        validate_arm_pairing(&self.single_pass, &self.tournament)?;
        if self.budget_id.is_empty() {
            return Err(CampaignError::ReportMismatch {
                reason: "budget id is empty",
            });
        }
        if !self.verdict_epsilon.is_finite() || self.verdict_epsilon < 0.0 {
            return Err(CampaignError::ReportMismatch {
                reason: "verdict epsilon must be finite and non-negative",
            });
        }
        if self.metric_definition_digest.is_empty() {
            return Err(CampaignError::ReportMismatch {
                reason: "metric definition digest is empty",
            });
        }
        let splits = [
            &self.single_pass.search,
            &self.single_pass.held_out,
            &self.tournament.search,
            &self.tournament.held_out,
        ];
        for split in splits {
            if split.metric_definition_digest != self.metric_definition_digest {
                return Err(CampaignError::ReportMismatch {
                    reason: "split digest differs from the report metric definition digest",
                });
            }
        }
        check_held_out_anchor(
            &self.decision.external_anchor,
            &self.single_pass.held_out,
            &self.tournament.held_out,
        )?;
        cross_check_held_out_decision(&self.single_pass, &self.tournament, &self.decision)?;
        let verdict = campaign_verdict(
            &self.single_pass.held_out.smoke,
            &self.tournament.held_out.smoke,
            &self.decision,
            self.verdict_epsilon,
        );
        if verdict != self.verdict {
            return Err(CampaignError::InvalidDecision {
                field: "verdict",
                reason: "does not match the re-derived precedence ladder",
            });
        }
        Ok(())
    }
}

/// Assembles the campaign comparison for one run-tree root.
///
/// `campaign_ref` echoes the caller-supplied root attempt id exactly; no
/// second identity is minted here, and rootness stays a caller obligation this
/// module cannot verify.
pub fn compare_campaign(
    campaign_ref: AttemptId,
    config: &CampaignConfig,
    single_pass: CampaignArmReport,
    tournament: CampaignArmReport,
    decision: CampaignHeldOutDecision,
) -> CampaignResult<CampaignComparisonReport> {
    config.validate()?;
    let budget = config.budget.as_ref().ok_or(CampaignError::InvalidConfig {
        field: "budget",
        reason: "absent",
    })?;
    validate_arm_pairing(&single_pass, &tournament)?;
    check_config_held_out_anchor(&decision.external_anchor, &config.splits.held_out)?;
    check_held_out_anchor(
        &decision.external_anchor,
        &single_pass.held_out,
        &tournament.held_out,
    )?;
    cross_check_held_out_decision(&single_pass, &tournament, &decision)?;

    let verdict = campaign_verdict(
        &single_pass.held_out.smoke,
        &tournament.held_out.smoke,
        &decision,
        config.verdict_epsilon,
    );
    let metric_definition_digest = single_pass.held_out.metric_definition_digest.clone();
    let report = CampaignComparisonReport {
        campaign_ref,
        budget_id: budget.budget_id.clone(),
        verdict_epsilon: config.verdict_epsilon,
        metric_definition_digest,
        single_pass,
        tournament,
        decision,
        verdict,
    };
    report.validate()?;
    Ok(report)
}

/// Report-derived held-out scalars.
struct CampaignHeldOutDerivation {
    tournament_wins_held_out: bool,
    ab_dominated: bool,
    quality_delta: f64,
}

fn derive_held_out_fields(
    baseline: &CampaignSplitReport,
    contender: &CampaignSplitReport,
) -> CampaignHeldOutDerivation {
    let quality_delta = contender.effective_taste_score - baseline.effective_taste_score;
    CampaignHeldOutDerivation {
        tournament_wins_held_out: quality_delta > 0.0,
        ab_dominated: baseline.effective_taste_score >= contender.effective_taste_score
            && baseline.cost.cost_usd <= contender.cost.cost_usd,
        quality_delta,
    }
}

/// The single verdict-precedence implementation.
///
/// 1. either held-out row smoke-killed — a killed baseline invalidates the
///    experiment, so keep is unreachable even when the tournament row is live;
/// 2. incumbent dominates;
/// 3. no held-out win — search-split performance never yields keep;
/// 4. net gain below epsilon;
/// 5. otherwise keep.
///
/// Raw numerics ride along on every reason: no early branch zeroes them.
fn campaign_verdict(
    single_pass_smoke: &CampaignSmokeOutcome,
    tournament_smoke: &CampaignSmokeOutcome,
    decision: &CampaignHeldOutDecision,
    verdict_epsilon: f64,
) -> CampaignVerdict {
    let quality_delta = decision.quality_delta;
    let cost_penalty = decision.cost_penalty;
    let net_gain = net_delta(quality_delta, cost_penalty);
    let reason = if smoke_is_killed(single_pass_smoke) || smoke_is_killed(tournament_smoke) {
        CampaignVerdictReason::SmokeKilled
    } else if decision.ab_dominated {
        CampaignVerdictReason::AbDominated
    } else if !decision.tournament_wins_held_out {
        CampaignVerdictReason::NoHeldOutWin
    } else if net_gain < verdict_epsilon {
        CampaignVerdictReason::QualityDeltaBelowEpsilon
    } else {
        CampaignVerdictReason::HeldOutWinNetOfCost
    };
    let verdict = match reason {
        CampaignVerdictReason::HeldOutWinNetOfCost => ExperimentVerdict::Keep,
        CampaignVerdictReason::SmokeKilled
        | CampaignVerdictReason::AbDominated
        | CampaignVerdictReason::NoHeldOutWin
        | CampaignVerdictReason::QualityDeltaBelowEpsilon => ExperimentVerdict::Discard,
    };
    CampaignVerdict::new(verdict, reason, quality_delta, cost_penalty)
}

fn cross_check_held_out_decision(
    single_pass: &CampaignArmReport,
    tournament: &CampaignArmReport,
    decision: &CampaignHeldOutDecision,
) -> CampaignResult<()> {
    if !decision.cost_penalty.is_finite() || decision.cost_penalty < 0.0 {
        return Err(CampaignError::InvalidDecision {
            field: "cost_penalty",
            reason: "must be finite and non-negative",
        });
    }
    let derived = derive_held_out_fields(&single_pass.held_out, &tournament.held_out);
    if decision.quality_delta != derived.quality_delta {
        return Err(CampaignError::InvalidDecision {
            field: "quality_delta",
            reason: "does not match the held-out effective scores",
        });
    }
    if decision.tournament_wins_held_out != derived.tournament_wins_held_out {
        return Err(CampaignError::InvalidDecision {
            field: "tournament_wins_held_out",
            reason: "does not match the held-out effective scores",
        });
    }
    if decision.ab_dominated != derived.ab_dominated {
        return Err(CampaignError::InvalidDecision {
            field: "ab_dominated",
            reason: "does not match the held-out effective scores and costs",
        });
    }
    Ok(())
}

fn check_held_out_anchor(
    anchor: &CampaignGoldAnchor,
    baseline: &CampaignSplitReport,
    contender: &CampaignSplitReport,
) -> CampaignResult<()> {
    if anchor.gold_digest.is_empty()
        || anchor.dataset_id != baseline.dataset.dataset_id
        || anchor.revision != baseline.dataset.revision
        || anchor.dataset_id != contender.dataset.dataset_id
        || anchor.revision != contender.dataset.revision
        || anchor.gold_digest != baseline.taste.external_anchor_digest
        || anchor.gold_digest != contender.taste.external_anchor_digest
    {
        return Err(CampaignError::HeldOutAnchorMismatch);
    }
    Ok(())
}

fn check_config_held_out_anchor(
    anchor: &CampaignGoldAnchor,
    held_out: &CampaignDatasetRef,
) -> CampaignResult<()> {
    if anchor.dataset_id != held_out.dataset_id || anchor.revision != held_out.revision {
        return Err(CampaignError::HeldOutAnchorMismatch);
    }
    Ok(())
}

fn validate_arm_pairing(
    single_pass: &CampaignArmReport,
    tournament: &CampaignArmReport,
) -> CampaignResult<()> {
    validate_arm_report(single_pass, CampaignExecutableArm::SinglePass)?;
    validate_arm_report(tournament, CampaignExecutableArm::Tournament)
}

fn validate_arm_report(
    report: &CampaignArmReport,
    expected: CampaignExecutableArm,
) -> CampaignResult<()> {
    if report.arm != expected {
        return Err(CampaignError::ReportMismatch {
            reason: "arm report is filed under the wrong arm",
        });
    }
    report.search.validate()?;
    report.held_out.validate()?;
    if report.search.arm != report.arm || report.held_out.arm != report.arm {
        return Err(CampaignError::ReportMismatch {
            reason: "split report arm differs from the arm report",
        });
    }
    if report.search.split != CampaignEvaluationSplit::Search
        || report.held_out.split != CampaignEvaluationSplit::HeldOut
    {
        return Err(CampaignError::ReportMismatch {
            reason: "arm report splits are not the search/held-out pair",
        });
    }
    Ok(())
}

fn campaign_split_dataset_ref(
    config: &CampaignConfig,
    split: CampaignEvaluationSplit,
) -> &CampaignDatasetRef {
    match split {
        CampaignEvaluationSplit::Search => &config.splits.search,
        CampaignEvaluationSplit::HeldOut => &config.splits.held_out,
    }
}

fn check_metric_pin(
    pin: &CampaignMetricPin,
    definitions: &Of360MetricDefinitionSet,
) -> CampaignResult<()> {
    if pin.set_id != definitions.set_id
        || pin.revision != definitions.revision
        || pin.derivation_envelope != definitions.derivation_envelope
    {
        return Err(CampaignError::MetricPinMismatch);
    }
    Ok(())
}

/// The one definition of the net held-out gain the ladder is applied to.
fn net_delta(quality_delta: f64, cost_penalty: f64) -> f64 {
    quality_delta - cost_penalty
}

fn effective_taste_score(smoke: &CampaignSmokeOutcome, taste: &CampaignTasteJudgment) -> f64 {
    if smoke_is_killed(smoke) {
        0.0
    } else {
        taste.score
    }
}

fn smoke_is_killed(smoke: &CampaignSmokeOutcome) -> bool {
    matches!(smoke, CampaignSmokeOutcome::Killed { .. })
}

fn validate_smoke(smoke: &CampaignSmokeOutcome) -> CampaignResult<()> {
    match smoke {
        CampaignSmokeOutcome::Passed => Ok(()),
        CampaignSmokeOutcome::Killed { reason } if !reason.trim().is_empty() => Ok(()),
        CampaignSmokeOutcome::Killed { .. } => Err(CampaignError::ReportMismatch {
            reason: "smoke kill requires a non-empty reason",
        }),
    }
}

fn validate_cost(cost: &CampaignCost) -> CampaignResult<()> {
    if !cost.cost_usd.is_finite() || cost.cost_usd < 0.0 {
        return Err(CampaignError::ReportMismatch {
            reason: "observed cost must be finite and non-negative",
        });
    }
    Ok(())
}

fn validate_taste(taste: &CampaignTasteJudgment) -> CampaignResult<()> {
    if !is_unit_interval_f64(taste.score) {
        return Err(CampaignError::ReportMismatch {
            reason: "taste score must be finite in [0, 1]",
        });
    }
    if taste.external_anchor_digest.is_empty() {
        return Err(CampaignError::ReportMismatch {
            reason: "taste judgment has no external anchor digest",
        });
    }
    Ok(())
}

fn validate_arms(arms: &[CampaignArmConfig]) -> CampaignResult<()> {
    let mut single_pass = None;
    let mut tournament = None;
    let mut strong_critic = None;
    for arm in arms {
        let slot = match arm.arm {
            CampaignArmId::SinglePass => &mut single_pass,
            CampaignArmId::Tournament => &mut tournament,
            CampaignArmId::StrongCritic => &mut strong_critic,
        };
        if slot.is_some() {
            return Err(CampaignError::InvalidConfig {
                field: "arms",
                reason: "an arm is declared more than once",
            });
        }
        *slot = Some(arm);
    }
    let single_pass = single_pass.ok_or_else(missing_arm_declaration)?;
    let tournament = tournament.ok_or_else(missing_arm_declaration)?;
    let strong_critic = strong_critic.ok_or_else(missing_arm_declaration)?;
    validate_arm_shape(
        single_pass,
        CampaignArmExecution::Executable,
        CampaignCriticTier::SameAsAuthor,
    )?;
    validate_arm_shape(
        tournament,
        CampaignArmExecution::Executable,
        CampaignCriticTier::SameAsAuthor,
    )?;
    validate_arm_shape(
        strong_critic,
        CampaignArmExecution::DesignOnly,
        CampaignCriticTier::Stronger,
    )?;
    Ok(())
}

fn missing_arm_declaration() -> CampaignError {
    CampaignError::InvalidConfig {
        field: "arms",
        reason: "single-pass, tournament and strong-critic arms must all be declared",
    }
}

fn validate_arm_shape(
    arm: &CampaignArmConfig,
    execution: CampaignArmExecution,
    critic_tier: CampaignCriticTier,
) -> CampaignResult<()> {
    if arm.execution != execution {
        return Err(CampaignError::InvalidConfig {
            field: "arms",
            reason: "arm execution mode is not the one pinned for that arm",
        });
    }
    if arm.critic_tier != critic_tier {
        return Err(CampaignError::InvalidConfig {
            field: "arms",
            reason: "arm critic tier is not the one pinned for that arm",
        });
    }
    Ok(())
}

fn validate_corpus(corpus: &CampaignCorpusFilter) -> CampaignResult<()> {
    if corpus.predicate_prefix != OF366_PATTERN_PREDICATE_PREFIX {
        return Err(CampaignError::InvalidConfig {
            field: "corpus.predicate_prefix",
            reason: "campaign corpus is restricted to the pattern-claim prefix",
        });
    }
    if corpus.min_sample_count < OF366_MIN_SAMPLE_COUNT {
        return Err(CampaignError::InvalidConfig {
            field: "corpus.min_sample_count",
            reason: "below the tournament admission minimum",
        });
    }
    Ok(())
}

fn validate_splits(splits: &CampaignSplits) -> CampaignResult<()> {
    validate_dataset_ref(&splits.search, "splits.search")?;
    validate_dataset_ref(&splits.held_out, "splits.held_out")?;
    validate_dataset_ref(&splits.sealed, "splits.sealed")?;
    let refs = [&splits.search, &splits.held_out, &splits.sealed];
    for (index, left) in refs.into_iter().enumerate() {
        if refs[index + 1..].contains(&left) {
            return Err(CampaignError::InvalidConfig {
                field: "splits",
                reason: "search, held-out and sealed refs must be pairwise distinct",
            });
        }
    }
    Ok(())
}

fn validate_dataset_ref(dataset: &CampaignDatasetRef, field: &'static str) -> CampaignResult<()> {
    if dataset.dataset_id.is_empty() {
        return Err(CampaignError::InvalidConfig {
            field,
            reason: "dataset id is empty",
        });
    }
    if dataset.revision.is_empty() {
        return Err(CampaignError::InvalidConfig {
            field,
            reason: "dataset revision is empty",
        });
    }
    Ok(())
}

fn validate_tournament(tournament: &CampaignTournamentConfig) -> CampaignResult<()> {
    if !(DREAMER_TOURNAMENT_MIN_FANOUT_M..=DREAMER_TOURNAMENT_MAX_FANOUT_M)
        .contains(&tournament.fanout_m)
    {
        return Err(CampaignError::InvalidConfig {
            field: "tournament.fanout_m",
            reason: "outside the landed tournament fan-out bounds",
        });
    }
    if tournament.max_rounds_k != DREAMER_TOURNAMENT_MAX_ROUNDS_K {
        return Err(CampaignError::InvalidConfig {
            field: "tournament.max_rounds_k",
            reason: "must equal the landed tournament round cap",
        });
    }
    if !is_unit_interval_f32(tournament.uncertainty_tau) {
        return Err(CampaignError::InvalidConfig {
            field: "tournament.uncertainty_tau",
            reason: "must be finite in [0, 1]",
        });
    }
    Ok(())
}

fn validate_budget(budget: Option<&CampaignBudgetLine>) -> CampaignResult<()> {
    let Some(budget) = budget else {
        return Err(CampaignError::InvalidConfig {
            field: "budget",
            reason: "absent",
        });
    };
    if budget.budget_id.is_empty() {
        return Err(CampaignError::InvalidConfig {
            field: "budget.budget_id",
            reason: "budget id is empty",
        });
    }
    if budget.reserve_units_per_step == 0 {
        return Err(CampaignError::InvalidConfig {
            field: "budget.reserve_units_per_step",
            reason: "must be greater than zero",
        });
    }
    Ok(())
}

fn validate_metric_pin(pin: &CampaignMetricPin) -> CampaignResult<()> {
    if pin.set_id.is_empty() {
        return Err(CampaignError::InvalidConfig {
            field: "metric_pin.set_id",
            reason: "metric definition set id is empty",
        });
    }
    if pin.revision.is_empty() {
        return Err(CampaignError::InvalidConfig {
            field: "metric_pin.revision",
            reason: "metric definition set revision is empty",
        });
    }
    let envelope = &pin.derivation_envelope;
    if envelope.content_hash.is_empty()
        || envelope.model_id.is_empty()
        || envelope.version.is_empty()
        || envelope.params_hash.is_empty()
    {
        return Err(CampaignError::InvalidConfig {
            field: "metric_pin.derivation_envelope",
            reason: "derivation envelope member is empty",
        });
    }
    Ok(())
}

fn is_unit_interval_f32(value: f32) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}

fn is_unit_interval_f64(value: f64) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}

#[cfg(test)]
mod tests {
    use rmpv::Value;

    use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
    use crate::config::VaultConfig;
    use crate::critic::{
        CriticLens, CritiqueArtifact, CritiqueProvenance, CritiqueSeverity, CritiqueVerdict,
        LensCatalog,
    };
    use crate::dreamer_runner::{
        DreamerClaimAuthoringBatchTier, DreamerClaimAuthoringGateDecision,
        DreamerClaimAuthoringSchedule, DreamerClaimAuthoringSinglePassReason,
        DreamerClaimEvidenceState, DreamerRunTreeRecord,
    };
    use crate::dreamer_tournament::{
        DreamerTournamentAuthorFork, DreamerTournamentBordaBallot, DreamerTournamentBranch,
        DreamerTournamentCandidate, DreamerTournamentJudgeClaim, DreamerTournamentRound,
        DreamerTournamentRun, DreamerTournamentStopReason, DreamerTournamentSynthesisArtifact,
        run_dreamer_claim_tournament,
    };
    use crate::edge::EdgeActorClass;
    use crate::entity_id::EntityId;
    use crate::error::Result;
    use crate::extraction_eval::{
        OF360_AR3_METRIC_TIER_INTERFACE_VERSION, OF360_METRIC_DEFINITION_SET_ID,
        OF360_METRIC_DEFINITION_SET_REVISION, OF360_SCHEMA_VERSION, Of360CaseExtractionOutput,
        Of360ExtractedClaim, Of360ExtractionScore, Of360GoldMatch, Of360SeededSubsetConfig,
        generate_of360_seeded_gold_subset,
    };
    use crate::registry::ENTITY_TYPE_PERSON;
    use crate::temporal::TimeRange;
    use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};

    use super::*;

    /// One field mutation applied to a cloned decision in the fabrication tests.
    type DecisionMutation = fn(&mut CampaignHeldOutDecision);

    /// The module's own source, used by the scope/API audits below. Needles are
    /// assembled with `concat!` so the audit text cannot satisfy itself.
    const MODULE_SOURCE: &str = include_str!("autoreason_campaign.rs");
    const ARM_ID_TYPE: &str = concat!("Campaign", "ArmId");
    const EXTERNAL_ANCHOR_DIGEST: &str = "sha256:of360-held-out-external-anchor";

    struct SplitFixture {
        cost_usd: f64,
        score: f64,
        smoke: CampaignSmokeOutcome,
    }

    impl SplitFixture {
        fn passed(cost_usd: f64, score: f64) -> Self {
            Self {
                cost_usd,
                score,
                smoke: CampaignSmokeOutcome::Passed,
            }
        }

        fn killed(cost_usd: f64, score: f64, reason: &str) -> Self {
            Self {
                cost_usd,
                score,
                smoke: killed_smoke(reason),
            }
        }
    }

    struct CampaignFixture {
        config: CampaignConfig,
        single_pass: CampaignArmReport,
        tournament: CampaignArmReport,
        decision: CampaignHeldOutDecision,
    }

    fn killed_smoke(reason: &str) -> CampaignSmokeOutcome {
        CampaignSmokeOutcome::Killed {
            reason: reason.to_owned(),
        }
    }

    fn split_dataset(seed: u64) -> Of360GoldDataset {
        generate_of360_seeded_gold_subset(Of360SeededSubsetConfig {
            seed,
            max_cases: usize::MAX,
        })
        .expect("seeded gold subset")
    }

    fn dataset_ref(dataset: &Of360GoldDataset) -> CampaignDatasetRef {
        CampaignDatasetRef {
            dataset_id: dataset.dataset_id.clone(),
            revision: dataset.revision.clone(),
        }
    }

    fn budget_line() -> CampaignBudgetLine {
        CampaignBudgetLine {
            budget_id: "budget:autoreason-claim-authoring".to_owned(),
            reserve_units_per_step: 8_000,
        }
    }

    fn test_config() -> CampaignConfig {
        CampaignConfig::of366(
            dataset_ref(&split_dataset(1)),
            dataset_ref(&split_dataset(2)),
            dataset_ref(&split_dataset(3)),
            budget_line(),
        )
        .expect("of366 campaign config")
    }

    fn extraction_run(dataset: &Of360GoldDataset, run_id: &str) -> Of360ExtractionRun {
        let cases = dataset
            .cases
            .iter()
            .take(1)
            .map(|case| Of360CaseExtractionOutput {
                case_id: case.case_id.clone(),
                extracted_claims: case
                    .gold_memory_points
                    .iter()
                    .take(1)
                    .map(|memory| Of360ExtractedClaim {
                        extraction_id: format!("{}-extraction", memory.memory_id),
                        text: memory.claim.clone(),
                        matched_gold: vec![Of360GoldMatch {
                            memory_id: memory.memory_id.clone(),
                            score: Of360ExtractionScore::Full,
                        }],
                        temporal_correct: Some(true),
                        overreach: false,
                        dedup_key: None,
                    })
                    .collect(),
            })
            .collect();
        Of360ExtractionRun {
            schema_version: OF360_SCHEMA_VERSION,
            run_id: run_id.to_owned(),
            system_id: "oneiron-claim-authoring".to_owned(),
            dataset_id: dataset.dataset_id.clone(),
            dataset_revision: dataset.revision.clone(),
            cases,
        }
    }

    fn cost_row(cost_usd: f64) -> CampaignCost {
        CampaignCost {
            input_tokens: 12_000,
            output_tokens: 2_400,
            cache_read_tokens: 800,
            cache_write_tokens: 120,
            cost_usd,
            elapsed_ms: 4_200,
        }
    }

    fn taste_row(score: f64) -> CampaignTasteJudgment {
        CampaignTasteJudgment {
            score,
            useful: score > 0.5,
            external_anchor_digest: EXTERNAL_ANCHOR_DIGEST.to_owned(),
        }
    }

    fn split_report(
        config: &CampaignConfig,
        arm: CampaignExecutableArm,
        split: CampaignEvaluationSplit,
        dataset: &Of360GoldDataset,
        fixture: SplitFixture,
    ) -> CampaignSplitReport {
        let run = extraction_run(dataset, "run-autoreason-campaign-fixture");
        build_campaign_split_report(
            config,
            arm,
            split,
            dataset,
            &run,
            cost_row(fixture.cost_usd),
            taste_row(fixture.score),
            fixture.smoke,
        )
        .expect("campaign split report")
    }

    fn arm_report(
        config: &CampaignConfig,
        arm: CampaignExecutableArm,
        search: SplitFixture,
        held_out: SplitFixture,
    ) -> CampaignArmReport {
        let search_dataset = split_dataset(1);
        let held_out_dataset = split_dataset(2);
        merge_campaign_arm_report(
            split_report(
                config,
                arm,
                CampaignEvaluationSplit::Search,
                &search_dataset,
                search,
            ),
            split_report(
                config,
                arm,
                CampaignEvaluationSplit::HeldOut,
                &held_out_dataset,
                held_out,
            ),
        )
        .expect("campaign arm report")
    }

    fn held_out_anchor(config: &CampaignConfig) -> CampaignGoldAnchor {
        CampaignGoldAnchor {
            dataset_id: config.splits.held_out.dataset_id.clone(),
            revision: config.splits.held_out.revision.clone(),
            gold_digest: EXTERNAL_ANCHOR_DIGEST.to_owned(),
        }
    }

    fn campaign_fixture(
        single_pass_search: SplitFixture,
        single_pass_held_out: SplitFixture,
        tournament_search: SplitFixture,
        tournament_held_out: SplitFixture,
        cost_penalty: f64,
    ) -> CampaignFixture {
        let config = test_config();
        let single_pass = arm_report(
            &config,
            CampaignExecutableArm::SinglePass,
            single_pass_search,
            single_pass_held_out,
        );
        let tournament = arm_report(
            &config,
            CampaignExecutableArm::Tournament,
            tournament_search,
            tournament_held_out,
        );
        let decision = build_campaign_held_out_decision(
            &single_pass,
            &tournament,
            cost_penalty,
            held_out_anchor(&config),
        )
        .expect("campaign held-out decision");
        CampaignFixture {
            config,
            single_pass,
            tournament,
            decision,
        }
    }

    /// Held-out-focused fixture: both search rows are live and uninteresting.
    fn held_out_fixture(
        single_pass_held_out: SplitFixture,
        tournament_held_out: SplitFixture,
        cost_penalty: f64,
    ) -> CampaignFixture {
        campaign_fixture(
            SplitFixture::passed(0.20, 0.60),
            single_pass_held_out,
            SplitFixture::passed(0.90, 0.80),
            tournament_held_out,
            cost_penalty,
        )
    }

    fn compare(fixture: &CampaignFixture) -> CampaignComparisonReport {
        compare_campaign(
            AttemptId::now(),
            &fixture.config,
            fixture.single_pass.clone(),
            fixture.tournament.clone(),
            fixture.decision.clone(),
        )
        .expect("campaign comparison report")
    }

    fn of366_claim_authoring_lenses(catalog: &LensCatalog) -> [&CriticLens; 4] {
        [
            catalog
                .lens("groundedness", "claim_authoring")
                .expect("groundedness lens"),
            catalog
                .lens("overreach", "claim_authoring")
                .expect("overreach lens"),
            catalog
                .lens("temporal", "claim_authoring")
                .expect("temporal lens"),
            catalog
                .lens("redundancy", "claim_authoring")
                .expect("redundancy lens"),
        ]
    }

    fn tournament_candidate(
        subject: EntityId,
        candidate_ref: &str,
        claim_text: &str,
        strategy: &str,
    ) -> Result<DreamerTournamentCandidate> {
        DreamerTournamentCandidate::new(
            candidate_ref,
            AttemptId::now(),
            EntityId::now(),
            ClaimCandidate::new(
                "pattern.sleep",
                ClaimSubject::Entity(subject),
                Value::from(claim_text),
                0.8,
            )
            .with_evidence(Value::from(format!("evidence:{candidate_ref}"))),
            DreamerTournamentJudgeClaim::new(
                claim_text,
                vec!["obs:campaign:1".to_owned(), "obs:campaign:2".to_owned()],
            )?,
            strategy,
            1,
        )
    }

    fn accept_branch(
        candidate: DreamerTournamentCandidate,
        catalog: &LensCatalog,
        prefix: &str,
    ) -> Result<DreamerTournamentBranch> {
        let mut critiques = Vec::new();
        for lens in of366_claim_authoring_lenses(catalog) {
            let provenance = CritiqueProvenance::new(
                format!("critic:{}", lens.id),
                "campaign-fixture-model",
                Some("rev1".to_owned()),
            )?;
            critiques.push(CritiqueArtifact::new(
                format!("{prefix}_{}", lens.id),
                "run-autoreason-campaign",
                candidate.branch_attempt,
                candidate.candidate_ref.clone(),
                lens,
                provenance,
                CritiqueVerdict::Accept,
                CritiqueSeverity::Info,
                lens.hard_check.then_some(true),
                candidate.judge_claim.evidence_refs.clone(),
                None,
                10,
            )?);
        }
        let synthesis = DreamerTournamentSynthesisArtifact::survivor(
            format!("{prefix}_synthesis"),
            &candidate,
        )?;
        DreamerTournamentBranch::new(candidate, critiques, synthesis)
    }

    #[test]
    fn campaign_config_round_trips_and_validates() {
        let config = test_config();
        config.validate().expect("of366 config validates");

        assert_eq!(config.schema_version, AUTOREASON_CAMPAIGN_SCHEMA_VERSION);
        assert_eq!(config.campaign_id, AUTOREASON_CAMPAIGN_ID);
        assert_eq!(config.default_arm, CampaignArmId::SinglePass);
        assert_eq!(config.tournament.uncertainty_tau, OF366_UNCERTAINTY_TAU);
        assert_eq!(config.tournament.uncertainty_tau, 0.5);
        assert_eq!(config.verdict_epsilon, OF366_VERDICT_EPSILON);
        assert_eq!(config.verdict_epsilon, 0.05);
        assert_eq!(config.corpus.min_sample_count, OF366_MIN_SAMPLE_COUNT);
        assert_eq!(config.corpus.min_sample_count, 3);
        assert_eq!(config.tournament.fanout_m, 2);
        assert_eq!(config.tournament.max_rounds_k, 2);
        assert_eq!(config.corpus.predicate_prefix, "pattern.");
        assert_eq!(config.metric_pin.set_id, OF360_METRIC_DEFINITION_SET_ID);
        assert_eq!(
            config.metric_pin.revision,
            OF360_METRIC_DEFINITION_SET_REVISION
        );

        let encoded = serde_json::to_string(&config).expect("config encodes");
        let decoded: CampaignConfig = serde_json::from_str(&encoded).expect("config decodes");
        assert_eq!(decoded, config);
        decoded.validate().expect("decoded config validates");
    }

    #[test]
    fn campaign_config_rejects_missing_search_or_held_out_or_sealed_split() {
        let blank_ids: [fn(&mut CampaignSplits); 3] = [
            |splits| splits.search.dataset_id = String::new(),
            |splits| splits.held_out.dataset_id = String::new(),
            |splits| splits.sealed.dataset_id = String::new(),
        ];
        for blank in blank_ids {
            let mut config = test_config();
            blank(&mut config.splits);
            assert!(matches!(
                config.validate(),
                Err(CampaignError::InvalidConfig {
                    reason: "dataset id is empty",
                    ..
                })
            ));
        }

        let blank_revisions: [fn(&mut CampaignSplits); 3] = [
            |splits| splits.search.revision = String::new(),
            |splits| splits.held_out.revision = String::new(),
            |splits| splits.sealed.revision = String::new(),
        ];
        for blank in blank_revisions {
            let mut config = test_config();
            blank(&mut config.splits);
            assert!(matches!(
                config.validate(),
                Err(CampaignError::InvalidConfig {
                    reason: "dataset revision is empty",
                    ..
                })
            ));
        }

        let mut collided = test_config();
        collided.splits.held_out = collided.splits.search.clone();
        assert!(matches!(
            collided.validate(),
            Err(CampaignError::InvalidConfig {
                field: "splits",
                ..
            })
        ));
    }

    #[test]
    fn campaign_config_rejects_sample_count_below_three() {
        for count in 0..OF366_MIN_SAMPLE_COUNT {
            let mut config = test_config();
            config.corpus.min_sample_count = count;
            assert!(matches!(
                config.validate(),
                Err(CampaignError::InvalidConfig {
                    field: "corpus.min_sample_count",
                    ..
                })
            ));
        }

        let mut config = test_config();
        config.corpus.min_sample_count = OF366_MIN_SAMPLE_COUNT;
        config.validate().expect("minimum sample count validates");
    }

    #[test]
    fn campaign_config_rejects_invalid_fanout_or_depth() {
        for fanout in [1_u16, 4] {
            let mut config = test_config();
            config.tournament.fanout_m = fanout;
            assert!(matches!(
                config.validate(),
                Err(CampaignError::InvalidConfig {
                    field: "tournament.fanout_m",
                    ..
                })
            ));
        }

        for fanout in [2_u16, 3] {
            let mut config = test_config();
            config.tournament.fanout_m = fanout;
            config.validate().expect("landed fan-out bounds validate");
        }

        for depth in [1_u16, 3] {
            let mut config = test_config();
            config.tournament.max_rounds_k = depth;
            assert!(matches!(
                config.validate(),
                Err(CampaignError::InvalidConfig {
                    field: "tournament.max_rounds_k",
                    ..
                })
            ));
        }
    }

    #[test]
    fn campaign_config_requires_budget_line() {
        let mut absent = test_config();
        absent.budget = None;
        assert!(matches!(
            absent.validate(),
            Err(CampaignError::InvalidConfig {
                field: "budget",
                reason: "absent"
            })
        ));

        let mut empty_id = test_config();
        empty_id.budget = Some(CampaignBudgetLine {
            budget_id: String::new(),
            reserve_units_per_step: 8_000,
        });
        assert!(matches!(
            empty_id.validate(),
            Err(CampaignError::InvalidConfig {
                field: "budget.budget_id",
                ..
            })
        ));

        let mut zero_reserve = test_config();
        zero_reserve.budget = Some(CampaignBudgetLine {
            budget_id: "budget:autoreason-claim-authoring".to_owned(),
            reserve_units_per_step: 0,
        });
        assert!(matches!(
            zero_reserve.validate(),
            Err(CampaignError::InvalidConfig {
                field: "budget.reserve_units_per_step",
                ..
            })
        ));

        // A caller that drops the budget line gets a typed error, not a panic.
        let fixture = held_out_fixture(
            SplitFixture::passed(0.20, 0.60),
            SplitFixture::passed(0.90, 0.80),
            0.01,
        );
        let mut budget_less = fixture.config.clone();
        budget_less.budget = None;
        let err = compare_campaign(
            AttemptId::now(),
            &budget_less,
            fixture.single_pass.clone(),
            fixture.tournament.clone(),
            fixture.decision,
        )
        .expect_err("budget-less comparison is refused");
        assert!(matches!(
            err,
            CampaignError::InvalidConfig {
                field: "budget",
                reason: "absent"
            }
        ));
        assert!(matches!(
            budget_less.tournament_budget_axes(),
            Err(CampaignError::InvalidConfig {
                field: "budget",
                reason: "absent"
            })
        ));
    }

    #[test]
    fn strong_critic_variant_is_design_only_and_cannot_be_default() {
        let config = test_config();
        let strong = config
            .arms
            .iter()
            .find(|declared| declared.arm == CampaignArmId::StrongCritic)
            .expect("strong-critic arm is declared");
        assert_eq!(strong.execution, CampaignArmExecution::DesignOnly);
        assert_eq!(strong.critic_tier, CampaignCriticTier::Stronger);
        config
            .validate()
            .expect("a design-only strong critic validates under the single-pass default");

        let mut default_strong = test_config();
        default_strong.default_arm = CampaignArmId::StrongCritic;
        assert!(matches!(
            default_strong.validate(),
            Err(CampaignError::InvalidConfig {
                field: "default_arm",
                ..
            })
        ));

        let mut executable_strong = test_config();
        for declared in &mut executable_strong.arms {
            if declared.arm == CampaignArmId::StrongCritic {
                declared.execution = CampaignArmExecution::Executable;
            }
        }
        assert!(matches!(
            executable_strong.validate(),
            Err(CampaignError::InvalidConfig { field: "arms", .. })
        ));

        // The boundary only ever widens toward the declaration id, and the
        // design-only arm is not a decodable executable arm.
        assert_eq!(
            CampaignArmId::from(CampaignExecutableArm::SinglePass),
            CampaignArmId::SinglePass
        );
        assert_eq!(
            CampaignArmId::from(CampaignExecutableArm::Tournament),
            CampaignArmId::Tournament
        );
        assert!(serde_json::from_str::<CampaignExecutableArm>("\"strong_critic\"").is_err());

        // Source audit: no invocation entry point accepts the declaration id.
        for line in MODULE_SOURCE.lines() {
            let trimmed = line.trim_start();
            let is_parameter = trimmed.starts_with("arm: ") && !trimmed.contains("::");
            if trimmed.starts_with("pub fn ") || is_parameter {
                assert!(
                    !line.contains(ARM_ID_TYPE),
                    "invocation surface must not accept the declaration-only arm id: {line}"
                );
            }
        }
    }

    #[test]
    fn manual_single_pass_uses_landed_admission() -> Result<()> {
        let config = test_config();
        let admission = config.single_pass_admission();
        assert_eq!(admission, DreamerClaimAuthoringAdmission::single_pass());

        let decision = admission.gate_decision(DreamerClaimAuthoringBatchTier::batch())?;
        assert_eq!(
            decision,
            DreamerClaimAuthoringGateDecision::SinglePass(
                DreamerClaimAuthoringSinglePassReason::Strategy
            )
        );
        Ok(())
    }

    #[test]
    fn manual_tournament_uses_landed_gate_and_runner() -> Result<()> {
        let config = test_config();
        let admission = config
            .tournament_admission(DreamerTournamentClaim {
                predicate: "pattern.sleep".to_owned(),
                sample_count: OF366_MIN_SAMPLE_COUNT,
                incumbent_confidence: 0.30,
                evidence_state: DreamerClaimEvidenceState::Contested,
            })
            .expect("tournament admission");
        let decision = admission.gate_decision(DreamerClaimAuthoringBatchTier::batch())?;
        let DreamerClaimAuthoringGateDecision::Tournament(grant) = decision else {
            panic!("an eligible contested pattern claim must be admitted to the tournament");
        };
        let axes = config.tournament_budget_axes().expect("tournament axes");
        assert_eq!(grant.schedule, DreamerClaimAuthoringSchedule::Batch);
        assert_eq!(grant.fanout_m, config.tournament.fanout_m);
        assert_eq!(grant.depth_k, config.tournament.max_rounds_k);
        assert_eq!(grant.reserve_units, axes.reserve_units()?);

        // Both engine paths are callable end to end. No model is invoked here:
        // this proves the wiring, not that a live A/B ran.
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let actor = EntityId::now();
        let subject = EntityId::now();
        let seeded = TimeRange { start: 1, end: 1 };
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, seeded, 1, b"actor")?;
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, seeded, 1, b"subject")?;
        let envelope = WriteEnvelope::new(
            WriteActor::new(actor, EdgeActorClass::Agent),
            ClaimSource::Generated,
            WriteProvenance::new(Value::from("autoreason-campaign-fixture"))?,
            ClaimApprovalStatus::Approved,
        );
        let catalog = LensCatalog::of366_seed()?;
        let left = tournament_candidate(
            subject,
            "campaign-candidate-left",
            "Late caffeine tracks lighter sleep across the campaign corpus.",
            "seed-a",
        )?;
        let right = tournament_candidate(
            subject,
            "campaign-candidate-right",
            "An earlier caffeine cutoff tracks deeper sleep across the campaign corpus.",
            "seed-b",
        )?;
        let winner_id = right.claim_id;
        let fork = DreamerTournamentAuthorFork::new(
            "campaign-author-seed",
            AttemptId::now(),
            vec![left.branch_attempt, right.branch_attempt],
        )?;
        let run = DreamerTournamentRun::new(
            "run-autoreason-campaign",
            fork,
            config.tournament.fanout_m,
            config.tournament.max_rounds_k,
            vec![DreamerTournamentRound::new(
                vec![
                    accept_branch(left, &catalog, "campaign_left")?,
                    accept_branch(right, &catalog, "campaign_right")?,
                ],
                None,
                vec![
                    DreamerTournamentBordaBallot::new("judge-a", vec![1, 0])?,
                    DreamerTournamentBordaBallot::new("judge-b", vec![1, 0])?,
                ],
            )?],
            Vec::new(),
            envelope,
            TimeRange { start: 20, end: 20 },
            21,
        )?;

        let result = run_dreamer_claim_tournament(&vault, run)?;
        assert_eq!(result.winner.claim_id, winner_id);
        assert_eq!(result.stop_reason, DreamerTournamentStopReason::Consensus);
        assert_eq!(result.rounds_executed, 1);

        let stored = vault
            .get_claim(&winner_id)?
            .expect("winner claim is readable through the normal claim getter");
        assert_eq!(stored.predicate, "pattern.sleep");
        Ok(())
    }

    #[test]
    fn of360_and_cost_rows_merge_into_comparable_arm_report() {
        let config = test_config();
        let report = arm_report(
            &config,
            CampaignExecutableArm::Tournament,
            SplitFixture::passed(0.90, 0.80),
            SplitFixture::passed(1.10, 0.75),
        );

        assert_eq!(report.arm, CampaignExecutableArm::Tournament);
        assert_eq!(report.search.split, CampaignEvaluationSplit::Search);
        assert_eq!(report.held_out.split, CampaignEvaluationSplit::HeldOut);
        assert_eq!(report.search.dataset, config.splits.search);
        assert_eq!(report.held_out.dataset, config.splits.held_out);
        assert_eq!(
            report.search.of360.interface_version,
            OF360_AR3_METRIC_TIER_INTERFACE_VERSION
        );
        assert!(
            report
                .search
                .of360
                .report
                .metrics
                .halumem_recall
                .value
                .is_some()
        );
        assert_eq!(
            report.search.metric_definition_digest,
            report.held_out.metric_definition_digest
        );
        assert_eq!(report.held_out.cost.cost_usd, 1.10);
        assert_eq!(report.held_out.effective_taste_score, 0.75);
    }

    #[test]
    fn merge_campaign_arm_report_rejects_invalid_struct_literal_split() {
        let config = test_config();
        let search_dataset = split_dataset(1);
        let held_out_dataset = split_dataset(2);
        let search = split_report(
            &config,
            CampaignExecutableArm::SinglePass,
            CampaignEvaluationSplit::Search,
            &search_dataset,
            SplitFixture::passed(0.20, 0.60),
        );
        let base = split_report(
            &config,
            CampaignExecutableArm::SinglePass,
            CampaignEvaluationSplit::HeldOut,
            &held_out_dataset,
            SplitFixture::passed(0.25, 0.90),
        );

        // A hand-built literal: the type has no private field to hide behind,
        // so the refusal has to come from validation.
        let forged = CampaignSplitReport {
            arm: base.arm,
            split: base.split,
            dataset: base.dataset,
            metric_definition_digest: base.metric_definition_digest,
            of360: base.of360,
            cost: base.cost,
            taste: base.taste,
            smoke: killed_smoke("campaign smoke gate tripped"),
            effective_taste_score: 0.9,
        };
        let err = merge_campaign_arm_report(search, forged)
            .expect_err("a smoke-killed row with a live score is refused before assembly");
        assert!(matches!(err, CampaignError::ReportMismatch { .. }));
    }

    #[test]
    fn merge_campaign_arm_report_rejects_different_metric_definition_digests() {
        let mut report = arm_report(
            &test_config(),
            CampaignExecutableArm::SinglePass,
            SplitFixture::passed(0.20, 0.60),
            SplitFixture::passed(0.25, 0.90),
        );
        report
            .held_out
            .metric_definition_digest
            .push_str("-different");
        report
            .held_out
            .of360
            .metric_definitions
            .derivation_envelope
            .content_hash = report.held_out.metric_definition_digest.clone();

        report.search.validate().expect("valid search report");
        report.held_out.validate().expect("valid held-out report");
        assert_ne!(
            report.search.metric_definition_digest,
            report.held_out.metric_definition_digest
        );
        let err = merge_campaign_arm_report(report.search, report.held_out)
            .expect_err("individually valid reports with different metric digests cannot merge");
        assert!(matches!(
            err,
            CampaignError::ReportMismatch {
                reason: "search and held-out reports have different metric definition digests",
            }
        ));
    }

    #[test]
    fn metric_definition_digest_is_carried_and_must_match() {
        let config = test_config();
        let dataset = split_dataset(1);
        let run = extraction_run(&dataset, "run-metric-digest");
        let report = build_campaign_split_report(
            &config,
            CampaignExecutableArm::SinglePass,
            CampaignEvaluationSplit::Search,
            &dataset,
            &run,
            cost_row(0.20),
            taste_row(0.60),
            CampaignSmokeOutcome::Passed,
        )
        .expect("campaign split report");

        assert_eq!(
            report.metric_definition_digest,
            config.metric_pin.derivation_envelope.content_hash
        );
        assert_eq!(
            report.metric_definition_digest,
            report
                .of360
                .metric_definitions
                .derivation_envelope
                .content_hash
        );

        let mut mutated = test_config();
        mutated.metric_pin.derivation_envelope.content_hash =
            "sha256:not-the-landed-envelope".to_owned();
        let err = build_campaign_split_report(
            &mutated,
            CampaignExecutableArm::SinglePass,
            CampaignEvaluationSplit::Search,
            &dataset,
            &run,
            cost_row(0.20),
            taste_row(0.60),
            CampaignSmokeOutcome::Passed,
        )
        .expect_err("a mutated metric pin is refused");
        assert!(matches!(err, CampaignError::MetricPinMismatch));
    }

    #[test]
    fn campaign_ref_is_exact_run_tree_root() {
        let fixture = held_out_fixture(
            SplitFixture::passed(0.20, 0.60),
            SplitFixture::passed(0.90, 0.80),
            0.01,
        );
        // Rootness is the caller's contract; this module echoes the id it is
        // handed and mints no second identity.
        let root = DreamerRunTreeRecord {
            attempt_id: AttemptId::now(),
            parent_attempt: None,
            created_at: 42,
        };
        assert!(root.parent_attempt.is_none());

        let report = compare_campaign(
            root.attempt_id,
            &fixture.config,
            fixture.single_pass.clone(),
            fixture.tournament.clone(),
            fixture.decision.clone(),
        )
        .expect("campaign comparison report");
        assert_eq!(report.campaign_ref, root.attempt_id);
        assert_eq!(report.budget_id, "budget:autoreason-claim-authoring");

        let encoded = serde_json::to_string(&report).expect("report encodes");
        let decoded: CampaignComparisonReport =
            serde_json::from_str(&encoded).expect("report decodes");
        assert_eq!(decoded.campaign_ref, root.attempt_id);
        decoded.validate().expect("decoded report validates");
    }

    #[test]
    fn sealed_split_has_no_ar3_report_variant() {
        // Exhaustive: the reportable split set is exactly search/held-out.
        for split in [
            CampaignEvaluationSplit::Search,
            CampaignEvaluationSplit::HeldOut,
        ] {
            let encoded = match split {
                CampaignEvaluationSplit::Search => "search",
                CampaignEvaluationSplit::HeldOut => "held_out",
            };
            assert_eq!(
                serde_json::to_value(split).expect("split encodes"),
                serde_json::Value::from(encoded)
            );
        }
        assert!(serde_json::from_str::<CampaignEvaluationSplit>("\"sealed\"").is_err());

        // The sealed ref is pinned by the config and reachable from no report
        // constructor.
        let config = test_config();
        assert_ne!(config.splits.sealed, config.splits.held_out);
        assert_ne!(config.splits.sealed, config.splits.search);
        assert!(!MODULE_SOURCE.contains(concat!("Evaluation", "Split::Sealed")));
    }

    #[test]
    fn held_out_tournament_win_net_of_cost_keeps() {
        let fixture = held_out_fixture(
            SplitFixture::passed(0.20, 0.60),
            SplitFixture::passed(0.90, 0.80),
            0.05,
        );
        assert!(fixture.decision.tournament_wins_held_out);
        assert!(!fixture.decision.ab_dominated);

        let report = compare(&fixture);
        assert_eq!(report.verdict.verdict, ExperimentVerdict::Keep);
        assert_eq!(
            report.verdict.reason,
            CampaignVerdictReason::HeldOutWinNetOfCost
        );
        assert_eq!(report.verdict.verdict.predicate(), EXPERIMENT_VERDICT_KEEP);
        assert_eq!(
            report.verdict.verdict.predicate(),
            "experiment.verdict.keep"
        );
        assert!(report.verdict.net_delta >= report.verdict_epsilon);
    }

    #[test]
    fn ab_domination_discards() {
        let fixture = held_out_fixture(
            SplitFixture::passed(0.20, 0.75),
            SplitFixture::passed(0.90, 0.75),
            0.0,
        );
        assert_eq!(fixture.decision.quality_delta, 0.0);
        assert!(fixture.decision.ab_dominated);

        let report = compare(&fixture);
        assert_eq!(report.verdict.verdict, ExperimentVerdict::Discard);
        assert_eq!(report.verdict.reason, CampaignVerdictReason::AbDominated);
        assert_ne!(report.verdict.reason, CampaignVerdictReason::NoHeldOutWin);
        assert_eq!(
            report.verdict.verdict.predicate(),
            EXPERIMENT_VERDICT_DISCARD
        );
    }

    #[test]
    fn sub_epsilon_net_gain_discards() {
        let fixture = held_out_fixture(
            SplitFixture::passed(0.20, 0.60),
            SplitFixture::passed(0.90, 0.62),
            0.0,
        );
        assert!(fixture.decision.tournament_wins_held_out);
        assert!(!fixture.decision.ab_dominated);

        let report = compare(&fixture);
        assert!(report.verdict.net_delta < report.verdict_epsilon);
        assert_eq!(report.verdict.verdict, ExperimentVerdict::Discard);
        assert_eq!(
            report.verdict.reason,
            CampaignVerdictReason::QualityDeltaBelowEpsilon
        );
    }

    #[test]
    fn no_held_out_win_discards_even_if_search_wins() {
        // The tournament arm wins the search split by a wide margin and still
        // loses: only the held-out split can yield a keep.
        let fixture = campaign_fixture(
            SplitFixture::passed(0.20, 0.60),
            SplitFixture::passed(1.50, 0.80),
            SplitFixture::passed(0.90, 0.95),
            SplitFixture::passed(0.20, 0.70),
            0.0,
        );
        assert!(
            fixture.tournament.search.effective_taste_score
                > fixture.single_pass.search.effective_taste_score
        );
        assert!(!fixture.decision.tournament_wins_held_out);
        assert!(!fixture.decision.ab_dominated);

        let report = compare(&fixture);
        assert_eq!(report.verdict.verdict, ExperimentVerdict::Discard);
        assert_eq!(report.verdict.reason, CampaignVerdictReason::NoHeldOutWin);
    }

    #[test]
    fn smoke_kill_zeroes_score_and_discards() {
        let fixture = held_out_fixture(
            SplitFixture::passed(0.20, 0.60),
            SplitFixture::killed(0.90, 0.95, "tournament smoke gate tripped"),
            0.02,
        );

        // Raw metric and cost rows survive the kill; only the effective score
        // is zeroed.
        let held_out = &fixture.tournament.held_out;
        assert_eq!(held_out.effective_taste_score, 0.0);
        assert_eq!(held_out.taste.score, 0.95);
        assert_eq!(held_out.cost.cost_usd, 0.90);
        assert!(held_out.of360.report.metrics.halumem_recall.value.is_some());

        let report = compare(&fixture);
        assert_eq!(report.verdict.verdict, ExperimentVerdict::Discard);
        assert_eq!(report.verdict.reason, CampaignVerdictReason::SmokeKilled);
        assert_eq!(report.verdict.quality_delta, fixture.decision.quality_delta);
        assert_eq!(report.verdict.cost_penalty, 0.02);
        assert_eq!(
            report.verdict.net_delta,
            fixture.decision.quality_delta - 0.02
        );
        assert!(report.verdict.quality_delta < 0.0);
    }

    #[test]
    fn smoke_killed_baseline_cannot_yield_keep() {
        let fixture = held_out_fixture(
            SplitFixture::killed(0.20, 0.80, "single-pass smoke gate tripped"),
            SplitFixture::passed(0.90, 0.70),
            0.01,
        );
        // Every later rung would have kept: the killed baseline still wins.
        assert!(fixture.decision.tournament_wins_held_out);
        assert!(!fixture.decision.ab_dominated);
        assert!(fixture.decision.quality_delta - fixture.decision.cost_penalty > 0.05);

        let report = compare(&fixture);
        assert_eq!(report.verdict.verdict, ExperimentVerdict::Discard);
        assert_eq!(report.verdict.reason, CampaignVerdictReason::SmokeKilled);
    }

    #[test]
    fn deserialized_forged_keep_after_smoke_kill_is_rejected() {
        let fixture = held_out_fixture(
            SplitFixture::killed(0.20, 0.80, "single-pass smoke gate tripped"),
            SplitFixture::passed(0.90, 0.70),
            0.01,
        );
        let report = compare(&fixture);
        assert_eq!(report.verdict.reason, CampaignVerdictReason::SmokeKilled);

        // Only the verdict pair is forged: every numeric still matches, so the
        // rejection can only come from replaying the precedence ladder.
        let mut json = serde_json::to_value(&report).expect("report encodes");
        *json.pointer_mut("/verdict/verdict").expect("verdict node") =
            serde_json::Value::from("keep");
        *json.pointer_mut("/verdict/reason").expect("reason node") =
            serde_json::Value::from("held_out_win_net_of_cost");
        let forged: CampaignComparisonReport =
            serde_json::from_value(json).expect("forged report decodes");
        assert_eq!(forged.verdict.verdict, ExperimentVerdict::Keep);
        assert_eq!(forged.verdict.quality_delta, report.verdict.quality_delta);
        assert_eq!(forged.verdict.net_delta, report.verdict.net_delta);

        let err = forged
            .validate()
            .expect_err("a forged keep after a smoke-killed baseline is refused");
        assert!(matches!(
            err,
            CampaignError::InvalidDecision {
                field: "verdict",
                ..
            }
        ));
    }

    #[test]
    fn live_split_effective_score_equals_taste_score() {
        let config = test_config();
        let dataset = split_dataset(2);
        let passed = split_report(
            &config,
            CampaignExecutableArm::SinglePass,
            CampaignEvaluationSplit::HeldOut,
            &dataset,
            SplitFixture::passed(0.30, 0.72),
        );
        assert_eq!(passed.effective_taste_score, passed.taste.score);
        assert_eq!(passed.effective_taste_score, 0.72);

        let mut json = serde_json::to_value(&passed).expect("report encodes");
        *json
            .pointer_mut("/effective_taste_score")
            .expect("score node") = serde_json::Value::from(0.10);
        let decoded: CampaignSplitReport = serde_json::from_value(json).expect("report decodes");
        assert!(matches!(
            decoded.validate(),
            Err(CampaignError::ReportMismatch { .. })
        ));

        let stopped = split_report(
            &config,
            CampaignExecutableArm::SinglePass,
            CampaignEvaluationSplit::HeldOut,
            &dataset,
            SplitFixture::killed(0.30, 0.72, "smoke gate tripped"),
        );
        assert_eq!(stopped.effective_taste_score, 0.0);

        let mut json = serde_json::to_value(&stopped).expect("report encodes");
        *json
            .pointer_mut("/effective_taste_score")
            .expect("score node") = serde_json::Value::from(0.72);
        let decoded: CampaignSplitReport = serde_json::from_value(json).expect("report decodes");
        assert!(matches!(
            decoded.validate(),
            Err(CampaignError::ReportMismatch { .. })
        ));
    }

    #[test]
    fn fabricated_held_out_win_is_rejected() {
        let fixture = held_out_fixture(
            SplitFixture::passed(0.20, 0.80),
            SplitFixture::passed(0.90, 0.60),
            0.01,
        );
        assert!(!fixture.decision.tournament_wins_held_out);
        assert!(fixture.decision.ab_dominated);

        let fabrications: [(&str, DecisionMutation); 3] = [
            ("tournament_wins_held_out", |decision| {
                decision.tournament_wins_held_out = true;
            }),
            ("quality_delta", |decision| {
                decision.quality_delta = 0.5;
            }),
            ("ab_dominated", |decision| {
                decision.ab_dominated = !decision.ab_dominated;
            }),
        ];
        for (field, fabricate) in fabrications {
            let mut decision = fixture.decision.clone();
            fabricate(&mut decision);
            let err = compare_campaign(
                AttemptId::now(),
                &fixture.config,
                fixture.single_pass.clone(),
                fixture.tournament.clone(),
                decision,
            )
            .expect_err("a fabricated decision field is refused");
            match err {
                CampaignError::InvalidDecision { field: actual, .. } => {
                    assert_eq!(actual, field);
                }
                other => panic!("expected an invalid decision field, got {other:?}"),
            }
        }
    }

    #[test]
    fn blind_judge_payload_rejects_strategy_and_round_identity() {
        let config = test_config();
        let payload = BlindCampaignJudgeInput {
            claim: "Late caffeine tracks lighter sleep.".to_owned(),
            evidence_refs: vec!["obs:campaign:1".to_owned()],
            held_out_gold: held_out_anchor(&config),
        };

        let value = serde_json::to_value(&payload).expect("payload encodes");
        let object = value.as_object().expect("payload is an object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["claim", "evidence_refs", "held_out_gold"]);

        for leak in [
            "strategy",
            "round",
            "run_id",
            "arm",
            "candidate_ref",
            "model_tier",
            "campaign_ref",
        ] {
            let mut leaked = object.clone();
            leaked.insert(leak.to_owned(), serde_json::Value::from("leaked"));
            let decoded = serde_json::from_value::<BlindCampaignJudgeInput>(
                serde_json::Value::Object(leaked),
            );
            assert!(
                decoded.is_err(),
                "the judge payload must refuse a `{leak}` field"
            );
        }
    }

    #[test]
    fn held_out_anchor_must_match_external_gold() {
        let fixture = held_out_fixture(
            SplitFixture::passed(0.20, 0.60),
            SplitFixture::passed(0.90, 0.80),
            0.01,
        );
        let anchors = [
            CampaignGoldAnchor {
                dataset_id: fixture.config.splits.search.dataset_id.clone(),
                revision: fixture.config.splits.search.revision.clone(),
                gold_digest: EXTERNAL_ANCHOR_DIGEST.to_owned(),
            },
            CampaignGoldAnchor {
                dataset_id: "caller-invented-dataset".to_owned(),
                revision: "caller-invented-revision".to_owned(),
                gold_digest: EXTERNAL_ANCHOR_DIGEST.to_owned(),
            },
            CampaignGoldAnchor {
                gold_digest: "sha256:self-generated-anchor".to_owned(),
                ..held_out_anchor(&fixture.config)
            },
        ];

        for anchor in anchors {
            let err = build_campaign_held_out_decision(
                &fixture.single_pass,
                &fixture.tournament,
                0.01,
                anchor.clone(),
            )
            .expect_err("the decision builder refuses a foreign anchor");
            assert!(matches!(err, CampaignError::HeldOutAnchorMismatch));

            let mut decision = fixture.decision.clone();
            decision.external_anchor = anchor;
            let err = compare_campaign(
                AttemptId::now(),
                &fixture.config,
                fixture.single_pass.clone(),
                fixture.tournament.clone(),
                decision,
            )
            .expect_err("the comparison builder refuses a foreign anchor");
            assert!(matches!(err, CampaignError::HeldOutAnchorMismatch));
        }
    }

    #[test]
    fn campaign_scope_guards_exclude_unrelated_symbols() {
        assert!(!MODULE_SOURCE.contains(concat!("Companion", "Mem")));
        assert!(!MODULE_SOURCE.contains(concat!("oneiron", "_bench")));
        assert!(!MODULE_SOURCE.contains(concat!("interface", "_bench")));
        assert!(!MODULE_SOURCE.contains(concat!("Evaluation", "Split::Sealed")));
    }
}
