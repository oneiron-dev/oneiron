use serde::{Deserialize, Serialize};

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
    Of360DerivationEnvelope, Of360MetricDefinitionSet, of360_metric_definitions,
};

use super::{
    AUTOREASON_CAMPAIGN_ID, AUTOREASON_CAMPAIGN_SCHEMA_VERSION, CampaignError,
    CampaignEvaluationSplit, CampaignResult, OF366_MIN_SAMPLE_COUNT,
    OF366_PATTERN_PREDICATE_PREFIX, OF366_UNCERTAINTY_TAU, OF366_VERDICT_EPSILON,
};

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
        validate_budget(self.budget.as_ref(), &self.tournament)?;
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
        validate_budget(self.budget.as_ref(), &self.tournament)
    }
}

pub(super) fn campaign_split_dataset_ref(
    config: &CampaignConfig,
    split: CampaignEvaluationSplit,
) -> &CampaignDatasetRef {
    match split {
        CampaignEvaluationSplit::Search => &config.splits.search,
        CampaignEvaluationSplit::HeldOut => &config.splits.held_out,
    }
}

pub(super) fn check_metric_pin(
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

fn validate_budget(
    budget: Option<&CampaignBudgetLine>,
    tournament: &CampaignTournamentConfig,
) -> CampaignResult<DreamerTournamentBudgetAxes> {
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
    let axes = DreamerTournamentBudgetAxes {
        fanout_m: tournament.fanout_m,
        depth_k: tournament.max_rounds_k,
        reserve_units_per_step: budget.reserve_units_per_step,
    };
    axes.reserve_units()
        .map_err(|_| CampaignError::InvalidConfig {
            field: "budget.reserve_units_per_step",
            reason: "tournament reservation product overflows u64",
        })?;
    Ok(axes)
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
    check_metric_pin(pin, &of360_metric_definitions()?)
}

fn is_unit_interval_f32(value: f32) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}
