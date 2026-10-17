//! `vault.research.*` (OF-351): the autoresearch workflow skill's verbs over
//! the campaign record `autoreason_campaign::research` keeps on the run tree.
//!
//! ARCH-0053: "measure and decide run outside an experiment's write scope".
//! Every verb is the campaign controller's: the vault owner, or the agent
//! running the campaign's root attempt, from that try, its lease re-proved
//! here. An experiment runs as a node under the root and never passes. Ids
//! travel as hex; times are the vault's clock, never the caller's.

use serde::{Deserialize, Serialize};

use super::highway::forbidden;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::autoreason_campaign::CampaignDatasetRef;
use crate::autoreason_campaign::archive::CampaignArchivePin;
use crate::autoreason_campaign::beam_promotion::SealedRefereeMeasurement;
use crate::autoreason_campaign::general::{CampaignConfig, Measurement};
use crate::autoreason_campaign::research::{
    self, CampaignPromotionReceipt, CandidateRef, ConfirmationOutcome, ExperimentNode, ForkInput,
    ForkKind, PriorSeed, PromotionBasis, PruneReason, ResearchBindRequest, ResearchBinding,
    ResearchConfirmationSeat, ResearchReservation, ResearchTarget, SearchEvidence,
    SelectionBenchmark, SelectionReceipt, WeaveInput,
};
use crate::autoreason_campaign::selection::OracleSignal;
use crate::entity_id::EntityId;
use crate::llm::RsiSpendPurpose;
use crate::memory::{Memory, MemoryResult};
use crate::skill_optimize::{EvalRelease, SufficiencyInput};

/// `vault.research.bind`: binds a campaign to its existing root attempt.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchBindWire {
    pub root: EntityId,
    #[schemars(with = "serde_json::Value")]
    pub config: CampaignConfig,
    #[schemars(with = "serde_json::Value")]
    pub target: ResearchTarget,
    pub holder: Option<String>,
    #[schemars(with = "serde_json::Value")]
    pub confirmation: Option<ResearchConfirmationSeat>,
    pub share: Option<String>,
    /// The incumbent configuration, pinned as the root node.
    #[schemars(with = "serde_json::Value")]
    pub incumbent: CandidateRef,
    /// The cold-start ladder the root's belief seeds from.
    #[serde(default)]
    #[schemars(with = "serde_json::Value")]
    pub prior_ladder: Vec<PriorSeed>,
}

/// `vault.research.fork`: a child the workflow enqueued under `parent`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchForkWire {
    pub root: EntityId,
    pub parent: EntityId,
    pub child: EntityId,
    #[schemars(with = "serde_json::Value")]
    pub kind: ForkKind,
    #[schemars(with = "serde_json::Value")]
    pub candidate: CandidateRef,
}

/// `vault.research.weave`: a crossover child whose candidate landed as
/// `claim`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchWeaveWire {
    pub root: EntityId,
    pub parents: Vec<EntityId>,
    pub child: EntityId,
    pub common_ancestor: EntityId,
    pub validation_overlap: f64,
    #[schemars(with = "serde_json::Value")]
    pub candidate: CandidateRef,
    pub claim: EntityId,
}

/// `vault.research.measure_search`: a node's search-split evidence.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchSearchWire {
    pub root: EntityId,
    pub attempt: EntityId,
    #[schemars(with = "serde_json::Value")]
    pub evidence: SearchEvidence,
}

/// `vault.research.measure_held_out`: a node's held-out evidence, once.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchHeldOutWire {
    pub root: EntityId,
    pub attempt: EntityId,
    #[schemars(with = "serde_json::Value")]
    pub measurement: Measurement,
    pub receipt_refs: Vec<String>,
}

/// `vault.research.mark_invalid`: a buggy node, kept as evidence.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchInvalidWire {
    pub root: EntityId,
    pub attempt: EntityId,
    pub reason: String,
    pub evidence_refs: Vec<String>,
}

/// Why a branch stops. A stop names the caller, never a field.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ResearchPruneCause {
    Dominated { by: EntityId },
    FloorRegression { axis: String },
    GainBelowFloor,
    Stopped,
}

/// `vault.research.prune`: stop exploring a branch for a stated cause.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchPruneWire {
    pub root: EntityId,
    pub attempt: EntityId,
    pub cause: ResearchPruneCause,
    pub evidence_refs: Vec<String>,
}

/// `vault.research.select`: one selection round.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchSelectWire {
    pub root: EntityId,
    /// The external oracle's word that the goal is met. Only the owner
    /// gives it; a model's own success is not an oracle.
    #[serde(default)]
    pub goal_met: bool,
}

/// `vault.research.promotion_basis`: a candidate's held-out decision, once.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchBasisWire {
    pub root: EntityId,
    pub candidate: EntityId,
    #[schemars(with = "serde_json::Value")]
    pub archive: Option<CampaignArchivePin>,
}

/// `vault.research.reserve_confirmation`: a candidate's one sealed shot.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchCandidateWire {
    pub root: EntityId,
    pub candidate: EntityId,
}

/// The sealed referee's scores of candidate and incumbent on the released
/// cohort, in `[0, 1]`, under its content pin. The engine derives the win.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchRefereeScores {
    pub candidate: f64,
    pub incumbent: f64,
    pub referee_pin: String,
}

/// `vault.research.promote`: settle a candidate on its sealed confirmation.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchPromoteWire {
    pub root: EntityId,
    pub candidate: EntityId,
    pub referee: ResearchRefereeScores,
    #[schemars(with = "serde_json::Value")]
    pub sufficiency: SufficiencyInput,
    /// A skill campaign's staged revision proposal; a config campaign none.
    pub skill_proposal: Option<EntityId>,
}

/// `vault.research.reserve_work`: token work on the campaign's RSI share.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchWorkWire {
    pub root: EntityId,
    #[schemars(with = "serde_json::Value")]
    pub purpose: RsiSpendPurpose,
    pub units: u64,
    /// The node the work is for, if one.
    pub attempt: Option<EntityId>,
}

/// `vault.research.settle_work`: a reservation's actual spend.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchSettleWire {
    pub root: EntityId,
    pub reservation: EntityId,
    pub actual: u64,
}

/// `vault.research.refund_work`: an unspent reservation, returned.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchRefundWire {
    pub root: EntityId,
    pub reservation: EntityId,
}

/// `vault.research.record_benchmark`: an estimator version's held-out
/// selection benchmark against the DGM formula, once per version.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchBenchmarkWire {
    pub estimator_version: String,
    #[schemars(with = "serde_json::Value")]
    pub benchmark: CampaignDatasetRef,
    pub cases: u64,
    pub dgm_score: f64,
    pub estimator_score: f64,
    pub receipt_refs: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Caller {
    Owner,
    Controller,
}

/// The campaign controller calling for `root` (any bound campaign's, for a
/// version-wide benchmark): the vault owner, or the agent whose live leased
/// try is that root.
fn controller(memory: &Memory<'_>, root: Option<AttemptId>) -> MemoryResult<Caller> {
    let vault = memory.vault();
    {
        let txn = vault
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)?;
        if crate::memory::actor_is_vault_owner_in_txn(
            vault,
            &txn,
            memory.actor(),
            memory.actor_class(),
        )? {
            return Ok(Caller::Owner);
        }
    }
    let refused = || {
        forbidden(
            "only the campaign's controller drives its record: the owner, or the agent running its root attempt",
            "Call from the campaign's root try, or as the owner.",
        )
    };
    let binding = memory.task_host().ok_or_else(refused)?;
    let attempt = binding.parent();
    let admitted = match root {
        Some(root) => attempt == root,
        None => research::research_binding(vault, attempt)?.is_some(),
    };
    let live = AttemptQueue::new(vault)
        .get(attempt)?
        .is_some_and(|record| {
            record.state.is_running()
                && record.lease_owner.as_deref() == Some(binding.lease_owner())
                && record.attempt_count == binding.attempt_count()
        });
    if !admitted || !live {
        return Err(refused());
    }
    Ok(Caller::Controller)
}

fn attempt(id: EntityId) -> MemoryResult<AttemptId> {
    Ok(AttemptId::from_bytes(id.as_bytes())?)
}

fn now(memory: &Memory<'_>) -> u64 {
    memory.vault().store.clock.now_recorded_at()
}

/// `vault.research.bind`.
pub fn research_bind(
    memory: &Memory<'_>,
    input: ResearchBindWire,
) -> MemoryResult<ResearchBinding> {
    let root = attempt(input.root)?;
    controller(memory, Some(root))?;
    let request = ResearchBindRequest {
        root,
        config: input.config,
        target: input.target,
        holder: input.holder,
        confirmation: input.confirmation,
        share: input.share,
        incumbent: input.incumbent,
        prior_ladder: input.prior_ladder,
    };
    Ok(research::bind_research(
        memory.vault(),
        request,
        now(memory),
    )?)
}

/// `vault.research.fork`.
pub fn research_fork(memory: &Memory<'_>, input: ResearchForkWire) -> MemoryResult<ExperimentNode> {
    let root = attempt(input.root)?;
    controller(memory, Some(root))?;
    let fork = ForkInput {
        parent: attempt(input.parent)?,
        child: attempt(input.child)?,
        kind: input.kind,
        candidate: input.candidate,
    };
    Ok(research::record_fork(
        memory.vault(),
        root,
        fork,
        now(memory),
    )?)
}

/// `vault.research.weave`.
pub fn research_weave(
    memory: &Memory<'_>,
    input: ResearchWeaveWire,
) -> MemoryResult<ExperimentNode> {
    let root = attempt(input.root)?;
    controller(memory, Some(root))?;
    let weave = WeaveInput {
        parents: input
            .parents
            .into_iter()
            .map(attempt)
            .collect::<MemoryResult<_>>()?,
        child: attempt(input.child)?,
        common_ancestor: attempt(input.common_ancestor)?,
        validation_overlap: input.validation_overlap,
        candidate: input.candidate,
        claim: input.claim,
    };
    Ok(research::record_weave(
        memory.vault(),
        root,
        weave,
        now(memory),
    )?)
}

/// `vault.research.measure_search`.
pub fn research_measure_search(
    memory: &Memory<'_>,
    input: ResearchSearchWire,
) -> MemoryResult<ExperimentNode> {
    let root = attempt(input.root)?;
    controller(memory, Some(root))?;
    Ok(research::record_search_measurement(
        memory.vault(),
        root,
        attempt(input.attempt)?,
        input.evidence,
    )?)
}

/// `vault.research.measure_held_out`.
pub fn research_measure_held_out(
    memory: &Memory<'_>,
    input: ResearchHeldOutWire,
) -> MemoryResult<ExperimentNode> {
    let root = attempt(input.root)?;
    controller(memory, Some(root))?;
    Ok(research::record_held_out_measurement(
        memory.vault(),
        root,
        attempt(input.attempt)?,
        input.measurement,
        input.receipt_refs,
        now(memory),
    )?)
}

/// `vault.research.mark_invalid`.
pub fn research_mark_invalid(
    memory: &Memory<'_>,
    input: ResearchInvalidWire,
) -> MemoryResult<ExperimentNode> {
    let root = attempt(input.root)?;
    controller(memory, Some(root))?;
    Ok(research::record_invalid_experiment(
        memory.vault(),
        root,
        attempt(input.attempt)?,
        &input.reason,
        input.evidence_refs,
        now(memory),
    )?)
}

/// `vault.research.prune`. A stop names this caller.
pub fn research_prune(
    memory: &Memory<'_>,
    input: ResearchPruneWire,
) -> MemoryResult<ExperimentNode> {
    let root = attempt(input.root)?;
    controller(memory, Some(root))?;
    let reason = match input.cause {
        ResearchPruneCause::Dominated { by } => PruneReason::Dominated { by: attempt(by)? },
        ResearchPruneCause::FloorRegression { axis } => PruneReason::FloorRegression { axis },
        ResearchPruneCause::GainBelowFloor => PruneReason::GainBelowFloor,
        ResearchPruneCause::Stopped => PruneReason::Stopped { by: memory.actor() },
    };
    Ok(research::prune_branch(
        memory.vault(),
        root,
        attempt(input.attempt)?,
        reason,
        input.evidence_refs,
        now(memory),
    )?)
}

/// `vault.research.select`. Only the owner's word stops on a met goal.
pub fn research_select(
    memory: &Memory<'_>,
    input: ResearchSelectWire,
) -> MemoryResult<SelectionReceipt> {
    let root = attempt(input.root)?;
    let caller = controller(memory, Some(root))?;
    let oracle = if !input.goal_met {
        OracleSignal::NoSignal
    } else if caller == Caller::Owner {
        OracleSignal::GoalMet
    } else {
        return Err(forbidden(
            "a met goal is the external oracle's word, not the controller's",
            "Let the owner confirm the goal is met.",
        ));
    };
    Ok(research::select_next(
        memory.vault(),
        root,
        oracle,
        now(memory),
    )?)
}

/// `vault.research.promotion_basis`.
pub fn research_promotion_basis(
    memory: &Memory<'_>,
    input: ResearchBasisWire,
) -> MemoryResult<PromotionBasis> {
    let root = attempt(input.root)?;
    controller(memory, Some(root))?;
    Ok(research::promotion_basis(
        memory.vault(),
        root,
        attempt(input.candidate)?,
        input.archive,
        now(memory),
    )?)
}

/// `vault.research.reserve_confirmation`: the released cohort goes to the
/// controller's referee.
pub fn research_reserve_confirmation(
    memory: &Memory<'_>,
    input: ResearchCandidateWire,
) -> MemoryResult<EvalRelease> {
    let root = attempt(input.root)?;
    controller(memory, Some(root))?;
    Ok(research::reserve_confirmation(
        memory.vault(),
        root,
        attempt(input.candidate)?,
        now(memory),
    )?)
}

/// `vault.research.promote`: this door is the sealed referee adapter. The
/// referee's scores stay inside the sealed measurement; only its win bit
/// and digest reach the receipt.
pub fn research_promote(
    memory: &Memory<'_>,
    input: ResearchPromoteWire,
) -> MemoryResult<CampaignPromotionReceipt> {
    let root = attempt(input.root)?;
    controller(memory, Some(root))?;
    let outcome = ConfirmationOutcome {
        sealed: SealedRefereeMeasurement::from_referee_scores(
            input.referee.candidate,
            input.referee.incumbent,
            &input.referee.referee_pin,
        )?,
        sufficiency: input.sufficiency,
        skill_proposal: input.skill_proposal,
    };
    Ok(research::promote_measured(
        memory.vault(),
        root,
        attempt(input.candidate)?,
        outcome,
        now(memory),
    )?)
}

/// `vault.research.reserve_work`: the reservation's id.
pub fn research_reserve_work(
    memory: &Memory<'_>,
    input: ResearchWorkWire,
) -> MemoryResult<EntityId> {
    let root = attempt(input.root)?;
    controller(memory, Some(root))?;
    Ok(research::reserve_research_work(
        memory.vault(),
        root,
        input.purpose,
        input.units,
        input.attempt.map(attempt).transpose()?,
        now(memory),
    )?)
}

/// `vault.research.settle_work`.
pub fn research_settle_work(
    memory: &Memory<'_>,
    input: ResearchSettleWire,
) -> MemoryResult<ResearchReservation> {
    let root = attempt(input.root)?;
    controller(memory, Some(root))?;
    Ok(research::settle_research_work(
        memory.vault(),
        root,
        input.reservation,
        input.actual,
    )?)
}

/// `vault.research.refund_work`.
pub fn research_refund_work(
    memory: &Memory<'_>,
    input: ResearchRefundWire,
) -> MemoryResult<ResearchReservation> {
    let root = attempt(input.root)?;
    controller(memory, Some(root))?;
    Ok(research::refund_research_work(
        memory.vault(),
        root,
        input.reservation,
    )?)
}

/// `vault.research.record_benchmark`: recorded at the vault's clock.
pub fn research_record_benchmark(
    memory: &Memory<'_>,
    input: ResearchBenchmarkWire,
) -> MemoryResult<SelectionBenchmark> {
    controller(memory, None)?;
    Ok(research::record_selection_benchmark(
        memory.vault(),
        SelectionBenchmark {
            estimator_version: input.estimator_version,
            benchmark: input.benchmark,
            cases: input.cases,
            dgm_score: input.dgm_score,
            estimator_score: input.estimator_score,
            receipt_refs: input.receipt_refs,
            recorded_at: now(memory),
        },
    )?)
}
