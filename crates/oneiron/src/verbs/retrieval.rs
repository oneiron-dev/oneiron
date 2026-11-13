//! Owner-only, tenant-local retrieval diagnostics over the existing finalized ledger.
//! Replay returns the recorded state, ordered pack and trace; it never runs a new search.
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::store::{
    RetrievalBlendSignal, RetrievalBlendTuningConfig, RetrievalBlendWeightTableEntry,
    RetrievalBlendWeights, RetrievalEndOutcome, RetrievalOutcome, RetrievalOutcomeRecord,
    RetrievalPolicyCandidate, RetrievalPolicyEvaluation, RetrievalPolicyPin,
    RetrievalPolicyVerdict, RetrievalRunId, RetrievalRunRecord, RetrievalScoreBreakdown,
    RetrievalState, RetrievalTrace, RetrievalTurn, RetrievalWeightRow,
};

/// Default number of newest runs in an unbounded-by-caller diagnostic read.
/// This is a response default, not a retrieval or learning budget.
pub const RETRIEVAL_RUNS_DEFAULT: usize = 100;

pub use crate::retrieval_depth::RecallTelemetry;

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetrievalRunsRequest {
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetrievalRunRequest {
    pub run_id: RetrievalRunId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetrievalTurnRequest {
    pub turn_id: [u8; 16],
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetrievalTraceRequest {
    pub fork_hash: [u8; 32],
}

/// Explicit serving-run handles, never inferred from overlapping memories.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetrievalDiagnosticRequest {
    pub run_ids: Vec<RetrievalRunId>,
}

/// Outcome rows are sidecars; a missing outcome never becomes a success flag.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalRunEvidence {
    pub run: RetrievalRunRecord,
    pub outcomes: Vec<RetrievalOutcomeRecord>,
}

/// Query-free diagnostic export. Free-form outcome metadata and replay references
/// are omitted, so a caller cannot smuggle query text into the exported envelope.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalDiagnosticExport {
    pub contract_version: String,
    pub runs: Vec<RetrievalRunEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalReplayRun {
    pub source_run_id: RetrievalRunId,
    pub turn: Option<RetrievalTurn>,
    pub state: RetrievalState,
    pub result_ids: Vec<[u8; 16]>,
    pub pack: Vec<RetrievalScoreBreakdown>,
    pub trace: Option<RetrievalTrace>,
}

/// A snapshot replay of finalized records, not an execution against today's graph.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalDiagnosticReplay {
    pub contract_version: String,
    pub runs: Vec<RetrievalReplayRun>,
}

fn admitted(memory: &Memory<'_>, owner: &AuthenticatedOwner) -> MemoryResult<()> {
    if owner.revalidate(memory.vault())? != memory.actor()
        || memory.actor_class() != crate::EdgeActorClass::Human
    {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "retrieval diagnostics act as the authenticated vault owner",
            &["Present the owner's own verified, unattenuated credential."],
        ));
    }
    Ok(())
}

fn evidence(memory: &Memory<'_>, run: RetrievalRunRecord) -> MemoryResult<RetrievalRunEvidence> {
    Ok(RetrievalRunEvidence {
        outcomes: memory.vault().retrieval_outcomes(run.run_id)?,
        run,
    })
}

fn required_runs(
    memory: &Memory<'_>,
    input: RetrievalDiagnosticRequest,
) -> MemoryResult<Vec<RetrievalRunRecord>> {
    let mut seen = std::collections::HashSet::new();
    input
        .run_ids
        .into_iter()
        .map(|id| {
            if !seen.insert(id) {
                return Err(MemoryError::bad_request("duplicate retrieval run id"));
            }
            memory
                .vault()
                .retrieval_run(id)?
                .ok_or_else(|| crate::Error::EntityNotFound.into())
        })
        .collect()
}

pub fn retrieval_runs_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: RetrievalRunsRequest,
) -> MemoryResult<Vec<RetrievalRunEvidence>> {
    admitted(memory, owner)?;
    retrieval_runs(memory, input)
}

/// [`retrieval_runs_as_owner`] for the caller `memory` binds when it holds a
/// live Steward grant naming `read` (untangle 6.6c), checked at this read.
///
/// # Errors
///
/// A caller who holds no such grant; storage errors.
pub fn retrieval_runs_as_reader(
    memory: &Memory<'_>,
    input: RetrievalRunsRequest,
) -> MemoryResult<Vec<RetrievalRunEvidence>> {
    crate::federation::admit_substrate_read_by(
        memory.vault(),
        crate::WriteActor::new(memory.actor(), memory.actor_class()),
        "vault.retrieval.runs",
        crate::federation::SubstrateRead::Evidence,
    )?;
    retrieval_runs(memory, input)
}

/// `vault.retrieval.runs` on a bound handle: the embedded owner reads under
/// its own proof, any other caller as a reader.
///
/// # Errors
///
/// As [`retrieval_runs_as_owner`] and [`retrieval_runs_as_reader`].
pub fn retrieval_runs_embedded(
    memory: &Memory<'_>,
    input: RetrievalRunsRequest,
) -> MemoryResult<Vec<RetrievalRunEvidence>> {
    match memory.embedded_owner("vault.retrieval.runs") {
        Ok(owner) => retrieval_runs_as_owner(memory, &owner, input),
        Err(_) => retrieval_runs_as_reader(memory, input),
    }
}

fn retrieval_runs(
    memory: &Memory<'_>,
    input: RetrievalRunsRequest,
) -> MemoryResult<Vec<RetrievalRunEvidence>> {
    memory
        .vault()
        .retrieval_runs(input.limit.unwrap_or(RETRIEVAL_RUNS_DEFAULT))?
        .into_iter()
        .map(|run| evidence(memory, run))
        .collect()
}

pub fn retrieval_run_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: RetrievalRunRequest,
) -> MemoryResult<Option<RetrievalRunEvidence>> {
    admitted(memory, owner)?;
    memory
        .vault()
        .retrieval_run(input.run_id)?
        .map(|run| evidence(memory, run))
        .transpose()
}

pub fn retrieval_turn_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: RetrievalTurnRequest,
) -> MemoryResult<Vec<RetrievalRunEvidence>> {
    admitted(memory, owner)?;
    let run_ids = memory.vault().retrieval_runs_by_turn(&input.turn_id)?;
    required_runs(memory, RetrievalDiagnosticRequest { run_ids })?
        .into_iter()
        .map(|run| evidence(memory, run))
        .collect()
}

/// Raw caller observations remain telemetry, not gate-attributed training labels.
pub fn retrieval_outcomes_put_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: RetrievalOutcome,
) -> MemoryResult<Vec<RetrievalOutcomeRecord>> {
    admitted(memory, owner)?;
    let run_id = input.run_id;
    memory.vault().record_retrieval_outcome(input)?;
    Ok(memory.vault().retrieval_outcomes(run_id)?)
}

/// The existing end-outcome writer validates the exact run/turn links and writes
/// or retracts every contributor atomically; the door computes no reward itself.
pub fn retrieval_outcomes_end_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: RetrievalEndOutcome,
) -> MemoryResult<Vec<RetrievalRunEvidence>> {
    admitted(memory, owner)?;
    let turn_id = input.turn_id;
    memory.vault().record_retrieval_end_outcome(input)?;
    retrieval_turn_as_owner(memory, owner, RetrievalTurnRequest { turn_id })
}

pub fn retrieval_trace_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: RetrievalTraceRequest,
) -> MemoryResult<Option<RetrievalTrace>> {
    admitted(memory, owner)?;
    Ok(memory
        .vault()
        .retrieval_trace_by_fork_hash(input.fork_hash)?)
}

pub fn retrieval_export_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: RetrievalDiagnosticRequest,
) -> MemoryResult<RetrievalDiagnosticExport> {
    admitted(memory, owner)?;
    let runs = required_runs(memory, input)?
        .into_iter()
        .map(|run| {
            let mut row = evidence(memory, run)?;
            if let Some(inputs) = row.run.replay_inputs.as_mut() {
                inputs.query_ref = None;
                inputs.corpus_snapshot_ref = None;
            }
            for outcome in &mut row.outcomes {
                outcome.metadata.clear();
            }
            Ok(row)
        })
        .collect::<MemoryResult<Vec<_>>>()?;
    Ok(RetrievalDiagnosticExport {
        contract_version: "oneiron.retrieval_diagnostic_export.v1".into(),
        runs,
    })
}

pub fn retrieval_replay_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: RetrievalDiagnosticRequest,
) -> MemoryResult<RetrievalDiagnosticReplay> {
    admitted(memory, owner)?;
    let runs = required_runs(memory, input)?
        .into_iter()
        .map(|run| {
            let pack = run
                .result_ids
                .iter()
                .map(|id| {
                    run.score_breakdown
                        .iter()
                        .find(|score| &score.result_id == id)
                        .cloned()
                        .ok_or(crate::Error::CorruptedIndex("retrieval replay pack"))
                })
                .collect::<crate::Result<Vec<_>>>()?;
            Ok(RetrievalReplayRun {
                source_run_id: run.run_id,
                turn: run.turn,
                state: run.replay_state().clone(),
                result_ids: run.result_ids,
                pack,
                trace: run.trace,
            })
        })
        .collect::<MemoryResult<Vec<_>>>()?;
    Ok(RetrievalDiagnosticReplay {
        contract_version: "oneiron.retrieval_diagnostic_replay.v1".into(),
        runs,
    })
}

/// Whole-request typed recall for SDK diagnostic callers, over the ordinary serving path.
pub fn retrieval_recall_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: super::RecallRequest,
) -> MemoryResult<crate::memory::MemoryPack> {
    admitted(memory, owner)?;
    super::recall_unembedded(memory, input)
}

/// Optional tuning bounds for a policy train/evaluate/admit/update call.
/// Absent fields take the engine tuner's own defaults.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetrievalPolicyTrainRequest {
    #[serde(default)]
    pub max_runs: Option<usize>,
    #[serde(default)]
    pub learning_rate: Option<f32>,
    #[serde(default)]
    pub min_reward_count: Option<usize>,
}

impl RetrievalPolicyTrainRequest {
    fn config(&self) -> RetrievalBlendTuningConfig {
        let defaults = RetrievalBlendTuningConfig::default();
        RetrievalBlendTuningConfig {
            max_runs: self.max_runs.unwrap_or(defaults.max_runs),
            learning_rate: self.learning_rate.unwrap_or(defaults.learning_rate),
            min_reward_count: self.min_reward_count.unwrap_or(defaults.min_reward_count),
        }
    }
}

/// Candidate weights to judge on the tuner's held-out runs.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetrievalPolicyEvaluateRequest {
    pub weights: RetrievalBlendWeights,
    #[serde(default)]
    pub config: RetrievalPolicyTrainRequest,
}

/// Candidate weights plus the evidence-manifest digest they were judged on.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetrievalPolicyAdmitRequest {
    pub weights: RetrievalBlendWeights,
    pub manifest_digest: String,
    #[serde(default)]
    pub config: RetrievalPolicyTrainRequest,
}

/// Pins one blend weight at `value`, or clears its pin when `value` is
/// absent; or, with `read_shape` in place of `signal`, pins or clears the
/// read shape one model's runs work through. A request names exactly one.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetrievalPolicyPinRequest {
    #[serde(default)]
    pub signal: Option<RetrievalBlendSignal>,
    #[serde(default)]
    pub value: Option<f32>,
    #[serde(default)]
    pub read_shape: Option<ReadShapePinRequest>,
}

/// Pins `model`'s runs to `shape`, or clears the model's pin when `shape` is
/// absent. A pin beats every learned pick for that model.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadShapePinRequest {
    pub model: crate::llm::ModelId,
    #[serde(default)]
    pub shape: Option<crate::store::ReadShape>,
}

/// One model-manifest route the owner's manifest currently pins.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalRoutingPin {
    pub slot: crate::llm::manifest::ModelSlot,
    pub locality: crate::llm::ModelLocality,
}

/// One model's read-shape arms (ARCH-0051 #decision-r9-bench): the owner's
/// pin, and each shape's labelled attempts and posterior mean reward (`None`
/// while the shape has no labelled attempt).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReadShapeModelRow {
    pub model: crate::llm::ModelId,
    pub pinned: Option<crate::store::ReadShape>,
    pub verbs_pulls: u32,
    pub mount_pulls: u32,
    pub verbs_mean: Option<f64>,
    pub mount_mean: Option<f64>,
}

/// The served retrieval policy as the receipts report it: active weights and
/// their origins, owner pins, the learned posterior, routing pins, and the
/// read-shape arms per model.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalPolicyView {
    pub policy_version: u8,
    pub active: RetrievalBlendWeightTableEntry,
    pub rows: Vec<RetrievalWeightRow>,
    pub pins: Vec<RetrievalPolicyPin>,
    pub posterior_tuned_at: u64,
    pub posterior_labeled_runs: usize,
    pub posterior_observations: usize,
    pub read_shapes_tuned_at: u64,
    pub read_shapes_labeled_attempts: usize,
    pub read_shapes: Vec<ReadShapeModelRow>,
    pub routing_manifest_digest: Option<String>,
    pub routing: Vec<RetrievalRoutingPin>,
}

/// Whether a declared update was served or left as an offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalPolicyDisposition {
    Applied,
    Offered,
}

/// The outcome of one declared policy update: the trained candidate, whether
/// it now serves, and the policy as served after the call.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalPolicyUpdateReceipt {
    pub disposition: RetrievalPolicyDisposition,
    pub reason: Option<String>,
    pub candidate: RetrievalPolicyCandidate,
    pub view: RetrievalPolicyView,
}

/// An admission's receipt: the held-out judgment it passed and the policy
/// as served after it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalPolicyAdmitReceipt {
    pub evaluation: RetrievalPolicyEvaluation,
    pub view: RetrievalPolicyView,
}

fn policy_view(memory: &Memory<'_>) -> MemoryResult<RetrievalPolicyView> {
    let vault = memory.vault();
    let active = vault.retrieval_blend_weight_table()?;
    let pins = vault.retrieval_policy_pins()?;
    let posterior = vault.store.retrieval_policy_posterior()?;
    let manifest = vault.model_manifest()?;
    let (routing_manifest_digest, routing) = match &manifest {
        Some(manifest) => {
            let bytes = serde_json::to_vec(manifest)
                .map_err(|_| crate::Error::InvariantViolation("model manifest encode failed"))?;
            (
                Some(blake3::hash(&bytes).to_hex().to_string()),
                manifest
                    .routes
                    .iter()
                    .map(|(slot, locality)| RetrievalRoutingPin {
                        slot: *slot,
                        locality: *locality,
                    })
                    .collect(),
            )
        }
        None => (None, Vec::new()),
    };
    let read_shape_posterior = vault.read_shape_posterior()?;
    let read_shape_pins = vault.read_shape_pins()?;
    Ok(RetrievalPolicyView {
        policy_version: active.version,
        rows: active.weight_rows(&pins),
        active,
        pins: pins.pins,
        posterior_tuned_at: posterior.tuned_at,
        posterior_labeled_runs: posterior.labeled_runs,
        posterior_observations: posterior.observation_count(),
        read_shapes_tuned_at: read_shape_posterior.tuned_at,
        read_shapes_labeled_attempts: read_shape_posterior.labeled_attempts,
        read_shapes: read_shape_rows(&read_shape_posterior, &read_shape_pins),
        routing_manifest_digest,
        routing,
    })
}

/// One row per model the read-shape posterior or the owner's pins name,
/// sorted by model.
fn read_shape_rows(
    posterior: &crate::store::ReadShapePosterior,
    pins: &crate::store::ReadShapePins,
) -> Vec<ReadShapeModelRow> {
    let mut models: Vec<&crate::llm::ModelId> = posterior
        .arms()
        .iter()
        .map(|arm| &arm.model)
        .chain(pins.pins.iter().map(|pin| &pin.model))
        .collect();
    models.sort();
    models.dedup();
    models
        .into_iter()
        .map(|model| {
            let arm_of = |shape: crate::store::ReadShape| {
                posterior
                    .arms()
                    .iter()
                    .find(|arm| arm.model == *model && arm.shape == shape)
            };
            let (verbs, mount) = (
                arm_of(crate::store::ReadShape::Verbs),
                arm_of(crate::store::ReadShape::Mount),
            );
            ReadShapeModelRow {
                model: model.clone(),
                pinned: pins.shape_for(model),
                verbs_pulls: verbs.map_or(0, |arm| arm.pulls),
                mount_pulls: mount.map_or(0, |arm| arm.pulls),
                verbs_mean: verbs.map(crate::store::ReadShapeArm::mean),
                mount_mean: mount.map(crate::store::ReadShapeArm::mean),
            }
        })
        .collect()
}

pub fn retrieval_policy_get_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    _input: super::EmptyRequest,
) -> MemoryResult<RetrievalPolicyView> {
    admitted(memory, owner)?;
    policy_view(memory)
}

/// A pin takes effect on the served weights at once and binds every later
/// learned update; derived rewards still write no facts. A read-shape pin
/// binds every later pick for its model.
pub fn retrieval_policy_pin_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: RetrievalPolicyPinRequest,
) -> MemoryResult<RetrievalPolicyView> {
    admitted(memory, owner)?;
    match (input.signal, input.read_shape) {
        (Some(signal), None) => {
            memory
                .vault()
                .put_retrieval_policy_pin(signal, input.value)?;
        }
        (None, Some(pin)) if input.value.is_none() => {
            memory.vault().put_read_shape_pin(&pin.model, pin.shape)?;
        }
        _ => {
            return Err(crate::Error::InvalidConfig(
                "a retrieval policy pin names one blend signal with its value, or one read shape"
                    .to_owned(),
            )
            .into());
        }
    }
    policy_view(memory)
}

pub fn retrieval_policy_train_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: RetrievalPolicyTrainRequest,
) -> MemoryResult<RetrievalPolicyCandidate> {
    admitted(memory, owner)?;
    Ok(memory
        .vault()
        .train_retrieval_policy_candidate(input.config())?)
}

pub fn retrieval_policy_evaluate_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: RetrievalPolicyEvaluateRequest,
) -> MemoryResult<RetrievalPolicyEvaluation> {
    admitted(memory, owner)?;
    Ok(memory
        .vault()
        .evaluate_retrieval_policy_candidate(input.config.config(), input.weights)?)
}

pub fn retrieval_policy_admit_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: RetrievalPolicyAdmitRequest,
) -> MemoryResult<RetrievalPolicyAdmitReceipt> {
    admitted(memory, owner)?;
    let config = input.config.config();
    let evaluation = memory
        .vault()
        .evaluate_retrieval_policy_candidate(config, input.weights)?;
    memory.vault().admit_retrieval_policy_candidate(
        config,
        input.weights,
        &input.manifest_digest,
    )?;
    Ok(RetrievalPolicyAdmitReceipt {
        evaluation,
        view: policy_view(memory)?,
    })
}

/// One declared update: train on the gated outcomes, admit only a
/// not-worse candidate (anything else stays an offer), and rebuild the
/// learned action posterior from the same gated labels.
pub fn retrieval_policy_update_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: RetrievalPolicyTrainRequest,
) -> MemoryResult<RetrievalPolicyUpdateReceipt> {
    admitted(memory, owner)?;
    let config = input.config();
    let candidate = memory.vault().train_retrieval_policy_candidate(config)?;
    let (disposition, reason) = if candidate.held_out.verdict == RetrievalPolicyVerdict::NotWorse {
        match memory.vault().admit_retrieval_policy_candidate(
            config,
            candidate.weights,
            &candidate.manifest_digest,
        ) {
            Ok(_) => (RetrievalPolicyDisposition::Applied, None),
            Err(crate::Error::InvalidConfig(reason)) => {
                (RetrievalPolicyDisposition::Offered, Some(reason))
            }
            Err(error) => return Err(error.into()),
        }
    } else if candidate.held_out.verdict == RetrievalPolicyVerdict::Regression {
        (
            RetrievalPolicyDisposition::Offered,
            Some("retrieval policy candidate regressed on held-out runs".to_owned()),
        )
    } else {
        (
            RetrievalPolicyDisposition::Offered,
            Some("retrieval policy candidate lacks held-out evidence for admission".to_owned()),
        )
    };
    memory.vault().store.update_retrieval_policy_at_sleep()?;
    Ok(RetrievalPolicyUpdateReceipt {
        disposition,
        reason,
        candidate,
        view: policy_view(memory)?,
    })
}
