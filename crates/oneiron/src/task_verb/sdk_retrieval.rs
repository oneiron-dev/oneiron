//! Owner-only, tenant-local retrieval diagnostics over the existing finalized ledger.
//! Replay returns the recorded state, ordered pack and trace; it never runs a new search.
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::store::{
    RetrievalEndOutcome, RetrievalOutcome, RetrievalOutcomeRecord, RetrievalRunId,
    RetrievalRunRecord, RetrievalScoreBreakdown, RetrievalState, RetrievalTrace, RetrievalTurn,
};

/// Default number of newest runs in an unbounded-by-caller diagnostic read.
/// This is a response default, not a retrieval or learning budget.
pub const RETRIEVAL_RUNS_DEFAULT: usize = 100;

/// Opt-in stage capture and the actual host turn whose retrieval is being observed.
/// The vault's capture setting remains authoritative; this cannot turn it on.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecallTelemetry {
    #[serde(default)]
    pub capture_trace: bool,
    #[serde(default)]
    pub turn: Option<RetrievalTurn>,
}

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
    input.run_ids.into_iter().map(|id| {
        if !seen.insert(id) {
            return Err(MemoryError::bad_request("duplicate retrieval run id"));
        }
        memory.vault().retrieval_run(id)?
            .ok_or_else(|| crate::Error::EntityNotFound.into())
    }).collect()
}

pub fn retrieval_runs_as_owner(
    memory: &Memory<'_>, owner: &AuthenticatedOwner, input: RetrievalRunsRequest,
) -> MemoryResult<Vec<RetrievalRunEvidence>> {
    admitted(memory, owner)?;
    memory.vault().retrieval_runs(input.limit.unwrap_or(RETRIEVAL_RUNS_DEFAULT))?
        .into_iter().map(|run| evidence(memory, run)).collect()
}

pub fn retrieval_run_as_owner(
    memory: &Memory<'_>, owner: &AuthenticatedOwner, input: RetrievalRunRequest,
) -> MemoryResult<Option<RetrievalRunEvidence>> {
    admitted(memory, owner)?;
    memory.vault().retrieval_run(input.run_id)?
        .map(|run| evidence(memory, run)).transpose()
}

pub fn retrieval_turn_as_owner(
    memory: &Memory<'_>, owner: &AuthenticatedOwner, input: RetrievalTurnRequest,
) -> MemoryResult<Vec<RetrievalRunEvidence>> {
    admitted(memory, owner)?;
    let run_ids = memory.vault().retrieval_runs_by_turn(&input.turn_id)?;
    required_runs(memory, RetrievalDiagnosticRequest { run_ids })?
        .into_iter().map(|run| evidence(memory, run)).collect()
}

/// Raw caller observations remain telemetry, not gate-attributed training labels.
pub fn retrieval_outcomes_put_as_owner(
    memory: &Memory<'_>, owner: &AuthenticatedOwner, input: RetrievalOutcome,
) -> MemoryResult<Vec<RetrievalOutcomeRecord>> {
    admitted(memory, owner)?;
    let run_id = input.run_id;
    memory.vault().record_retrieval_outcome(input)?;
    Ok(memory.vault().retrieval_outcomes(run_id)?)
}

/// The existing end-outcome writer validates the exact run/turn links and writes
/// or retracts every contributor atomically; the door computes no reward itself.
pub fn retrieval_outcomes_end_as_owner(
    memory: &Memory<'_>, owner: &AuthenticatedOwner, input: RetrievalEndOutcome,
) -> MemoryResult<Vec<RetrievalRunEvidence>> {
    admitted(memory, owner)?;
    let turn_id = input.turn_id;
    memory.vault().record_retrieval_end_outcome(input)?;
    retrieval_turn_as_owner(memory, owner, RetrievalTurnRequest { turn_id })
}

pub fn retrieval_trace_as_owner(
    memory: &Memory<'_>, owner: &AuthenticatedOwner, input: RetrievalTraceRequest,
) -> MemoryResult<Option<RetrievalTrace>> {
    admitted(memory, owner)?;
    Ok(memory.vault().retrieval_trace_by_fork_hash(input.fork_hash)?)
}

pub fn retrieval_export_as_owner(
    memory: &Memory<'_>, owner: &AuthenticatedOwner, input: RetrievalDiagnosticRequest,
) -> MemoryResult<RetrievalDiagnosticExport> {
    admitted(memory, owner)?;
    let runs = required_runs(memory, input)?.into_iter().map(|run| {
        let mut row = evidence(memory, run)?;
        if let Some(inputs) = row.run.replay_inputs.as_mut() {
            inputs.query_ref = None;
            inputs.corpus_snapshot_ref = None;
        }
        for outcome in &mut row.outcomes {
            outcome.metadata.clear();
        }
        Ok(row)
    }).collect::<MemoryResult<Vec<_>>>()?;
    Ok(RetrievalDiagnosticExport {
        contract_version: "oneiron.retrieval_diagnostic_export.v1".into(),
        runs,
    })
}

pub fn retrieval_replay_as_owner(
    memory: &Memory<'_>, owner: &AuthenticatedOwner, input: RetrievalDiagnosticRequest,
) -> MemoryResult<RetrievalDiagnosticReplay> {
    admitted(memory, owner)?;
    let runs = required_runs(memory, input)?.into_iter().map(|run| {
        let pack = run.result_ids.iter().map(|id| {
            run.score_breakdown.iter().find(|score| &score.result_id == id).cloned()
                .ok_or(crate::Error::CorruptedIndex("retrieval replay pack"))
        }).collect::<crate::Result<Vec<_>>>()?;
        Ok(RetrievalReplayRun {
            source_run_id: run.run_id,
            turn: run.turn,
            state: run.replay_state().clone(),
            result_ids: run.result_ids,
            pack,
            trace: run.trace,
        })
    }).collect::<MemoryResult<Vec<_>>>()?;
    Ok(RetrievalDiagnosticReplay {
        contract_version: "oneiron.retrieval_diagnostic_replay.v1".into(),
        runs,
    })
}

/// Whole-request typed recall for SDK diagnostic callers, over the ordinary serving path.
pub fn retrieval_recall_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: super::sdk::RecallRequest,
) -> MemoryResult<crate::memory::MemoryPack> {
    admitted(memory, owner)?;
    super::sdk::recall_unembedded(memory, input)
}
