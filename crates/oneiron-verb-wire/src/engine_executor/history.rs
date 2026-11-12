//! Moved from `crates/oneiron/src/engine_executor/history.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::code_run::fold_api::FoldHistoryRequest;
use crate::code_run::fold_api::FoldUnfoldRequest;
use crate::code_run::type_diagnostics::ProgramPreparationNote;
use crate::code_run::type_diagnostics::ProgramStepFeedbackRelease;
use crate::code_run::type_diagnostics::TypeDiagnostics;
use crate::compaction::folds::FoldDescription;
use crate::compaction::folds::FoldList;
use crate::compaction::folds::FoldReply;
use crate::compaction::folds::FoldUnfold;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::result_manifest::CODE_RUN_OUTPUT_PREVIEW_WITHHELD;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FoldHistory {
    pub run: String,
    /// Count of checkpointed steps, not an in-flight step or a caller's ordinal.
    pub completed_steps: u64,
    /// Last step covered by a committed epoch, inclusive; none before the first.
    pub compacted_through: Option<u64>,
    pub state: FoldList,
    pub folds: Vec<FoldDescription>,
    pub unfolds: Vec<FoldUnfold>,
    pub epochs: Vec<FoldHistoryEpoch>,
    pub steps: Vec<FoldHistoryStep>,
    pub next: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FoldHistoryEpoch {
    pub summary_ref: String,
    pub epoch: u64,
    pub from: u64,
    pub through: u64,
    /// None when the source was withdrawn; the retained boundary remains.
    pub text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FoldHistoryStep {
    pub step: u64,
    pub code: String,
    pub console: String,
    /// The step's type check as it stands now (FIX 8277): the host's
    /// feedback beside its console, never part of it. None when no feedback
    /// was kept for the step, or its program is withheld.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_diagnostics: Option<TypeDiagnostics>,
    /// What the program's preparation noted, when it ran as written though
    /// it was not JavaScript Oxc accepts (FIX 8276).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preparation_note: Option<ProgramPreparationNote>,
    /// The step's feedback withheld from this answer's destination, in place
    /// of `type_diagnostics` and `preparation_note`, when its own release
    /// check holds it (FIX 10390): its identity, `check_ref`, state, facts
    /// and measures, with none of its text. None as the run reads it; only
    /// an MCP answer's release sets it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_feedback: Option<ProgramStepFeedbackRelease>,
}
