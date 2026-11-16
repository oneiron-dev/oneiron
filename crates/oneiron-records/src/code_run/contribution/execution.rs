//! Moved from `crates/oneiron/src/code_run/contribution/execution.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::code_run::contribution::owner::OwnerJudgment;
use crate::compaction::output::OutputRef;
use serde::Deserialize;
use serde::Serialize;

/// What a pair's scorer reads (FIX 3607), the same for both forks: one part
/// of the identity both forks are scored under, beside their anchor's
/// frozen rubric and scorer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForkEvidenceMode {
    /// Each answer's text alone: the route before FIX 3607, and a workflow
    /// step's always.
    Text,
    /// An engine step whose two forks both ran their answers under one pin:
    /// each answer's text and what its program did, by the digest of the
    /// [`ForkExecutionPin`] both ran under.
    Executed { pin: [u8; 32] },
}

/// A fork's score: the evidence mode its pair was scored in, whether it
/// passed and who decided that. Both forks of a pair are scored in one mode
/// and by one judge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkScore {
    pub mode: ForkEvidenceMode,
    pub passed: bool,
    pub judge: ForkJudge,
}

/// Who decided a fork's score (FIX 3609). It is kept apart from the
/// evidence mode: the mode says what was read, the judge says who read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForkJudge {
    /// The anchor's scorer the host lent, by the pair's frozen rubric.
    Scorer,
    /// The owner's own counted word on the pair's question.
    Owner(OwnerJudgment),
}

/// How a fork's program step ended when it ran: to its end (`done` when its
/// program finished the run), or failed as a run's step fails (`kind` names
/// how). Only these are evidence a scorer reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutedStepStatus {
    StepComplete { done: bool },
    Failed { kind: String },
}

/// One body a fork's program left, adopted as a body its source run owns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutedBody {
    /// Its path in the step, as the program's run names it.
    pub path: String,
    /// Where the run keeps it: an opaque fork path.
    pub stored_path: String,
    pub body: OutputRef,
    /// Whether its producer finished it.
    pub complete: bool,
}
