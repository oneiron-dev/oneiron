use std::collections::HashSet;

use rmpv::Value;

use crate::attempt_queue::{AttemptId, AttemptState};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::consult_payload::{ConsultPayload, ConsultPayloadRef, ConsultRecovery};
use super::terminal_state::{ConsultResultSummary, TaskExecutionState, TaskTerminalRecord};
use super::verb_kind::{TaskAssignee, TaskKind, TaskTtl};

/// One peer answer landing on an existing consult TASK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsultResultKind {
    Answer {
        result_ref: EntityId,
        evidence_refs: Vec<ConsultPayloadRef>,
    },
    Abstain {
        result_ref: EntityId,
        reason_ref: ConsultPayloadRef,
    },
}

impl ConsultResultKind {
    pub(super) const fn result_ref(&self) -> EntityId {
        match self {
            Self::Answer { result_ref, .. } | Self::Abstain { result_ref, .. } => *result_ref,
        }
    }

    pub(super) fn summary(&self) -> ConsultResultSummary {
        match self {
            Self::Answer { evidence_refs, .. } => ConsultResultSummary::Answer {
                evidence_refs: evidence_refs.clone(),
            },
            Self::Abstain { reason_ref, .. } => ConsultResultSummary::Abstained {
                reason_ref: *reason_ref,
            },
        }
    }

    /// Every typed ref this result carries, for resolution checks.
    pub(super) fn carried_refs(&self) -> Vec<ConsultPayloadRef> {
        match self {
            Self::Answer { evidence_refs, .. } => evidence_refs.clone(),
            Self::Abstain { reason_ref, .. } => vec![*reason_ref],
        }
    }

    /// An answer carries at least one typed evidence ref; an abstention
    /// carries its durable reason by construction.
    pub(super) fn validate(&self) -> Result<()> {
        match self {
            Self::Answer { evidence_refs, .. } => {
                if evidence_refs.is_empty() {
                    return Err(Error::InvalidTaskBody("tasks.consult.evidence"));
                }
                let mut seen = HashSet::with_capacity(evidence_refs.len());
                if evidence_refs.iter().any(|entry| !seen.insert(*entry)) {
                    return Err(Error::InvalidTaskBody("tasks.consult.duplicate_ref"));
                }
                Ok(())
            }
            Self::Abstain { .. } => Ok(()),
        }
    }
}

/// Input to [`MemoryFacade::land_consult_result`](crate::facade::MemoryFacade::land_consult_result).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsultResultInput {
    pub kind: ConsultResultKind,
    pub completed_at: u64,
}

/// Receipt for one landed consult result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskResultReceipt {
    pub task_ref: EntityId,
    pub terminal: TaskTerminalRecord,
    pub idempotent_replay: bool,
}

/// One question addressed to N distinct peer actors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsultFanOutSpec {
    pub question_ref: ConsultPayloadRef,
    pub context_refs: Vec<ConsultPayloadRef>,
    pub assignees: Vec<EntityId>,
    pub deadline_at: u64,
    pub label: Option<String>,
    /// Caller clock, exactly as `TaskCreateSpec::now`: the fan-out runs the
    /// same validated consult-create path, so it reads the same clock. The
    /// rate window stays on the engine clock either way.
    pub now: Option<u64>,
}

/// Receipt for one fan-out: the shared correlation ref plus one task per peer,
/// in deterministic assignee order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsultFanOutReceipt {
    pub correlation_ref: EntityId,
    pub task_refs: Vec<EntityId>,
}

/// Host-supplied addressing for the ARCH-0046 expiry digest, plus the typed
/// recovery choices the lens renders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsultDigestRoute {
    pub verb: String,
    pub channel: String,
    pub target: String,
    pub on_behalf_of: Option<String>,
    pub recovery: Vec<ConsultRecovery>,
}

/// Outcome of one TTL reconciliation sweep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsultExpiryReport {
    pub expired_task_refs: Vec<EntityId>,
    pub digest_intent_refs: Vec<String>,
    pub already_settled: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct TaskVerbBody {
    pub(super) role: u8,
    pub(super) schema_version: u8,
    pub(super) subkind: String,
    pub(super) kind: Option<TaskKind>,
    pub(super) owner_ref: String,
    pub(super) assignee: Option<TaskAssignee>,
    pub(super) label: Option<String>,
    pub(super) spec: Value,
    pub(super) consult: Option<ConsultPayload>,
    pub(super) ttl: Option<TaskTtl>,
    pub(super) state: Option<TaskExecutionState>,
    pub(super) provenance: Value,
    pub(super) created_at: u64,
}

impl TaskVerbBody {
    /// `None` is the schema-v1 compatibility representation of a standard task.
    pub(super) const fn task_kind(&self) -> TaskKind {
        match self.kind {
            Some(kind) => kind,
            None => TaskKind::Standard,
        }
    }

    pub(super) const fn terminal(&self) -> Option<&TaskTerminalRecord> {
        match &self.state {
            Some(state) => state.terminal(),
            None => None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct CancelTargetState {
    pub(super) owned: bool,
    pub(super) task_ref: Option<EntityId>,
    pub(super) attempts: Vec<(AttemptId, AttemptState)>,
    pub(super) proposal_subject: EntityId,
    pub(super) target_ref: String,
}
