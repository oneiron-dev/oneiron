//! Typed cross-kind review settlements and run compensation (ARCH-0040).
//!
//! Membership is explicit, never guessed from actor or time. Review binds the
//! exact members and policy frontier; settlement keeps their inverse handles.

mod revert;
mod settle;
mod snapshot;
mod topology;

use crate::consent::AuthenticatedOwner;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::side_table::{self, Named, SideTable};
use crate::{EdgeActorClass, EntityId, WriteActor};
use serde::{Deserialize, Serialize};

/// An existing change joining this explicit review. No raw entity, approval,
/// actor or external action can be supplied through this door.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunReviewChange {
    Claim {
        claim_ref: String,
    },
    /// An edge is undone through its existing provenance retraction door.
    Edge {
        provenance_ref: String,
    },
    Note {
        note_ref: String,
        fork_ref: String,
    },
    Topology {
        event_ref: String,
    },
    /// An existing external-effect gate receipt; it is never replayed.
    ExternalEffect {
        receipt_ref: String,
    },
    Delete {
        entity_ref: String,
    },
    Erase {
        entity_ref: String,
    },
}

impl RunReviewChange {
    fn change(&self) -> &str {
        match self {
            Self::Claim { claim_ref } => claim_ref,
            Self::Edge { provenance_ref } => provenance_ref,
            Self::Note { fork_ref, .. } => fork_ref,
            Self::Topology { event_ref } => event_ref,
            Self::ExternalEffect { receipt_ref } => receipt_ref,
            Self::Delete { entity_ref } | Self::Erase { entity_ref } => entity_ref,
        }
    }

    fn rows(&self) -> MemoryResult<Vec<EntityId>> {
        match self {
            Self::ExternalEffect { .. } => Ok(Vec::new()),
            Self::Note { note_ref, .. } => Ok(vec![EntityId::from_hex(note_ref)?]),
            _ => Ok(vec![EntityId::from_hex(self.change())?]),
        }
    }
}

/// The exact set being reviewed, including any child-job changes. A run id
/// labels the job, not an actor and not a time range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunReviewRequest {
    pub run_id: String,
    pub changes: Vec<RunReviewChange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunChangeVerdict {
    Landed,
    Rejected,
    Waiting,
    LetGo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunChangeOutcome {
    pub change: String,
    pub verdict: RunChangeVerdict,
    pub receipt: Option<String>,
}

/// Derived text with its source refs. It is never persisted as a memory row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunReviewExplainer {
    pub text: String,
    pub read_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunReview {
    pub run_id: String,
    pub review_id: String,
    pub changes: Vec<RunChangeOutcome>,
    pub explainer: RunReviewExplainer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunSettleDecision {
    Approve,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunSettleRequest {
    pub review: RunReviewRequest,
    pub review_id: String,
    pub decision: RunSettleDecision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum RunAnsweredBy {
    Word { word_ref: String },
    Row { row: String },
    Grant { grant: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum RunSettlementKind {
    ProposalOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunSettlementReason {
    OwnerApproved,
    OwnerRejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunSettlement {
    pub kind: RunSettlementKind,
    pub run_id: String,
    pub receipt: String,
    pub changes: Vec<RunChangeOutcome>,
    pub verdict: RunChangeVerdict,
    pub answered_by: RunAnsweredBy,
    pub reason: RunSettlementReason,
    pub summary: String,
    pub revert_handle: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunSettlementRequest {
    pub run_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevertRunRequest {
    /// The job id or the settlement's run: handle.
    pub run_id: String,
    /// Absent means all; a present list selects exact change refs, even one.
    #[serde(default)]
    pub changes: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunCompensation {
    pub change: String,
    pub receipt: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunNotUndoneReason {
    OneWay,
    BackupOnly,
    Dependent,
    NotSelected,
    NotLanded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunNotUndone {
    pub change: String,
    pub reason: RunNotUndoneReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RevertRunOutcome {
    pub run_id: String,
    pub compensated: Vec<RunCompensation>,
    pub not_undone: Vec<RunNotUndone>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredRun {
    settlement: RunSettlement,
    changes: Vec<StoredChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredChange {
    member: RunReviewChange,
    verdict: RunChangeVerdict,
    inverse: Option<RunInverse>,
    compensation: Option<String>,
    unrestored: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum RunInverse {
    Authored { author: String, fingerprint: String },
    Note(crate::note::RunNoteUndo),
    Topology { event: String },
}

const SETTLEMENTS: SideTable<String, StoredRun, Named> =
    SideTable::new(&side_table::RUN_REVIEW_SETTLEMENT);

fn run_key(run: &str) -> MemoryResult<String> {
    let run = run.strip_prefix("run:").unwrap_or(run);
    if run.trim().is_empty() || run.len() > 1024 {
        return Err(MemoryError::bad_request(
            "run_id is a nonempty job id of at most 1024 bytes",
        ));
    }
    Ok(run.to_owned())
}

fn require_owner(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    owner: &AuthenticatedOwner,
) -> MemoryResult<WriteActor> {
    let person = super::authorship::verify_owner(memory.vault(), txn, owner)?;
    if person != memory.actor() || memory.actor_class() != EdgeActorClass::Human {
        return Err(MemoryError::new(
            super::MEMORY_CODE_FORBIDDEN,
            "run review acts through the caller's own owner credential",
            &[],
        ));
    }
    memory.verify_actor_write_in_txn(txn)?;
    Ok(WriteActor::new(person, EdgeActorClass::Human))
}

fn fingerprint(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

impl Memory<'_> {
    /// The durable result of this job's one cross-kind settlement.
    pub fn run_settlement_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &RunSettlementRequest,
    ) -> MemoryResult<RunSettlement> {
        let run = run_key(&input.run_id)?;
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        require_owner(self, &txn, owner)?;
        let journal = SETTLEMENTS
            .get(&self.vault().store, &txn, &run)?
            .ok_or_else(|| MemoryError::not_found("no run settlement has that id"))?;
        self.produced_from(
            journal
                .changes
                .iter()
                .map(|m| m.member.rows())
                .collect::<MemoryResult<Vec<_>>>()?
                .into_iter()
                .flatten(),
        );
        Ok(journal.settlement)
    }

    /// Reads exactly the explicit set and the live policy in one snapshot.
    pub fn review_run_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &RunReviewRequest,
    ) -> MemoryResult<RunReview> {
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        require_owner(self, &txn, owner)?;
        let reviewed = snapshot::review_in_txn(self, &txn, input)?;
        self.produced_from(
            input
                .changes
                .iter()
                .map(RunReviewChange::rows)
                .collect::<MemoryResult<Vec<_>>>()?
                .into_iter()
                .flatten(),
        );
        Ok(reviewed)
    }
}
