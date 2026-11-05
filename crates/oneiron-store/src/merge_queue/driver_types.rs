//! The queue driver's instructions, outcomes, holds and the durable drive
//! record a batch keeps (FIX 6868, G2 PR2).
//!
//! A [`QueueWork`] is a snapshot instruction, never a capability: the driver
//! reads the queue again under its repository writer before it acts. A
//! batch's [`QueueBatchDrive`] keeps only what the driver decided and must
//! not decide twice: its custody pins, its overlap handoff, its survivor
//! disposition and its last typed hold. Check status and receipts stay on
//! the checker's own rows and are joined, never copied.
use serde::{Deserialize, Serialize};

use crate::merge_queue::tested_types::QueueExportHold;
use crate::merge_queue::tested_types::QueueRevisionLink;
use crate::merge_queue::tested_types::QueueSealTarget;
use crate::repo_fork::RepoForkHash;
use oneiron_contracts::entity_id::EntityId;

/// One pass of the checker drain, as the driver reads it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueueDrivePass {
    /// The lifecycle tick started this pass, not a commit wake. A held
    /// check or a held landing is asked again on a tick only, so a hold
    /// never wakes itself.
    pub tick: bool,
    /// The first pass since this host started: a check that needed host
    /// configuration is asked again once.
    pub first: bool,
}

/// What one driven step did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueDriveOutcome {
    /// A durable transition committed.
    Changed,
    /// A bound check was asked for; the checker runs it.
    RequestedCheck { work_ref: String },
    /// Nothing moved; the batch waits or is held for this reason.
    Waiting(QueueDriveHold),
    /// Nothing is left to drive here.
    Done,
}

impl QueueDriveOutcome {
    /// Whether this step wrote something a later step may build on.
    #[must_use]
    pub fn moved(&self) -> bool {
        matches!(self, Self::Changed | Self::RequestedCheck { .. })
    }
}

/// Why the driver waits on or holds a batch. A hold keeps every byte,
/// review and verdict; none is a failed check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueDriveHoldReason {
    /// A requested check is queued or running.
    WaitingCheck,
    /// A predecessor's symbol declaration still holds the run entry.
    WaitingSymbols,
    /// A member lacks its unanimous critic review.
    WaitingReview,
    /// The reviewed landing refused its admission.
    WaitingAdmission,
    /// The batch's base moved: a fresh reviewed proposal is needed. No
    /// automatic rebase.
    HeldNeedsNewBase,
    /// The repository HEAD moved without a queue receipt.
    HeldDiverged,
    /// A verdict was recorded without a bound receipt; the automatic
    /// driver does not land on it.
    HeldBinding,
    /// A saved path cannot be put back at its saved commit.
    HeldMaterialization,
    /// Overlapping accepted proposals were handed to a reconciliation.
    HeldOverlap,
    /// The reconciliation TASK waits below its creator's Auto ceiling.
    HeldTaskAuthority,
    /// A landing or rollback intent needs the existing recovery.
    HeldRecovery,
    /// The checker held the check: no verdict.
    HeldCheck,
    /// The checker needs host configuration first.
    NeedsConfiguration,
    /// The green tree's tested-revision seal holds; the batch's
    /// `seal_hold` names why (G2 PR3).
    HeldSeal,
}

/// A typed hold and its reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueDriveHold {
    pub reason: QueueDriveHoldReason,
    pub detail: String,
}

impl QueueDriveHold {
    #[must_use]
    pub fn new(reason: QueueDriveHoldReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }
}

/// The attached branch a checked queue lands on, captured at checked
/// initialization: never guessed and never rebuilt from a moved HEAD.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueDriverTarget {
    /// The full ref HEAD named, e.g. `refs/heads/main`.
    pub full_ref: String,
    pub branch: String,
    /// The subject its typed conflicts attach to: the queue's CODE_ARTIFACT.
    pub branch_subject: EntityId,
}

/// A quarantined batch's survivor disposition, decided once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueueSurvivorLink {
    /// No member survived.
    Empty,
    /// The survivors' batch.
    Batch(String),
}

/// One overlap handoff: the typed conflict, its TASK or the hold that
/// keeps it, and the successor that resolves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueConflictLink {
    pub conflict: EntityId,
    pub branch_subject: EntityId,
    /// The reconciliation TASK, once its creator's authority admits it.
    pub task: Option<EntityId>,
    /// Why no TASK was minted yet (HeldTaskAuthority).
    pub held: Option<String>,
    /// The overlapping source proposals, canonically ordered.
    pub sources: Vec<EntityId>,
    /// Every participating batch, in key order.
    pub batches: Vec<String>,
    /// The fresh queue entry the reconciliation submitted.
    pub resolution_batch: Option<String>,
    /// The resolution reached green: this source is kept, superseded.
    pub superseded: bool,
}

/// What the driver decided for one batch.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueBatchDrive {
    /// Its staged commits carry keep-refs; false again once a settled
    /// batch's pins are released (FIX 7305).
    pub pinned: bool,
    pub overlap: Option<QueueConflictLink>,
    pub survivor: Option<QueueSurvivorLink>,
    /// The quarantined batch these survivors came from.
    pub survivor_of: Option<String>,
    /// The last typed hold; an unchanged one is not written again.
    pub hold: Option<QueueDriveHold>,
    /// Its tested-revision seal once green: pending, then sealed (G2 PR3).
    pub tested: Option<QueueRevisionLink>,
}

/// Where the automatic driver stands on one batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueDriveStatus {
    /// No checked configuration enrolls this queue: nothing drives it.
    Unenrolled,
    /// The driver moves it on its next pass.
    Driving,
    WaitingCheck,
    WaitingSymbols,
    WaitingReview,
    WaitingAdmission,
    HeldNeedsNewBase,
    HeldDiverged,
    HeldBinding,
    HeldMaterialization,
    HeldOverlap,
    HeldTaskAuthority,
    HeldRecovery,
    HeldCheck,
    NeedsConfiguration,
    HeldSeal,
    /// The drive record could not be read; the batch is unchanged.
    Unavailable,
    /// Green, rolled back, cancelled or its survivors decided.
    Done,
}

impl From<QueueDriveHoldReason> for QueueDriveStatus {
    fn from(reason: QueueDriveHoldReason) -> Self {
        match reason {
            QueueDriveHoldReason::WaitingCheck => Self::WaitingCheck,
            QueueDriveHoldReason::WaitingSymbols => Self::WaitingSymbols,
            QueueDriveHoldReason::WaitingReview => Self::WaitingReview,
            QueueDriveHoldReason::WaitingAdmission => Self::WaitingAdmission,
            QueueDriveHoldReason::HeldNeedsNewBase => Self::HeldNeedsNewBase,
            QueueDriveHoldReason::HeldDiverged => Self::HeldDiverged,
            QueueDriveHoldReason::HeldBinding => Self::HeldBinding,
            QueueDriveHoldReason::HeldMaterialization => Self::HeldMaterialization,
            QueueDriveHoldReason::HeldOverlap => Self::HeldOverlap,
            QueueDriveHoldReason::HeldTaskAuthority => Self::HeldTaskAuthority,
            QueueDriveHoldReason::HeldRecovery => Self::HeldRecovery,
            QueueDriveHoldReason::HeldCheck => Self::HeldCheck,
            QueueDriveHoldReason::NeedsConfiguration => Self::NeedsConfiguration,
            QueueDriveHoldReason::HeldSeal => Self::HeldSeal,
        }
    }
}

/// One overlap handoff on the wire: references only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueConflictView {
    /// The overlapping source proposals.
    pub source_proposals: Vec<String>,
    /// The typed conflict claim.
    pub conflict: String,
    /// The reconciliation TASK, once minted.
    pub task: Option<String>,
    /// The fresh queue entry that resolves it, once linked.
    pub resolution_batch: Option<String>,
}

/// The automatic driver's view of one batch: its status, the checker work
/// and receipts that bind it, and its overlap handoff. No host path,
/// command body or exhaust.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueDriveView {
    pub batch_ref: String,
    pub status: QueueDriveStatus,
    pub reason: Option<String>,
    /// The checker work this batch's checks ride, by reference.
    pub check_work_refs: Vec<String>,
    /// Their receipts, as `queue-check:v1:<inputs digest>`.
    pub receipt_refs: Vec<String>,
    pub conflicts: Vec<QueueConflictView>,
    /// The survivors' batch of a quarantined batch.
    pub survivor_batch: Option<String>,
    /// The tested revision this green batch sealed (G2 PR3).
    pub tested_revision: Option<String>,
    /// Why its seal holds, and how out (CALLS D and E).
    pub seal_hold: Option<QueueExportHold>,
}
