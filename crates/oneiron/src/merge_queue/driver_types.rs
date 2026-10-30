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

use super::{CheckPhase, QueueExportHold, QueueRevisionLink, QueueSealTarget};
use crate::EntityId;
use crate::repo_mutation::RepoForkHash;

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

/// What the driver does next on one queue. Each names the batch it acts on
/// and its place in the order [`QueueWork::priority`] reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueWork {
    /// A landing or rollback intent: the existing recovery runs first.
    Recover,
    /// Settle the pending slow results through the existing `settle_slow`.
    SettleSlow {
        batch: String,
        red: bool,
        order: u64,
    },
    /// Put a saved path back at its saved commit, or pin its objects.
    RepairPath {
        batch: String,
        mask: u64,
        phase: CheckPhase,
        order: u64,
    },
    /// Ask the checker for one missing bound check.
    RequestCheck {
        batch: String,
        mask: u64,
        phase: CheckPhase,
        order: u64,
    },
    /// Stage a queued batch, or hold it.
    Stage { batch: String, order: u64 },
    /// Ask the checker for the bound diagnosis of a red batch.
    Diagnose { batch: String, order: u64 },
    /// Decide a quarantined batch's survivors once.
    RequeueSurvivors { batch: String, order: u64 },
    /// Land a ready batch through the existing reviewed landing.
    LandReviewed { batch: String, order: u64 },
    /// Keep a handed-off batch's conflict, TASK and successor links.
    HandoffOverlap { batch: String, order: u64 },
    /// Seal a green tree's tested revision, earlier green first (G2 PR3).
    SealTested { target: QueueSealTarget, order: u64 },
    /// Write a moved HEAD's hold on a live batch's drive record, or clear it
    /// once HEAD is back (FIX 7310).
    RecordDiverged { batch: String, order: u64 },
    /// Release a settled batch's staged-path keep-refs (FIX 7305).
    ReleasePins { batch: String, order: u64 },
}

impl QueueWork {
    /// The driver's order (CALL C "driver selection policy"): recovery
    /// first, then a red slow settlement, then the landed batches' slow
    /// work and settlement in landing order, then the unlanded batches in
    /// batch-key order. Lower sorts first. No window, cutoff or count.
    #[must_use]
    pub fn priority(&self) -> (u8, u64) {
        match self {
            Self::Recover => (0, 0),
            Self::SettleSlow { red: true, .. } => (1, 0),
            Self::SealTested { order, .. } => (1, order.saturating_add(1)),
            Self::SettleSlow { order, .. }
            | Self::RepairPath {
                phase: CheckPhase::Slow,
                order,
                ..
            }
            | Self::RequestCheck {
                phase: CheckPhase::Slow,
                order,
                ..
            } => (2, *order),
            Self::RepairPath { order, .. }
            | Self::RequestCheck { order, .. }
            | Self::Stage { order, .. }
            | Self::Diagnose { order, .. }
            | Self::RequeueSurvivors { order, .. }
            | Self::LandReviewed { order, .. }
            | Self::HandoffOverlap { order, .. }
            | Self::RecordDiverged { order, .. } => (3, *order),
            Self::ReleasePins { order, .. } => (4, *order),
        }
    }
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

/// Two accepted same-base proposals that replace one path: proven from the
/// stored sources, their common green and retained snapshot, and their
/// exact base bytes. It carries no tree or verdict a caller supplied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QueueStageOverlap {
    /// The queue's CODE_ARTIFACT.
    pub(crate) repo: EntityId,
    /// Every participating batch, in key order.
    pub(crate) batches: Vec<String>,
    pub(crate) target: QueueDriverTarget,
    pub(crate) base_green: String,
    /// The retained snapshot both sources were proposed on.
    pub(crate) snapshot: RepoForkHash,
    /// The two sources, canonically ordered.
    pub(crate) sources: Vec<EntityId>,
    /// The source of the batch whose staging found the overlap: its actor
    /// is the reconciliation's creator.
    pub(crate) driven_source: EntityId,
    /// The shared paths, sorted.
    pub(crate) paths: Vec<String>,
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
