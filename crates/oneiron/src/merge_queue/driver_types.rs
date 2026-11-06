//! Core half of `merge_queue::driver_types`: its store-layer items live in `oneiron_store::merge_queue::driver_types` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::merge_queue::driver_types::*;

use super::{CheckPhase, QueueExportHold, QueueRevisionLink, QueueSealTarget};
use crate::EntityId;
use crate::store::repo_fork::RepoForkHash;
use serde::{Deserialize, Serialize};

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
