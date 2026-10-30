//! The tested-revision seal's records, links and holds (FIX 6868, G2 PR3).
//!
//! A batch that reaches green, and the checked baseline before it, earn
//! one durable complete-tree CodeRevision: [`QueueTestedRevision`] is its
//! immutable queue record. The queue row keeps a compact
//! [`QueueRevisionLink`] only; the full inventory lives in the revision. A
//! green pointer earns a tested record, never review authority over bytes
//! nobody reviewed, so the export of a seal waits on its own named holds.
use serde::{Deserialize, Serialize};

use super::CheckPhase;
use crate::EntityId;
use crate::code_revision::CodeRevision;
use crate::repo_mutation::RepoForkHash;

/// One bound checker receipt a tested revision stands on. The receipt on
/// the checker's work row keeps the inputs, action, output and attempt; the
/// link names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueReceiptLink {
    pub phase: CheckPhase,
    /// The checked path's mask; zero for the baseline.
    pub mask: u64,
    /// The checker work row that holds the receipt.
    pub work_ref: String,
    pub inputs_digest: String,
    /// The verdict the receipt bound; the baseline records none.
    pub verdict_ref: Option<String>,
}

/// One proposal a landed batch applied, in landing order, with its own
/// session and provenance: the aggregation never rewrites them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueAppliedSource {
    pub proposal: EntityId,
    /// The repo mutation operation it landed as.
    pub operation_seq: u64,
    pub session: EntityId,
    pub provenance_claim: EntityId,
}

/// What a tested revision records it tested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum QueueTestedTarget {
    /// The approved baseline checked initialization ran both phases on.
    Baseline,
    /// One batch that reached green: its actually landed prefix.
    Landed {
        batch: String,
        landed_mask: u64,
        /// The staged commit the fast checks ran on, not the landed one.
        speculative_commit: String,
        /// The green the batch landed on.
        expected_head: String,
        pre_snapshot: RepoForkHash,
        applied: Vec<QueueAppliedSource>,
    },
}

/// The immutable queue record of one tested complete tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueTestedRevision {
    pub schema_version: u8,
    /// The CODE_ARTIFACT the queue serves.
    pub repo: EntityId,
    /// The proven object store's hex identity.
    pub store: String,
    /// The checked-init work key the queue's tested chain descends from.
    pub init_work: String,
    pub baseline_commit: String,
    pub baseline_tree: String,
    /// The contract baseline the verdicts compare to.
    pub oracle_baseline: String,
    pub plan_digest: String,
    /// The exact checked commit and tree.
    pub commit: String,
    pub tree: String,
    pub target: QueueTestedTarget,
    /// Every fast check that earned landing, by mask.
    pub fast: Vec<QueueReceiptLink>,
    /// The slow check of the landed tree.
    pub slow: QueueReceiptLink,
    /// The digest of the complete document and blob inventory.
    pub inventory_digest: [u8; 32],
    /// Each accepted push this tree consumed completely, sorted (G4 PR2):
    /// its checked root is the push's incoming tip. Empty on every other
    /// revision, which encodes as before.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub received_pushes: Vec<CodePushSourceLink>,
}

/// One accepted push a tested revision consumed completely: its candidate,
/// its retained source and publication, its base revision and the
/// candidate's source digest. Only an all-files bundle whose checked tree
/// is the incoming tip's earns it; a subset or a mixed tree never does.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodePushSourceLink {
    pub candidate: EntityId,
    pub provenance: EntityId,
    pub ref_name: String,
    pub publication: EntityId,
    pub old_commit: String,
    pub new_commit: String,
    pub base_revision: EntityId,
    pub candidate_digest: [u8; 32],
    /// A push from a masked copy: what ties it to the canonical tree it was
    /// translated to (FIX 7608 2b-ii); none for every other push.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection: Option<CodePushProjectionSourceLink>,
}

/// A projected push's tie to the canonical tree it was translated to: its
/// masked copy's graph and ingress proof, the submitted COPY tips, the
/// ORIGINAL base and the canonical target tree, and the digest of the
/// candidate's projection pins. A complete link is earned only when the
/// checked canonical tree is this target, never the submitted tree.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodePushProjectionSourceLink {
    pub graph: EntityId,
    pub ingress: EntityId,
    pub submitted_old: Option<String>,
    pub submitted_new: String,
    pub canonical_base: String,
    pub canonical_target_tree: String,
    pub pins_digest: [u8; 32],
}

/// Which seal a driver step works on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueueSealTarget {
    /// The checked baseline, kept on its init work row.
    Baseline,
    /// One green batch.
    Landed { batch: String },
}

/// What a seal will write, decided once: its deterministic identities and
/// its persisted seal time. No bytes and no inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueRevisionIntent {
    pub revision: EntityId,
    pub session: EntityId,
    pub target: QueueSealTarget,
    /// The green this one landed on; `None` for the baseline.
    pub parent_commit: Option<String>,
    pub commit: String,
    pub tree: String,
    pub plan_digest: String,
    /// The checked-init approver, recorded for the baseline only.
    pub approver: Option<EntityId>,
    pub sealed_at: u64,
}

/// A batch's or the baseline's seal: pending with its last hold, or sealed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueueRevisionLink {
    Pending {
        intent: QueueRevisionIntent,
        hold: Option<QueueExportHold>,
    },
    Sealed {
        revision: EntityId,
    },
}

impl QueueRevisionLink {
    /// The sealed revision, once sealed.
    #[must_use]
    pub fn sealed(&self) -> Option<EntityId> {
        match self {
            Self::Sealed { revision } => Some(*revision),
            Self::Pending { .. } => None,
        }
    }
}

/// Why a seal or a green export holds (CALLS D and E). None is a red
/// verdict; each keeps the work and names its way out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueExportHoldReason {
    /// The current green's tested revision is not sealed yet.
    SealPending,
    /// An earlier green's seal is missing; this one waits on it.
    HeldSealAncestor,
    /// A verdict carries no bound checker receipt.
    HeldBinding,
    /// A checked Git object is not in the object store.
    HeldObject,
    /// The tree holds an entry the origin export does not write.
    HeldUnsupportedTree,
    /// A path changed without an admitted reviewed operation.
    HeldUnreviewedChange,
    /// The export checkout does not share the queue's object store.
    HeldStore,
    /// Untouched imported bytes have no reviewed admission yet (G4).
    HeldUntouchedPromotion,
    /// The canonical author was erased: an author erased before the seal
    /// holds this revision's export alone, never later seals (FIX 7348).
    AuthorErased,
    /// The canonical author cannot be read.
    AuthorUnavailable,
    /// No checked configuration drives this queue.
    Unenrolled,
    /// The queue's rows could not be read.
    Unavailable,
}

impl QueueExportHoldReason {
    /// Its wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SealPending => "seal_pending",
            Self::HeldSealAncestor => "held_seal_ancestor",
            Self::HeldBinding => "held_binding",
            Self::HeldObject => "held_object",
            Self::HeldUnsupportedTree => "held_unsupported_tree",
            Self::HeldUnreviewedChange => "held_unreviewed_change",
            Self::HeldStore => "held_store",
            Self::HeldUntouchedPromotion => "held_untouched_promotion",
            Self::AuthorErased => "author_erased",
            Self::AuthorUnavailable => "author_unavailable",
            Self::Unenrolled => "unenrolled",
            Self::Unavailable => "unavailable",
        }
    }
}

/// A named hold and how out of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueExportHold {
    pub reason: QueueExportHoldReason,
    pub detail: String,
    pub way_out: String,
}

impl QueueExportHold {
    #[must_use]
    pub fn new(reason: QueueExportHoldReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
            way_out: way_out(reason).to_owned(),
        }
    }
}

const OWNER_EXPORT: &str = "the owner's unchanged vault.code.export exports a reviewed revision";

fn way_out(reason: QueueExportHoldReason) -> &'static str {
    match reason {
        QueueExportHoldReason::SealPending => {
            "the queue driver seals the current green on its next pass; until then, the owner's \
             unchanged vault.code.export"
        }
        QueueExportHoldReason::HeldSealAncestor => {
            "the earlier green's seal finishes first; read that batch's seal_hold"
        }
        QueueExportHoldReason::HeldBinding => {
            "land a fresh reviewed proposal through the driven queue, whose checks bind receipts; \
             or the owner's unchanged vault.code.export"
        }
        QueueExportHoldReason::HeldObject => {
            "restore the queue's pinned Git objects and the driver seals again on a tick; or the \
             owner's unchanged vault.code.export"
        }
        QueueExportHoldReason::HeldUnsupportedTree => {
            "the origin export writes no submodule link; the owner's unchanged vault.code.export \
             of a revision without one"
        }
        QueueExportHoldReason::HeldUnreviewedChange => {
            "a fresh combined reviewed proposal; or the owner's unchanged vault.code.export"
        }
        QueueExportHoldReason::HeldStore => {
            "export from a live checkout of the queue's own object store"
        }
        QueueExportHoldReason::HeldUntouchedPromotion => {
            "untouched imported bytes need the reviewed import manifest (G4); until then, the \
             owner's unchanged vault.code.export"
        }
        QueueExportHoldReason::AuthorErased | QueueExportHoldReason::AuthorUnavailable => {
            "the owner's unchanged vault.code.export, or a fresh combined proposal"
        }
        QueueExportHoldReason::Unenrolled => OWNER_EXPORT,
        QueueExportHoldReason::Unavailable => "read the queue again",
    }
}

/// The current green's export readiness on the queue's status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueGreenExportView {
    pub green_commit: String,
    /// Its sealed tested revision, once sealed.
    pub tested_revision: Option<String>,
    /// Why `vault.code.merge_queue.export_green` holds now; `None` when
    /// it is ready.
    pub hold: Option<QueueExportHold>,
}

/// The current green's sealed revision, issued by the queue after it read
/// the persisted record, its folds and evidence and matched them to the
/// live green pointer. A read capability: it grants no write, review or
/// publication authority. No caller constructs or decodes one.
pub struct GreenQueueRevision {
    pub(super) revision: CodeRevision,
    pub(super) store: String,
    pub(super) commit: String,
}

impl GreenQueueRevision {
    #[must_use]
    pub fn revision_id(&self) -> EntityId {
        self.revision.revision_id
    }

    #[must_use]
    pub fn revision(&self) -> &CodeRevision {
        &self.revision
    }

    #[must_use]
    pub fn store(&self) -> &str {
        &self.store
    }

    #[must_use]
    pub fn commit(&self) -> &str {
        &self.commit
    }
}

/// Where a seal attaches in its finalizer's writer.
pub(crate) enum QueueSealSource {
    /// A green batch, by its row key.
    Batch(String),
    /// The checked-init work, by its row key.
    Init(String),
}

/// A finalized revision the queue issued from a validated target: the
/// record, the source row its link attaches to and the stored repository
/// pointer. Only the queue builds one.
pub(crate) struct QueueRevisionSeal {
    pub(super) revision: CodeRevision,
    pub(super) source: QueueSealSource,
    pub(super) repo_ref: String,
}

impl QueueRevisionSeal {
    pub(crate) fn revision(&self) -> &CodeRevision {
        &self.revision
    }

    /// The queue's stored local folder pointer, canonical.
    pub(crate) fn repo_ref(&self) -> &str {
        &self.repo_ref
    }
}
