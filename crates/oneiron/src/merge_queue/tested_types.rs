//! Core half of `merge_queue::tested_types`: its store-layer items live in `oneiron_store::merge_queue::tested_types` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::merge_queue::tested_types::*;

use crate::EntityId;
use crate::store::code_revision_record::CodeRevision;

#[doc(hidden)]
pub use oneiron_records::merge_queue::tested_types::{QueueReceiptLink, QueueTestedRevision};

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
