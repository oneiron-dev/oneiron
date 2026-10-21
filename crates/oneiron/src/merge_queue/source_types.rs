//! The served queue source's names (FIX 6869): which authenticated import a
//! served repository's checked queue materializes, and where.
//!
//! A served anchor stores its bare object store with no commit selected, so
//! its queue cannot stand on that folder. Its checked initialization binds
//! ONE import manifest instead, and the queue runs in one engine-owned
//! detached linked worktree of that same object store under the vault's
//! environment (CALL 1). The descriptor is metadata, never authority: the
//! owner's queued approval and every engine gate stay where they are.
use serde::{Deserialize, Serialize};

use super::MergeQueue;
use crate::EntityId;

/// The directory under the vault environment that holds every served
/// store's queue source: `<vault env>/merge-queue/<store hex>/source`,
/// one root per object store (CALL 1).
pub(crate) const QUEUE_SOURCE_DIR: &str = "merge-queue";

/// The leaf of one store's queue source root.
pub(super) const QUEUE_SOURCE_LEAF: &str = "source";

/// The import a checked initialization's served queue source materializes:
/// the `repo.import_manifest` claim it froze. Stored only on the init's own
/// work row; `None` there means a native queue, not an older format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServedQueueSource {
    /// The import manifest claim, by its deterministic id.
    pub manifest: EntityId,
}

/// A queue an owner's checked init requests on: a native repository's own
/// root, or a served import's materialized source with the descriptor its
/// init work freezes.
pub(crate) struct PreparedQueueInit<'a> {
    pub(crate) queue: MergeQueue<'a>,
    pub(crate) source: Option<ServedQueueSource>,
}
