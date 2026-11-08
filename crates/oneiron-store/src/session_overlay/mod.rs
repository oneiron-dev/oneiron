//! In-memory session write-overlay substrate (ARCH-0052, D1).
//!
//! The overlay is independent of the durable off-record fence machinery. It
//! owns one structurally shared keyspace per database manifest slot, typed
//! journal entries, generation-stamped read/segment leases, and the byte
//! budget that bounds live overlay rows.

pub mod journal;
pub mod keyspace;
pub mod overlay;
pub mod route;
pub mod short_id;
pub mod snapshot;

#[cfg(any(test, feature = "test-support"))]
pub mod hygiene_tests;
#[cfg(test)]
mod tests;

pub use self::journal::{
    JournalEntry, JournalRole, JournalScope, PromotePlan, replayed_subject,
    zeroize_batch_op_payload,
};
pub use self::keyspace::OverlayKeyspace;
pub use self::overlay::{RecordMetaRows, SessionOverlay, TxnSegmentGuard, txn_segment_installed};
pub use self::route::{RouteTarget, SessionWriteRoute};
pub use self::snapshot::{
    OverlaySnapshot, SnapshotLookup, SnapshotMergePlan, SnapshotMergeRow, StagedRows,
};

// The flat session_overlay.rs module used to provide these names to the test
// module through `use super::*`; after the directory split the seam re-imports
// them so the extracted sibling `tests.rs` resolves exactly as it did inline.
#[cfg(test)]
use self::keyspace::OverlayMutation;
#[cfg(test)]
use self::overlay::{ACTIVE_SEGMENT, OverlayLifecycleState};
#[cfg(test)]
use self::short_id::{
    SESSION_SHORT_ID_SIGIL, encode_session_short_id_forward_key, session_short_id_content_hash,
};
#[cfg(test)]
use crate::batch_op::BatchOp;
#[cfg(test)]
use oneiron_contracts::entity_id::EntityId;
#[cfg(test)]
use oneiron_contracts::error::{Error, Result};
#[cfg(test)]
use std::collections::BTreeSet;
#[cfg(test)]
use std::sync::Arc;
