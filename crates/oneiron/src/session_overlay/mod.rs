//! In-memory session write-overlay substrate (ARCH-0052, D1).
//!
//! The overlay is independent of the durable off-record fence machinery. It
//! owns one structurally shared keyspace per database manifest slot, typed
//! journal entries, generation-stamped read/segment leases, and the byte
//! budget that bounds live overlay rows.

mod journal;
mod keyspace;
mod overlay;
mod route;
mod short_id;
mod snapshot;

#[cfg(test)]
mod tests;

pub(crate) use self::journal::{JournalEntry, JournalRole, JournalScope, PromotePlan};
pub(crate) use self::keyspace::OverlayKeyspace;
pub(crate) use self::overlay::{SessionOverlay, TxnSegmentGuard};
pub(crate) use self::route::{RouteTarget, SessionWriteRoute};
pub(crate) use self::snapshot::{
    OverlaySnapshot, SnapshotLookup, SnapshotMergePlan, SnapshotMergeRow,
};

// The flat session_overlay.rs module used to provide these names to the test
// module through `use super::*`; after the directory split the seam re-imports
// them so the extracted sibling `tests.rs` resolves exactly as it did inline.
#[cfg(test)]
use self::keyspace::{KeyspaceState, OverlayMutation};
#[cfg(test)]
use self::overlay::{ACTIVE_SEGMENT, OverlayLifecycleState};
#[cfg(test)]
use self::short_id::{
    SESSION_SHORT_ID_SIGIL, encode_session_short_id_forward_key, session_short_id_content_hash,
};
#[cfg(test)]
use crate::batch::BatchOp;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use std::collections::BTreeSet;
#[cfg(test)]
use std::sync::Arc;
