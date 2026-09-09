//! Entity bridge: CRDT ↔ LMDB materialization observers.
//!
//! **Observer A** (`subscribe_local_update`): Fires for local commits and
//! persists update bytes to sync_state/broadcasts, except a deletion's
//! explicitly-suppressed live commit. Its authority recovery data is staged
//! first; the following TXN1 atomically persists the exact snapshot/delta.
//!
//! **Observer B** (`doc.subscribe(container_id)` × 3): Fires for all commits.
//! Subscribes to each of the three map containers (entities, edges, tombstones)
//! via the doc's container event system. Materializes key-level changes to LMDB,
//! skipping bridge-origin writes.
//!
//! Origin tracking: bridge writes use `commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN))`.
//! Observer B callbacks check the event origin and skip bridge-tagged events
//! to avoid circular LMDB→CRDT→LMDB loops.

mod app_reads;
pub use app_reads::{scoped_subscription_pending, scoped_subscription_receipts};

mod childof;
mod companion_identity;
mod edges;
mod entities;
mod observers;
mod tombstones;

// Anchor for the unchanged `super::diagnostic_ingest` body path in entities.rs:
// it resolves through this import, so the moved body stays byte-identical.
use super::diagnostic_ingest;

#[cfg(test)]
pub(in crate::sync) use self::companion_identity::INJECT_LOCAL_ENDPOINT_FAILURE;
pub(crate) use self::companion_identity::ingest_replicated_identity_topology_event_in_txn;
pub use self::companion_identity::{
    encode_edge_value_for_crdt, format_edge_key, parse_edge_key, parse_edge_value,
};
#[cfg(test)]
pub(in crate::sync) use self::entities::INJECT_BATCH_COMMIT_FAILURES;
pub use self::observers::{
    BRIDGE_ORIGIN, LiveQueryTee, MaterializedDiffSummary, Materializer, ObserverAState, OriginMark,
    OutboundSink, local_deletion_is_materialized, register_observer_a, register_observer_b,
    register_observer_b_with_tee,
};
pub(crate) use self::observers::{
    DELETION_TOMBSTONE_ORIGIN, persist_window_update, persist_window_update_in_txn,
    with_deletion_tombstone_observer_a_suppressed,
};
pub(in crate::sync) use self::tombstones::admitted_concurrent_delete_protected_header;

#[cfg(test)]
mod diagnostic_tests;
#[cfg(test)]
mod tests;

#[cfg(test)]
use self::{childof::*, edges::*, entities::*, observers::*};

// The flat bridge.rs module used to provide these names to the sibling test
// modules through `use super::*`: its own private import header. After the
// directory split the seam re-imports it under cfg(test) so `tests.rs` and
// `diagnostic_tests.rs` resolve exactly as they did before.
#[cfg(test)]
use crate::affect::Vad;
#[cfg(test)]
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
#[cfg(test)]
use crate::edge::EdgeKind;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
#[cfg(test)]
use crate::sync::loro_support::map_get_bytes;
#[cfg(test)]
use crate::sync::quarantine::{QuarantineContainer, remote_rejection_reason};
#[cfg(test)]
use crate::sync::quota;
#[cfg(test)]
use crate::{Error, Result, Vault};
#[cfg(test)]
use loro::LoroDoc;
#[cfg(test)]
use std::sync::{Arc, Mutex};
