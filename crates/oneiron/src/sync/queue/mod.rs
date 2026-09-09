//! Persistent offline queue backed by LMDB.
//!
//! Stores pending sync updates, embed jobs, and hard-delete sweep jobs in the
//! `sync_queue` database (#25).
//! Updates are keyed by monotonic sequence number for ordered replay.
//!
//! Key format (per ARCH-023b §5.4):
//! - `q:{seq:8BE}` → `[window_key_len:1][window_key][encoded_update]`
//! - `e:{entity_id:16}` → `[priority:1][queued_at:8BE]`
//! - `h:{seq:8BE}` → ARCH-0038 hard-delete historical-carrier sweep job
//! - `d:{seq:8BE}` → `[1]` — engine-internal DELETE-BEARING sidecar marker
//!   (ONE-1135): the matching `q:{seq}` row carries a tombstone-commit
//!   delta. Delete-bearing rows are EXEMPT from every optimistic clear
//!   (`clear_through` / `clear_updates` / `clear_all`) and are removed only
//!   by [`SyncQueue::clear_through_confirmed`] once the server VV confirms
//!   receipt (protocol lands in M4-12). Losing one would silently lose a
//!   GDPR delete on an unconfirmed reconnect — fail-closed: keep until
//!   confirmed.
//!
//!   Constructed ONLY by the tombstone-commit path: `push_delete_bearing_in_txn`
//!   takes a `DeleteBearingUpdate`, whose single constructor is
//!   `export_tombstone_commit_delta`
//!   — arbitrary payloads can never acquire the marker and its clear/scrub
//!   exemptions (ONE-1135 review item 14). Invariant: a `d:{seq}` marker
//!   never outlives its `q:{seq}` row — the malformed-row prune drops both
//!   in the same txn, and sequence recovery treats any surviving (orphan)
//!   marker's seq as allocated so it is never reused (ONE-1135 review
//!   item 15).

use crate::Vault;
use crate::entity_id::EntityId;
use std::sync::Arc;

/// Maximum number of queue entries before triggering re-bootstrap.
const MAX_QUEUE_SIZE: usize = 10_000;

/// Prefix for update queue entries.
const UPDATE_PREFIX: &[u8] = b"q:";
/// Prefix for embed job entries.
const EMBED_PREFIX: &[u8] = b"e:";
/// Prefix for delete-bearing sidecar markers (ONE-1135).
const DELETE_BEARING_PREFIX: &[u8] = b"d:";
/// Metadata key storing the last allocated update sequence number.
const LAST_UPDATE_SEQ_KEY: &[u8] = b"m:last_update_seq";
const ERR_SYNC_QUEUE_UPDATE_ROW: &str = "sync queue update row";
const ERR_SYNC_QUEUE_EMBED_ROW: &str = "sync queue embed row";

/// A queued update ready for replay on reconnect.
#[derive(Debug)]
pub struct QueuedUpdate {
    /// Sequence number for ordering.
    pub seq: u64,
    /// Window key (YYYY-MM format).
    pub window_key: String,
    /// Raw CRDT update bytes (will be wire-encoded during replay via `encode_window_sync`).
    pub encoded: Vec<u8>,
}

/// A queued embed job for background processing.
#[derive(Debug)]
pub struct QueuedEmbedJob {
    /// Entity requiring embedding.
    pub entity_id: EntityId,
    /// Priority (`0` surfaced-hot, `1` server, `2` device, `3` backfill).
    pub priority: u8,
    /// When the job was queued (Unix ms).
    pub queued_at: u64,
}

/// Persistent offline queue backed by LMDB `sync_queue` database.
///
/// LMDB serializes writers and the queue relies on monotonic `u64` sequence
/// numbers in metadata for ordering. `drain_updates`, `drain_embed_jobs`,
/// and `clear_through` drop their read txn before opening a fresh write
/// txn for the prune/metadata step — concurrent writers between the two
/// txns would race. Under the single-sync-client design (one `SyncClient`
/// per `Vault`) this is benign. If multi-writer semantics are ever
/// required, collapse read-then-prune into a single write txn.
pub struct SyncQueue {
    vault: Arc<Vault>,
}

mod codec;
mod core;
mod scrub;
mod seq;

pub(in crate::sync) use self::scrub::scrub_receiver_outbox_on_remote_hard_delete_in_txn;
pub(crate) use self::scrub::scrub_window_updates_in_txn;
pub(crate) use self::seq::{
    delete_embed_job_in_txn, push_delete_bearing_in_txn, push_embed_job_in_txn,
};

#[cfg(test)]
mod tests;

// Private test seam: sibling tests reach these through `use super::*`.
#[cfg(test)]
use self::codec::{
    decode_embed_job_row, decode_embed_key, decode_last_update_seq_metadata, decode_update_key,
    encode_delete_bearing_key, encode_embed_key, encode_update_key, encode_update_value,
};

#[cfg(test)]
thread_local! {
    static INJECT_RECEIVER_SCRUB_FAILURES: std::cell::Cell<u32> =
        const { std::cell::Cell::new(0) };
}
#[cfg(test)]
use crate::error::Error;
#[cfg(test)]
use crate::sync::transport::MAX_WINDOW_KEY_LEN;
