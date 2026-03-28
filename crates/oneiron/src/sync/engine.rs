//! CRDT engine trait abstraction for the sync layer.
//!
//! Defines engine-agnostic interfaces that `bridge`, `window`, `schema`,
//! and `client` modules program against. The concrete implementation
//! (`loro_engine`) is selected at compile time via the `sync` feature.

use std::sync::Arc;

use crate::error::Result;

/// Callback type for subscribing to locally-generated CRDT updates.
/// Return `false` from the callback to auto-unsubscribe.
pub type LocalUpdateCallback = Box<dyn Fn(&[u8]) -> bool + Send + Sync>;

// ─── Map Change Events ──────────────────────────────────────────────────────

/// A single key-level change inside a CRDT map.
#[derive(Debug)]
pub enum MapChange {
    Inserted {
        key: String,
        value: Vec<u8>,
    },
    Updated {
        key: String,
        old_value: Vec<u8>,
        new_value: Vec<u8>,
    },
    Removed {
        key: String,
        old_value: Vec<u8>,
    },
}

// ─── Subscription Handle ────────────────────────────────────────────────────

/// Opaque subscription handle — the observer fires as long as this lives.
/// The inner value is never read; dropping it unsubscribes the observer.
pub struct Subscription(#[allow(dead_code)] pub(crate) Box<dyn std::any::Any + Send + Sync>);

impl Subscription {
    pub fn new(inner: impl std::any::Any + Send + Sync + 'static) -> Self {
        Self(Box::new(inner))
    }
}

// ─── CrdtMap ────────────────────────────────────────────────────────────────

/// Engine-agnostic CRDT map (LWW semantics).
///
/// All values are binary blobs — the sync layer serialises entities,
/// edges, and tombstones into `Vec<u8>` before storing.
pub trait CrdtMap: Send + Sync {
    /// Insert (or overwrite) a binary value at `key`.
    fn insert(&self, key: &str, value: &[u8]) -> Result<()>;

    /// Get the binary value at `key`, if present.
    fn get(&self, key: &str) -> Option<Vec<u8>>;

    /// Delete the entry at `key`.
    fn remove(&self, key: &str) -> Result<()>;

    /// Whether the map contains `key`.
    fn contains_key(&self, key: &str) -> bool;

    /// Iterate over all entries as `(key, value)` pairs.
    fn for_each(&self, f: &mut dyn FnMut(&str, &[u8]));

    /// Subscribe to key-level changes. The callback receives a batch of
    /// changes after each commit.
    fn subscribe_changes(&self, cb: Arc<dyn Fn(Vec<MapChange>) + Send + Sync>) -> Subscription;
}

// ─── CrdtDoc ────────────────────────────────────────────────────────────────

/// Engine-agnostic CRDT document.
///
/// A document owns zero or more named maps. It supports snapshot-based
/// and delta-based sync, local-update observation, and persistence.
pub trait CrdtDoc: Send + Sync + 'static {
    type Map: CrdtMap;

    /// Create an empty document.
    fn new() -> Self;

    /// Get (or lazily create) a named root-level map.
    fn get_or_create_map(&self, name: &str) -> Self::Map;

    // ── Sync operations ─────────────────────────────────────────────────

    /// Export all updates from the beginning of time.
    fn export_all_updates(&self) -> Result<Vec<u8>>;

    /// Export only the updates that `remote_vv` does not yet have.
    fn export_updates_since(&self, remote_vv: &[u8]) -> Result<Vec<u8>>;

    /// Export a full snapshot (state + history).
    fn export_snapshot(&self) -> Result<Vec<u8>>;

    /// Import updates or a snapshot produced by `export_*`.
    fn import(&self, bytes: &[u8]) -> Result<()>;

    /// Return the current version vector, encoded to bytes.
    fn version_vector(&self) -> Vec<u8>;

    // ── Commit / origin ─────────────────────────────────────────────────

    /// Commit pending operations. Loro requires an explicit commit to fire
    /// events.
    fn commit(&self);

    /// Commit pending operations, tagging them with an origin string.
    /// The origin can be inspected in event callbacks to distinguish
    /// local bridge writes from remote/user writes.
    fn commit_with_origin(&self, origin: &str);

    // ── Persistence ─────────────────────────────────────────────────────

    /// Encode the full document state as bytes (equivalent to snapshot).
    fn encode_full_state(&self) -> Result<Vec<u8>>;

    /// Reconstruct a document from a snapshot previously produced by
    /// `encode_full_state` or `export_snapshot`.
    fn from_snapshot(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;

    // ── Observation ─────────────────────────────────────────────────────

    /// Subscribe to locally-generated updates. The callback receives
    /// encoded update bytes after each commit. Return `false` from the
    /// callback to auto-unsubscribe.
    fn subscribe_local_updates(&self, cb: LocalUpdateCallback) -> Subscription;
}
