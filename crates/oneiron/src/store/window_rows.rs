//! Core half of `store::window_rows`: its store-layer items live in `oneiron_store::window_rows` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::window_rows::*;

use crate::error::Error;
use crate::side_table::{self, CodecError, Raw, RawValue, SideKey, SideTable};

/// A window's persisted CRDT snapshot (`d:w:{key}`).
pub(crate) const WINDOW_SNAPSHOT: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::WINDOW_SNAPSHOT);

/// A window's persisted state vector (`sv:w:{key}`).
pub(crate) const WINDOW_STATE_VECTOR: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::WINDOW_STATE_VECTOR);

/// Whether a window's persisted state vector is fresh (`svf:w:{key}`): the
/// single pinned byte `[SVF_FRESH]` or `[0]` (stale). Every reader checks
/// presence-and-content, never decodes further, so callers compare the raw
/// byte through [`SideTable::get`] directly.
pub(crate) const WINDOW_SHALLOW_FENCE: SideTable<String, [u8; 1], Raw> =
    SideTable::new(&side_table::WINDOW_SHALLOW_FENCE);

/// Durable pin forcing a window to export as a history-free snapshot
/// (`hfs:w:{key}`). Marker byte `[1]`.
pub(crate) const HISTORY_FREE_WINDOW: SideTable<String, [u8; 1], Raw> =
    SideTable::new(&side_table::SYNC_HISTORY_FREE_WINDOW);

/// A sync window needs a full resync (`fr:w:{key}`). Marker byte `[1]`.
pub(crate) const WINDOW_FULL_RESYNC_MARKER: SideTable<String, [u8; 1], Raw> =
    SideTable::new(&side_table::WINDOW_FULL_RESYNC_MARKER);

/// Device-only in-progress marker between a received BulkTransfer chunk and
/// its BulkTransferDone (`bulk:w:{key}`). Marker byte `[1]`.
pub(crate) const BULK_TRANSFER_MARKER: SideTable<String, [u8; 1], Raw> =
    SideTable::new(&side_table::SYNC_BULK_TRANSFER_MARKER);

/// One durable pending CRDT update for a window (`u:w:{key}:{seq:016x}`),
/// key [`WindowUpdateKey`].
pub(crate) const WINDOW_UPDATE: SideTable<WindowUpdateKey, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_U_W);

/// Crash-safe monotonic counter allocating the next [`WINDOW_UPDATE`]
/// sequence number for one window (`m:u_seq:w:{key}`), value
/// [`WindowUpdateSeq`] (little-endian `u64`).
pub(crate) const WINDOW_UPDATE_SEQ: SideTable<String, WindowUpdateSeq, Raw> =
    SideTable::new(&side_table::SYNC_M_U_SEQ_W);

/// The root document's full CRDT snapshot (`d:root`, server-write-only
/// `meta.windows`). Key: `()` (singleton).
pub(crate) const ROOT_SNAPSHOT: SideTable<(), Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_D_ROOT);

/// The root document's state vector, paired with [`ROOT_SNAPSHOT`]. Key: `()`.
pub(crate) const ROOT_STATE_VECTOR: SideTable<(), Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_SV_ROOT);

/// Freshness flag for the persisted root state vector. Key: `()`.
pub(crate) const ROOT_SHALLOW_FENCE: SideTable<(), [u8; 1], Raw> =
    SideTable::new(&side_table::SYNC_SVF_ROOT);

/// One durable pending CRDT update for the root document
/// (`u:root:{seq:08x}`), applied on top of [`ROOT_SNAPSHOT`] at startup;
/// read-only in this crate (written server-side).
pub(crate) const ROOT_UPDATE: SideTable<HexSeqKey, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_U_ROOT);

/// Client-only: last Unix-seconds timestamp this device reached
/// fully-synced status (`m:last_sync`, u64 LE). Key: `()`.
pub(crate) const LAST_SYNC: SideTable<(), [u8; 8], Raw> =
    SideTable::new(&side_table::SYNC_M_LAST_SYNC);

/// Pending-tombstone marker (`pt:{window}:{entity_hex}`), value = the v2
/// tombstone wire value. `deletion::tombstone` owns the row family and reads
/// and writes it through its own `PENDING_TOMBSTONE`, which is not reachable
/// from here. Other readers go through the window deletion-row port, or this
/// table: the sync layer's own binding of the SAME declaration for every
/// sync-layer reader/writer of the row (two typed tables, one declaration).
pub(crate) const PENDING_TOMBSTONE: SideTable<WindowEntityHexKey, Vec<u8>, Raw> =
    SideTable::new(&side_table::DELETION_PENDING_TOMBSTONE);

/// Queued tombstone re-assertion marker (`ra:w:{window}:{entity_hex}`),
/// value = the exact `dt:` tombstone value bytes to re-assert.
pub(crate) const REASSERT_MARKER: SideTable<WindowEntityHexKey, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_REASSERT_MARKER);

/// Needs-rematerialization marker (`rm:w:{window}:{entity_hex}`). Marker
/// byte `[1]`.
pub(crate) const REMAT_MARKER: SideTable<WindowEntityHexKey, [u8; 1], Raw> =
    SideTable::new(&side_table::SYNC_REMAT_MARKER);

/// Sidecar on a [`REMAT_MARKER`] proving replay/quarantine origin
/// (`rmp:w:{window}:{entity_hex}`). Marker byte `[1]`.
pub(crate) const REPLAY_REMAT_MARKER_PROVENANCE: SideTable<WindowEntityHexKey, [u8; 1], Raw> =
    SideTable::new(&side_table::SYNC_REPLAY_REMAT_MARKER_PROVENANCE);

/// A window-scoped (no entity segment) `rm:w:{window}` marker — the
/// defensive/forward-looking whole-window flag `WindowManager::open_window`
/// checks (producer lands in M4-04; current producers all write the
/// entity-scoped [`REMAT_MARKER`] shape instead). Same declaration as
/// [`REMAT_MARKER`], a different key shape ("two typed tables, one
/// declaration" — the umbrella-family pattern).
pub(crate) const REMAT_WINDOW_MARKER: SideTable<String, [u8; 1], Raw> =
    SideTable::new(&side_table::SYNC_REMAT_MARKER);

/// Deduplicated marker recording which window a promoted turn's replayed
/// closure spans (`pm:{window}:{entity_hex}`), key [`WindowEntityKey`].
/// Marker byte `[1]`.
pub(crate) const OFF_RECORD_PROMOTE_PICKUP: SideTable<WindowEntityKey, [u8; 1], Raw> =
    SideTable::new(&side_table::OFF_RECORD_PROMOTE_PICKUP_MARKER);
