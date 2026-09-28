//! Typed `sync_state` tables for the window/root plane rows: one window's
//! persisted CRDT snapshot, state vector, freshness flags and pending update
//! log. Shared by every sync-layer file that reads or writes them (window
//! lifecycle, observers, server-side bulk sync, the client, connection
//! handshake and the receiver-side carrier scrub) — `pub(crate)` rather than
//! narrower because the row families cross those module boundaries.
//!
//! The ARCH-0023b document families (`d:e:`, `u:e:`, `sv:e:`, `ssv:e:`,
//! `m:u_seq:e:`) are a SEPARATE keyspace (entity-scoped, not window-scoped)
//! and are out of scope here.

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
/// One durable pending CRDT update for a window (`u:w:{key}:{seq:08x}`), key
/// [`WindowUpdateKey`].
pub(crate) const WINDOW_UPDATE: SideTable<WindowUpdateKey, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_U_W);
/// Crash-safe monotonic counter allocating the next [`WINDOW_UPDATE`]
/// sequence number for one window (`m:u_seq:w:{key}`), value
/// [`WindowUpdateSeq`] (little-endian `u32`).
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

/// [`ROOT_UPDATE`]'s key: an 8-hex-digit sequence number, exactly the
/// pre-typed `u:root:{seq:08x}` spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HexSeqKey(pub(crate) u32);

impl SideKey for HexSeqKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(format!("{:08x}", self.0).as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 8 {
            return None;
        }
        let seq = u32::from_str_radix(std::str::from_utf8(bytes).ok()?, 16).ok()?;
        Some(Self(seq))
    }
}

/// Pending-tombstone marker (`pt:{window}:{entity_hex}`), value = the v2
/// tombstone wire value. `deletion::tombstone` owns the row family (see its
/// `PENDING_TOMBSTONE` doc comment: "other modules keep using
/// `pending_tombstone_key` plus their own... access") and is not reachable
/// from here, so this binds the SAME declaration independently for every
/// sync-layer reader/writer of the row (two typed tables, one declaration).
pub(crate) const PENDING_TOMBSTONE: SideTable<WindowEntityHexKey, Vec<u8>, Raw> =
    SideTable::new(&side_table::DELETION_PENDING_TOMBSTONE);

/// Key after the `pt:` prefix: a window label, `:`, then the entity's 32
/// lower-case hex characters — split from the END (fixed-width hex tail) so
/// a window label containing `:` still decodes correctly, mirroring
/// `deletion::tombstone::PendingTombstoneKey`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowEntityHexKey {
    pub(crate) window: String,
    pub(crate) id: crate::entity_id::EntityId,
}

impl SideKey for WindowEntityHexKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.window.as_bytes());
        out.push(b':');
        out.extend_from_slice(self.id.to_hex().as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let split = bytes.len().checked_sub(32)?;
        let (head, hex) = bytes.split_at(split);
        let window = head.strip_suffix(b":")?;
        Some(Self {
            window: String::from_utf8(window.to_vec()).ok()?,
            id: crate::entity_id::EntityId::from_hex(std::str::from_utf8(hex).ok()?).ok()?,
        })
    }
}

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

/// A `{window} ":" {entity_hex32}` key shape: the bytes after a window+entity
/// marker table's own prefix (the `pm:` family here; other declared window+
/// entity marker families spell the identical layout).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowEntityKey {
    pub(crate) window: String,
    pub(crate) entity: crate::entity_id::EntityId,
}

impl SideKey for WindowEntityKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.window.as_bytes());
        out.push(b':');
        out.extend_from_slice(self.entity.to_hex().as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        let (window, hex) = text.rsplit_once(':')?;
        let entity = crate::entity_id::EntityId::from_hex(hex).ok()?;
        Some(Self {
            window: window.to_owned(),
            entity,
        })
    }
}

/// [`WINDOW_UPDATE`]'s key: a window key (never itself containing `:` — the
/// `YYYY-MM` format is fixed 7 bytes) then `:` then the update's 8-hex-digit
/// sequence number, exactly the pre-typed `u:w:{key}:{seq:08x}` spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowUpdateKey {
    pub(crate) window: String,
    pub(crate) seq: u32,
}

impl SideKey for WindowUpdateKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.window.as_bytes());
        out.push(b':');
        out.extend_from_slice(format!("{:08x}", self.seq).as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        let (window, seq_hex) = text.rsplit_once(':')?;
        if seq_hex.len() != 8 {
            return None;
        }
        let seq = u32::from_str_radix(seq_hex, 16).ok()?;
        Some(Self {
            window: window.to_owned(),
            seq,
        })
    }
}

/// Verdict text carried by the corrupt-`m:u_seq:w:` row [`Error::CorruptedIndex`].
pub(crate) const ERR_WINDOW_UPDATE_SEQ_ROW: &str = "observer a u_seq row";

/// [`WINDOW_UPDATE_SEQ`]'s value: little-endian `u32`, unchanged from the
/// pre-typed layout (a present-but-malformed row is corruption, never
/// silently reset — resetting would let the next allocated seq collide with
/// an update already persisted under the pre-corruption counter).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WindowUpdateSeq(pub(crate) u32);

impl RawValue for WindowUpdateSeq {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.0.to_le_bytes().to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let bytes: [u8; 4] = bytes
            .try_into()
            .map_err(|_| Error::CorruptedIndex(ERR_WINDOW_UPDATE_SEQ_ROW))?;
        Ok(Self(u32::from_le_bytes(bytes)))
    }
}
