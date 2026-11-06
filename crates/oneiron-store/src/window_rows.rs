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

use crate::side_table::codec::CodecError;
use crate::side_table::codec::RawValue;
use crate::side_table::key::SideKey;
use oneiron_base::error::Error;

/// [`ROOT_UPDATE`]'s key: an 8-hex-digit sequence number, exactly the
/// pre-typed `u:root:{seq:08x}` spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HexSeqKey(pub u32);

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

/// Key after the `pt:` prefix: a window label, `:`, then the entity's 32
/// lower-case hex characters — split from the END (fixed-width hex tail) so
/// a window label containing `:` still decodes correctly, mirroring
/// `deletion::tombstone::PendingTombstoneKey`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowEntityHexKey {
    pub window: String,
    pub id: oneiron_contracts::entity_id::EntityId,
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
            id: oneiron_contracts::entity_id::EntityId::from_hex(std::str::from_utf8(hex).ok()?)
                .ok()?,
        })
    }
}

/// A `{window} ":" {entity_hex32}` key shape: the bytes after a window+entity
/// marker table's own prefix (the `pm:` family here; other declared window+
/// entity marker families spell the identical layout).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowEntityKey {
    pub window: String,
    pub entity: oneiron_contracts::entity_id::EntityId,
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
        let entity = oneiron_contracts::entity_id::EntityId::from_hex(hex).ok()?;
        Some(Self {
            window: window.to_owned(),
            entity,
        })
    }
}

/// [`WINDOW_UPDATE`]'s key: a window key (never itself containing `:` — the
/// `YYYY-MM` format is fixed 7 bytes) then `:` then the update's 16-hex-digit
/// sequence number (`u:w:{key}:{seq:016x}`). The fixed width keeps the byte
/// order of the keys the sequence order (FIX 8883).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowUpdateKey {
    pub window: String,
    pub seq: u64,
}

impl SideKey for WindowUpdateKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.window.as_bytes());
        out.push(b':');
        out.extend_from_slice(format!("{:016x}", self.seq).as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        let (window, seq_hex) = text.rsplit_once(':')?;
        if seq_hex.len() != 16 {
            return None;
        }
        let seq = u64::from_str_radix(seq_hex, 16).ok()?;
        Some(Self {
            window: window.to_owned(),
            seq,
        })
    }
}

/// Verdict text carried by the corrupt-`m:u_seq:w:` row [`Error::CorruptedIndex`].
pub const ERR_WINDOW_UPDATE_SEQ_ROW: &str = "observer a u_seq row";

/// [`WINDOW_UPDATE_SEQ`]'s value: little-endian `u64`, so a window never
/// runs out of sequence numbers (FIX 8883). A present-but-malformed row is
/// corruption, never silently reset — resetting would let the next allocated
/// seq collide with an update already persisted under the pre-corruption
/// counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowUpdateSeq(pub u64);

impl RawValue for WindowUpdateSeq {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.0.to_le_bytes().to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let bytes: [u8; 8] = bytes
            .try_into()
            .map_err(|_| Error::CorruptedIndex(ERR_WINDOW_UPDATE_SEQ_ROW))?;
        Ok(Self(u64::from_le_bytes(bytes)))
    }
}

/// Each local path that removes the window carrier of an id deleted here.
/// Every one marks through [`mark_removed_carriers_first`], naming itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CarrierRemoval {
    /// The boot replay of `pt:` markers.
    PendingTombstoneReplay,
    /// The `ra:` drain, live and transient.
    ReassertDrain,
    /// The egress scrub of a carrier whose tombstone a peer withdrew.
    WithdrawnDeleteScrub,
    /// The egress scrub of the carriers at an id whose stored row is a CLAIM
    /// held back from sync, such as a soft-deleted CLAIM's shell.
    LocalClaimScrub,
    /// The local delete's tombstone publication, live and transient.
    LocalPublication,
    /// The sweep's compaction of a hard-erased id's residue.
    HardEraseSweep,
    /// A canonical window capture, which leaves a deleted id's carrier out
    /// of the artifact or keeps only its shell.
    CanonicalCapture,
}

impl CarrierRemoval {
    /// Every path, for the check that each marks before it removes.
    #[cfg(any(test, feature = "test-support"))]
    pub const ALL: [Self; 7] = [
        Self::PendingTombstoneReplay,
        Self::ReassertDrain,
        Self::WithdrawnDeleteScrub,
        Self::LocalClaimScrub,
        Self::LocalPublication,
        Self::HardEraseSweep,
        Self::CanonicalCapture,
    ];
}
