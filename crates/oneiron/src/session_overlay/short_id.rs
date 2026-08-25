use std::str;
use std::sync::Arc;

use xxhash_rust::xxh32::xxh32;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::keyspace::OverlayKeyspace;
use super::overlay::SessionOverlay;
use super::snapshot::SnapshotLookup;

/// Leading sigil of every session-local short id (ARCH-0052 §7).
///
/// Base short ids are `<two lowercase letters><decimal digits>`, which is
/// exactly what the short-ref parsers accept. `s` is not a legal base prefix
/// (a base prefix is always two letters), so the room namespace sits OUTSIDE
/// the base grammar and a session alias can never collide with, or mask, a
/// durable one.
pub(super) const SESSION_SHORT_ID_SIGIL: &str = "s";

impl SessionOverlay {
    /// Allocates this entity's session-local short id and content-hash byte
    /// (ARCH-0052 §7).
    ///
    /// In-room short ids are TEMPORARY PRESENTATION ALIASES. Canonical ids are
    /// allocated at promote (ONE-1730), so this counter draws from a
    /// session-scoped namespace held entirely in the overlay `ShortIds` /
    /// `ShortIdsReverse` keyspaces: the base `sid_counter:<type_byte>` rows and
    /// the base short-id tables are never read and never written, and every
    /// alias minted here evaporates at close.
    ///
    /// The alias is deliberately NOT format-compatible with a base short id.
    /// A base alias is `<two lowercase letters><decimal digits>`, and both
    /// short-ref parsers (`api/core.rs::parse_short_ref_parts`,
    /// `mcp.rs::validate_short_ref_parts`) accept exactly that shape. Minting
    /// session aliases in the same space would let a room alias collide with —
    /// and, through the composed overlay ∪ base read, MASK — a real base
    /// entity's alias for the length of the session. The `s` sigil puts the
    /// room namespace outside the base grammar, so a session alias cannot be
    /// mistaken for a durable one by any existing reader, and a caller that
    /// leaks one to a base door gets a clean parse rejection rather than a
    /// silent hit on the wrong entity.
    ///
    /// The content-hash byte uses the base scheme (`xxh32(data, 0) % 256`) so
    /// `Vault::hydrate_short_id`'s `(short_id, content_hash)` pairing behaves
    /// identically in-session.
    ///
    /// Re-allocating an id already aliased in this room returns the existing
    /// alias with a refreshed content hash, mirroring the base
    /// `plan_short_id_update` update arm: an alias is stable for the entity's
    /// lifetime in the room even as its body changes.
    pub(crate) fn alloc_session_short_id(
        self: &Arc<Self>,
        id: &EntityId,
        data: &[u8],
    ) -> Result<(String, u8)> {
        let content_hash = session_short_id_content_hash(data);
        let snapshot = self.snapshot()?;

        // An id already aliased in this room keeps its alias; only the
        // content-hash byte (part of the forward KEY) is refreshed, so the
        // stale forward row is retired first.
        if let SnapshotLookup::Present(existing) =
            snapshot.lookup_single(OverlayKeyspace::ShortIdsReverse, id.as_bytes())
        {
            let (short_id, old_content_hash) = parse_session_short_id_value(&existing)?;
            let short_id = short_id.to_owned();
            if old_content_hash != content_hash {
                self.delete_with_base_backing(
                    OverlayKeyspace::ShortIds,
                    &encode_session_short_id_forward_key(&short_id, old_content_hash),
                    false,
                )?;
            }
            self.put_session_short_id_rows(id, &short_id, content_hash)?;
            return Ok((short_id, content_hash));
        }

        // The room counter is the live alias count, read from the same
        // snapshot the allocation stages into: reverse rows are one-per-entity
        // and never deleted mid-room, so the next ordinal cannot collide with
        // an alias already minted in this segment.
        let next = snapshot
            .live_row_count(OverlayKeyspace::ShortIdsReverse, |_| true)
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("session short id counter"))?;
        let short_id = format!("{SESSION_SHORT_ID_SIGIL}{next}");
        self.put_session_short_id_rows(id, &short_id, content_hash)?;
        Ok((short_id, content_hash))
    }

    /// Stages both session short-id rows, mirroring the base pair: forward
    /// `(short_id ‖ content_hash)` -> entity id, reverse entity id -> the same
    /// bytes as the forward key.
    fn put_session_short_id_rows(
        self: &Arc<Self>,
        id: &EntityId,
        short_id: &str,
        content_hash: u8,
    ) -> Result<()> {
        let forward_key = encode_session_short_id_forward_key(short_id, content_hash);
        self.put(OverlayKeyspace::ShortIds, &forward_key, id.as_bytes())?;
        self.put(
            OverlayKeyspace::ShortIdsReverse,
            id.as_bytes(),
            &forward_key,
        )
    }
}

/// Content-hash byte for a session short id — the base scheme
/// (`xxh32(data, 0) % 256`, batch.rs `plan_short_id_update`), so
/// `hydrate_short_id`'s `(short_id, content_hash)` pairing is identical
/// in-session.
pub(super) fn session_short_id_content_hash(data: &[u8]) -> u8 {
    (xxh32(data, 0) % 256) as u8
}

/// Encodes the session `ShortIds` forward key `(short_id ‖ content_hash)`,
/// the same byte shape the base tables use — the namespaces are separated by
/// the sigil inside `short_id`, not by a second key encoding.
pub(super) fn encode_session_short_id_forward_key(short_id: &str, content_hash: u8) -> Vec<u8> {
    let mut key = Vec::with_capacity(short_id.len().saturating_add(1));
    key.extend_from_slice(short_id.as_bytes());
    key.push(content_hash);
    key
}

/// Splits a session `ShortIdsReverse` value back into `(short_id, content_hash)`.
pub(super) fn parse_session_short_id_value(value: &[u8]) -> Result<(&str, u8)> {
    let Some((&content_hash, short_id_bytes)) = value.split_last() else {
        return Err(Error::CorruptedIndex("session short id value"));
    };
    let short_id = str::from_utf8(short_id_bytes)
        .map_err(|_| Error::CorruptedIndex("session short id value"))?;
    Ok((short_id, content_hash))
}
