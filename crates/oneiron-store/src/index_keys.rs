//! Byte layouts of the edge, temporal and type index keys. `oneiron`'s
//! `Store::encode_edge_key`, `Store::encode_temporal_key` and
//! `Store::encode_type_key` return exactly these.

use oneiron_base::edge::EdgeKind;
use oneiron_contracts::entity_id::EntityId;

/// Encodes an edge key as `[src(16) | kind(1) | tgt(16)]`.
#[inline]
#[must_use]
pub fn encode_edge_key(src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> [u8; 33] {
    let mut key = [0_u8; 33];
    key[..16].copy_from_slice(src.as_bytes());
    key[16] = kind as u8;
    key[17..].copy_from_slice(tgt.as_bytes());
    key
}

/// Encodes a temporal key as `[timestamp_be(8) | id(16)]`.
#[inline]
#[must_use]
pub fn encode_temporal_key(ts: u64, id: &EntityId) -> [u8; 24] {
    let mut key = [0_u8; 24];
    key[..8].copy_from_slice(&ts.to_be_bytes());
    key[8..].copy_from_slice(id.as_bytes());
    key
}

/// Encodes a type key as `[entity_type(1) | id(16)]`.
#[inline]
#[must_use]
pub fn encode_type_key(entity_type: u8, id: &EntityId) -> [u8; 17] {
    let mut key = [0_u8; 17];
    key[0] = entity_type;
    key[1..].copy_from_slice(id.as_bytes());
    key
}
