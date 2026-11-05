//! Foundational byte-layout codecs with crate-wide fan-out: the edge /
//! temporal / type index key encoders, and the persisted vector row codec
//! (defined in `oneiron_store::vector_row`).

use crate::edge::EdgeKind;
use crate::entity_id::EntityId;

use super::*;

#[cfg(test)]
pub(crate) use oneiron_store::vector_row::VECTOR_ROW_FORMAT_F16_V1;
pub(crate) use oneiron_store::vector_row::{
    decode_vector_row, decode_vector_row_into, encode_vector_row_v1,
};

impl Store {
    /// Encodes an edge key as `[src(16) | kind(1) | tgt(16)]`.
    pub fn encode_edge_key(src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> [u8; 33] {
        oneiron_store::index_keys::encode_edge_key(src, kind, tgt)
    }

    /// Encodes a temporal key as `[timestamp_be(8) | id(16)]`.
    pub fn encode_temporal_key(ts: u64, id: &EntityId) -> [u8; 24] {
        oneiron_store::index_keys::encode_temporal_key(ts, id)
    }

    /// Encodes a type key as `[entity_type(1) | id(16)]`.
    pub fn encode_type_key(entity_type: u8, id: &EntityId) -> [u8; 17] {
        oneiron_store::index_keys::encode_type_key(entity_type, id)
    }
}
