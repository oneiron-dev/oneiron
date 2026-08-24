//! Foundational byte-layout codecs with crate-wide fan-out: the edge /
//! temporal / type index key encoders and the persisted vector row codec.

use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::*;

/// Version tag for persisted vector rows containing little-endian f16 values.
pub(crate) const VECTOR_ROW_FORMAT_F16_V1: u8 = 1;

/// Encode a vector using the canonical EMB-3 v1 row representation.
pub(crate) fn encode_vector_row_v1(vector: &[f32]) -> Result<Vec<u8>> {
    let mut row = Vec::with_capacity(1 + 2 * vector.len());
    row.push(VECTOR_ROW_FORMAT_F16_V1);
    for (index, &value) in vector.iter().enumerate() {
        let narrowed = half::f16::from_f32(value);
        // The review rider classifies an impossible persisted configuration
        // (a finite f32 that cannot be represented as finite f16) as config.
        if !value.is_finite() || !narrowed.is_finite() {
            return Err(Error::InvalidConfig(format!(
                "vector component {index} cannot be stored as finite f16: {value}"
            )));
        }
        row.extend_from_slice(&narrowed.to_bits().to_le_bytes());
    }
    Ok(row)
}

/// Decode exactly one configured persisted vector row; no prefix is accepted.
pub(crate) fn decode_vector_row_into<'a>(
    raw: &[u8],
    dimensions: usize,
    scratch: &'a mut Vec<f32>,
) -> Result<&'a [f32]> {
    let legacy_len = dimensions
        .checked_mul(4)
        .ok_or(Error::CorruptedIndex("vector row bytes"))?;
    let v1_len = dimensions
        .checked_mul(2)
        .and_then(|n| n.checked_add(1))
        .ok_or(Error::CorruptedIndex("vector row bytes"))?;

    // Length is the primary discriminator. A legacy f32 payload may begin
    // with byte 1, so inspecting the header before its exact legacy length is
    // a compatibility bug.
    if raw.len() == legacy_len {
        let (chunks, _) = raw.as_chunks::<4>();
        scratch.resize(dimensions, 0.0);
        for (slot, bytes) in scratch.iter_mut().zip(chunks) {
            *slot = f32::from_le_bytes(*bytes);
        }
        return Ok(scratch.as_slice());
    }
    if raw.len() == v1_len && raw.first() == Some(&VECTOR_ROW_FORMAT_F16_V1) {
        scratch.clear();
        scratch.reserve(dimensions);
        for bytes in raw[1..].chunks_exact(2) {
            scratch.push(half::f16::from_bits(u16::from_le_bytes([bytes[0], bytes[1]])).to_f32());
        }
        return Ok(scratch.as_slice());
    }
    Err(Error::CorruptedIndex("vector row bytes"))
}

pub(crate) fn decode_vector_row(raw: &[u8], dimensions: usize) -> Result<Vec<f32>> {
    let mut scratch = Vec::with_capacity(dimensions);
    Ok(decode_vector_row_into(raw, dimensions, &mut scratch)?.to_vec())
}

impl Store {
    /// Encodes an edge key as `[src(16) | kind(1) | tgt(16)]`.
    pub fn encode_edge_key(src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> [u8; 33] {
        let mut key = [0_u8; 33];
        key[..16].copy_from_slice(src.as_bytes());
        key[16] = kind as u8;
        key[17..].copy_from_slice(tgt.as_bytes());
        key
    }

    /// Encodes a temporal key as `[timestamp_be(8) | id(16)]`.
    pub fn encode_temporal_key(ts: u64, id: &EntityId) -> [u8; 24] {
        let mut key = [0_u8; 24];
        key[..8].copy_from_slice(&ts.to_be_bytes());
        key[8..].copy_from_slice(id.as_bytes());
        key
    }

    /// Encodes a type key as `[entity_type(1) | id(16)]`.
    pub fn encode_type_key(entity_type: u8, id: &EntityId) -> [u8; 17] {
        let mut key = [0_u8; 17];
        key[0] = entity_type;
        key[1..].copy_from_slice(id.as_bytes());
        key
    }
}
