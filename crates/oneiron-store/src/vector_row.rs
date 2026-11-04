//! The persisted vector row codec (EMB-3 v1): little-endian f16 components
//! behind a one-byte format tag.

use oneiron_contracts::error::{Error, Result};

/// Version tag for persisted vector rows containing little-endian f16 values.
pub const VECTOR_ROW_FORMAT_F16_V1: u8 = 1;

/// Encode a vector using the canonical EMB-3 v1 row representation.
pub fn encode_vector_row_v1(vector: &[f32]) -> Result<Vec<u8>> {
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
pub fn decode_vector_row_into<'a>(
    raw: &[u8],
    dimensions: usize,
    scratch: &'a mut Vec<f32>,
) -> Result<&'a [f32]> {
    let v1_len = dimensions
        .checked_mul(2)
        .and_then(|n| n.checked_add(1))
        .ok_or(Error::CorruptedIndex("vector row bytes"))?;

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

/// Decode exactly one configured persisted vector row into a new vector.
pub fn decode_vector_row(raw: &[u8], dimensions: usize) -> Result<Vec<f32>> {
    let mut scratch = Vec::with_capacity(dimensions);
    Ok(decode_vector_row_into(raw, dimensions, &mut scratch)?.to_vec())
}
