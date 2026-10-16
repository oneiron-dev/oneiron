//! Codec for the exact consolidation cursor position.
use super::super::support::{
    KEY_LAST_LEARNED_AT, KEY_LAST_TURN_ID, KEY_SCHEMA_VERSION, WATERMARK_SCHEMA_VERSION,
    WATERMARK_SCHEMA_VERSION_V1, decode_value, encode_value, expect_key, expect_map,
    invalid_consolidation,
};
use super::ConsolidationWatermark;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use rmpv::Value;

/// Encodes a watermark row. Every emitted row is schema v2 (no bulk rewrite
/// runs: a landed v1 row upgrades on its next advance). A nil learned-at in
/// schema v2 records the before-first position, never a completed second zero.
pub(in crate::dreamer_consolidation) fn encode_watermark(
    watermark: &ConsolidationWatermark,
) -> Result<Vec<u8>> {
    if watermark.before_first
        && (watermark.last_learned_at != 0 || watermark.last_turn_id.is_some())
    {
        return Err(invalid_consolidation(
            "invalid before-first dreamer watermark",
        ));
    }
    encode_value(&Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(WATERMARK_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_LAST_LEARNED_AT),
            if watermark.before_first {
                Value::Nil
            } else {
                Value::from(watermark.last_learned_at)
            },
        ),
        (
            Value::from(KEY_LAST_TURN_ID),
            watermark
                .last_turn_id
                .map_or(Value::Nil, |id| Value::Binary(id.as_bytes().to_vec())),
        ),
    ]))
}

pub(in crate::dreamer_consolidation) fn decode_watermark(
    raw: &[u8],
) -> Result<ConsolidationWatermark> {
    let value = decode_value(raw)?;
    let entries = expect_map(&value, "dreamer watermark row must be a MessagePack map")?;
    let mut schema_version = None;
    // Outer Options track key presence; inner None means before-first for
    // learned-at, or the complete-second sentinel for turn-id.
    let mut last_learned_at: Option<Option<u64>> = None;
    let mut last_turn_id: Option<Option<EntityId>> = None;
    for (key, value) in entries {
        match expect_key(key)? {
            KEY_SCHEMA_VERSION => {
                if schema_version.is_some() {
                    return Err(duplicate_watermark_key());
                }
                schema_version = Some(expect_watermark_u64(value)?);
            }
            KEY_LAST_LEARNED_AT => {
                if last_learned_at.is_some() {
                    return Err(duplicate_watermark_key());
                }
                last_learned_at = Some(match value {
                    Value::Nil => None,
                    _ => Some(expect_watermark_u64(value)?),
                });
            }
            KEY_LAST_TURN_ID => {
                if last_turn_id.is_some() {
                    return Err(duplicate_watermark_key());
                }
                last_turn_id = Some(decode_watermark_turn_id(value)?);
            }
            _ => return Err(unpinned_watermark_key()),
        }
    }
    let schema_version =
        schema_version.ok_or(invalid_consolidation("missing dreamer watermark schema"))?;
    let last_turn_id = match schema_version {
        // A v1 row carries EXACTLY the two landed keys and means "through
        // second X": `last_turn_id` on it is as unpinned as any unknown key.
        WATERMARK_SCHEMA_VERSION_V1 => {
            if last_turn_id.is_some() {
                return Err(unpinned_watermark_key());
            }
            None
        }
        WATERMARK_SCHEMA_VERSION => last_turn_id.ok_or(invalid_consolidation(
            "missing dreamer watermark turn position",
        ))?,
        _ => {
            return Err(invalid_consolidation(
                "unsupported dreamer watermark schema",
            ));
        }
    };
    let last_learned_at = last_learned_at.ok_or(invalid_consolidation(
        "missing dreamer watermark learned_at",
    ))?;
    let before_first = last_learned_at.is_none();
    if before_first && (schema_version != WATERMARK_SCHEMA_VERSION || last_turn_id.is_some()) {
        return Err(invalid_consolidation(
            "invalid before-first dreamer watermark",
        ));
    }
    Ok(ConsolidationWatermark {
        schema_version,
        last_learned_at: last_learned_at.unwrap_or(0),
        before_first,
        last_turn_id,
    })
}

const fn duplicate_watermark_key() -> Error {
    invalid_consolidation("duplicate dreamer watermark key")
}

const fn unpinned_watermark_key() -> Error {
    invalid_consolidation("dreamer watermark key is not pinned")
}

fn expect_watermark_u64(value: &Value) -> Result<u64> {
    value.as_u64().ok_or(invalid_consolidation(
        "dreamer watermark counters must be unsigned integers",
    ))
}

/// `nil` = the end-of-second sentinel; binary = an exact 16-byte entity id.
fn decode_watermark_turn_id(value: &Value) -> Result<Option<EntityId>> {
    match value {
        Value::Nil => Ok(None),
        Value::Binary(bytes) => {
            let raw: [u8; 16] = bytes.as_slice().try_into().map_err(|_| {
                invalid_consolidation("dreamer watermark turn id must be 16 binary bytes")
            })?;
            Ok(Some(EntityId::from_bytes(raw).map_err(|_| {
                invalid_consolidation("dreamer watermark turn id is not a valid entity id")
            })?))
        }
        _ => Err(invalid_consolidation(
            "dreamer watermark turn id must be binary or nil",
        )),
    }
}
