#![cfg_attr(not(test), allow(dead_code))]

use std::collections::HashMap;
use std::io::Cursor;

use heed::RoTxn;
use rmpv::Value;

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::error::Result;
use crate::store::Store;
use crate::types::{EntityId, ScoredEntity};

pub(crate) fn sort_scored_entities_desc(scores: &mut [ScoredEntity]) {
    scores.sort_unstable_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.id.as_bytes().cmp(b.id.as_bytes()))
    });
}

pub(crate) fn rrf_fuse(ranked_lists: &[Vec<ScoredEntity>], k: f32) -> Vec<ScoredEntity> {
    let mut fused = HashMap::<EntityId, f32>::new();

    for ranked in ranked_lists {
        for (rank, scored) in ranked.iter().enumerate() {
            let contribution = 1.0 / (k + rank as f32 + 1.0);
            *fused.entry(scored.id).or_insert(0.0) += contribution;
        }
    }

    let mut out: Vec<ScoredEntity> = fused
        .into_iter()
        .map(|(id, score)| ScoredEntity { id, score })
        .collect();
    sort_scored_entities_desc(&mut out);
    out
}

pub(crate) fn boost_salience(
    scores: &mut [ScoredEntity],
    store: &Store,
    rtxn: &RoTxn<'_>,
) -> Result<()> {
    for scored in scores {
        let Some(raw) = store.entities.get(rtxn, scored.id.as_bytes())? else {
            continue;
        };

        let Some(salience) = decode_msgpack_float(raw, "salience") else {
            continue;
        };

        scored.score *= 1.0 + salience;
    }

    Ok(())
}

pub(crate) fn boost_confidence(
    scores: &mut [ScoredEntity],
    store: &Store,
    rtxn: &RoTxn<'_>,
) -> Result<()> {
    for scored in scores {
        let Some(raw) = store.entities.get(rtxn, scored.id.as_bytes())? else {
            continue;
        };

        let Some(confidence) = decode_msgpack_float(raw, "confidence") else {
            continue;
        };

        scored.score *= 0.5 + 0.5 * confidence;
    }

    Ok(())
}

fn decode_msgpack_float(raw: &[u8], field: &str) -> Option<f32> {
    if raw.len() <= ENTITY_METADATA_HEADER_LEN {
        return None;
    }

    let mut cursor = Cursor::new(&raw[ENTITY_METADATA_HEADER_LEN..]);
    let value = rmpv::decode::read_value(&mut cursor).ok()?;
    let Value::Map(entries) = value else {
        return None;
    };

    for (key, value) in entries {
        if key.as_str()? != field {
            continue;
        }

        return decode_numeric_value(value);
    }

    None
}

fn decode_numeric_value(value: Value) -> Option<f32> {
    let parsed = match value {
        Value::F32(v) => v,
        Value::F64(v) => v as f32,
        Value::Integer(v) => {
            if let Some(i) = v.as_i64() {
                i as f32
            } else if let Some(u) = v.as_u64() {
                u as f32
            } else {
                return None;
            }
        }
        _ => return None,
    };

    if !parsed.is_finite() {
        return None;
    }
    Some(parsed.clamp(0.0, 1.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scored(id: [u8; 16], score: f32) -> ScoredEntity {
        ScoredEntity {
            id: EntityId::from_bytes_unchecked(id),
            score,
        }
    }

    #[test]
    fn rrf_single_list() {
        let list = vec![scored([1; 16], 10.0), scored([2; 16], 9.0)];
        let fused = rrf_fuse(&[list], 60.0);

        assert_eq!(fused.len(), 2);
        assert!((fused[0].score - (1.0 / 61.0)).abs() < 1e-6);
        assert!((fused[1].score - (1.0 / 62.0)).abs() < 1e-6);
    }

    #[test]
    fn rrf_two_lists_overlap() {
        let a = vec![scored([1; 16], 1.0), scored([2; 16], 1.0)];
        let b = vec![scored([2; 16], 1.0), scored([1; 16], 1.0)];

        let fused = rrf_fuse(&[a, b], 60.0);
        assert_eq!(fused.len(), 2);

        let first = fused
            .iter()
            .find(|entry| entry.id == EntityId::from_bytes_unchecked([1; 16]))
            .expect("missing entity 1");
        let second = fused
            .iter()
            .find(|entry| entry.id == EntityId::from_bytes_unchecked([2; 16]))
            .expect("missing entity 2");

        let expected_1 = 1.0 / 61.0 + 1.0 / 62.0;
        let expected_2 = 1.0 / 62.0 + 1.0 / 61.0;
        assert!((first.score - expected_1).abs() < 1e-6);
        assert!((second.score - expected_2).abs() < 1e-6);
    }

    #[test]
    fn rrf_empty_lists() {
        let fused = rrf_fuse(&[Vec::new(), Vec::new()], 60.0);
        assert!(fused.is_empty());
    }

    #[test]
    fn rrf_missing_entities() {
        let a = vec![scored([1; 16], 1.0)];
        let b = vec![scored([2; 16], 1.0)];

        let fused = rrf_fuse(&[a, b], 60.0);
        assert_eq!(fused.len(), 2);
        assert!((fused[0].score - (1.0 / 61.0)).abs() < 1e-6);
        assert!((fused[1].score - (1.0 / 61.0)).abs() < 1e-6);
    }
}
