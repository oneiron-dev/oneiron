//! Affect-weighted retrieval availability (OF-423; ARCH-0034 `scour:A53`,
//! eiri pick A66).
//!
//! Three read-side stages over Dreamer-written claim-VAD, all under one
//! per-vault [`AffectRetrievalPolicy`] whose every dial defaults off:
//!
//! - **Arousal availability.** A live claim's read-side aging half-life is
//!   stretched by its stored arousal, so an intense memory stays available
//!   longer than a routine one of the same age. Aging stays exponential
//!   (OF-099 ruling A); only its half-life moves.
//! - **Sensitivity floor.** A live claim whose predicate is critical, or
//!   whose stored arousal reaches the policy's floor arousal, keeps at least
//!   the policy's availability floor, so neither starves under aging.
//! - **Emotion congruence.** With a query VAD (the caller's, or the bound
//!   retrieval turn's annotation), a candidate's score is tilted by how close
//!   its stored VAD sits to the query's: a claim's consolidated VAD, or a
//!   TURN's or MESSAGE's own annotation.
//!
//! All three touch the surfacing multiplier only. Confidence, salience and
//! stored bytes stay exactly as written: availability is never decayed truth.

use std::collections::HashMap;

use heed::RoTxn;
use rmpv::Value;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimLifecycleStatus, ClaimRetrievability, ClaimSubject};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::store::StoreRead;
use crate::write_envelope::vad_annotation::VAD_ANNOTATION_CLAIM_PREDICATE;
use oneiron_contracts::affect::Vad;

use super::types::{EntityMetadataCache, ScoredEntity};

pub use crate::config::retrieval_affect::{
    AFFECT_AROUSAL_STRETCH_MAX, AFFECT_EMOTION_WEIGHT_MAX, AFFECT_FLOOR_AROUSAL_DEFAULT,
    AffectRetrievalPolicy,
};

/// A claim's active consolidated VAD: the `affect.claim_vad` state claim the
/// Dreamer writes about it, read under the run's snapshot. `None` when the
/// claim has no active state or its value does not decode to a valid VAD —
/// unknown affect stays unknown, never invented.
pub(super) fn stored_claim_vad(
    store: &StoreRead<'_>,
    rtxn: &RoTxn<'_>,
    claim_id: &EntityId,
) -> Result<Option<Vad>> {
    let rows = store.port_edges(
        rtxn,
        claim_id,
        EdgeDirection::In,
        Some(EdgeKind::ClaimOf),
        None,
    )?;
    for row in rows {
        let state_id = row?.target;
        let Some(raw) = store
            .port_entity_record(rtxn, &state_id)?
            .map(|row| row.encode())
        else {
            continue;
        };
        if EntityMetadataHeader::parse(&raw).map(|header| header.entity_type)
            != Some(ENTITY_TYPE_CLAIM)
        {
            continue;
        }
        let Some(body) = raw
            .get(ENTITY_METADATA_HEADER_LEN..)
            .and_then(|bytes| crate::claim::decode_claim_body(bytes, true).ok())
        else {
            continue;
        };
        if body.predicate != crate::write_envelope::claim_vad::CLAIM_VAD_REAPPRAISAL_PREDICATE
            || body.subject != ClaimSubject::Entity(*claim_id)
            || body.lifecycle != ClaimLifecycleStatus::Active
        {
            continue;
        }
        if let Some(vad) = decode_claim_vad_value(&body.value) {
            return Ok(Some(vad));
        }
    }
    Ok(None)
}

/// A candidate's stored VAD under the run's snapshot: a CLAIM's consolidated
/// state ([`stored_claim_vad`]), or a TURN's or MESSAGE's active `affect.vad`
/// annotation. `None` for any other kind, or when none is active and valid.
pub(super) fn stored_candidate_vad(
    store: &StoreRead<'_>,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
) -> Result<Option<Vad>> {
    if entity_type == ENTITY_TYPE_CLAIM {
        return stored_claim_vad(store, rtxn, id);
    }
    if entity_type != ENTITY_TYPE_TURN && entity_type != ENTITY_TYPE_MESSAGE {
        return Ok(None);
    }
    let claim_id = crate::write_envelope::vad_annotation::vad_annotation_claim_id(entity_type, id)?;
    let Some(raw) = store
        .port_entity_record(rtxn, &claim_id)?
        .map(|row| row.encode())
    else {
        return Ok(None);
    };
    if EntityMetadataHeader::parse(&raw).map(|header| header.entity_type) != Some(ENTITY_TYPE_CLAIM)
    {
        return Ok(None);
    }
    let Some(body) = raw
        .get(ENTITY_METADATA_HEADER_LEN..)
        .and_then(|bytes| crate::claim::decode_claim_body(bytes, true).ok())
    else {
        return Ok(None);
    };
    if body.predicate != VAD_ANNOTATION_CLAIM_PREDICATE
        || body.subject != ClaimSubject::Entity(*id)
        || body.lifecycle != ClaimLifecycleStatus::Active
    {
        return Ok(None);
    }
    Ok(decode_claim_vad_value(&body.value))
}

fn decode_claim_vad_value(value: &Value) -> Option<Vad> {
    let Value::Map(entries) = value else {
        return None;
    };
    let field = |name: &str| {
        entries
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .and_then(|(_, value)| value.as_f64())
            .map(|value| value as f32)
    };
    let vad = Vad {
        valence: field("valence")?,
        arousal: field("arousal")?,
        dominance: field("dominance")?,
    };
    vad.validate().ok().map(|()| vad)
}

/// The read-side factor of one live claim under `policy`, from the factor
/// [`crate::claim::claim_access_factor`] derived without an override.
///
/// A closed claim's zero stays zero. The arousal stretch re-ages the claim
/// on its own class policy with a longer half-life and scales the derived
/// factor by that ratio, so the class floor and any standalone weight carry
/// through unchanged. The sensitivity floor then holds a critical or aroused
/// claim at the policy floor.
pub(super) fn affect_access_factor(
    policy: &AffectRetrievalPolicy,
    derived: ClaimRetrievability,
    aging: crate::claim::AccessFactorPolicy,
    learned_at: u64,
    now: u64,
    arousal: Option<f32>,
    critical: bool,
) -> f32 {
    let mut factor = derived.access_factor;
    if factor <= 0.0 {
        return factor;
    }
    if policy.arousal_stretch > 0.0
        && let Some(arousal) = arousal.filter(|arousal| *arousal > 0.0)
    {
        let age_secs = now.saturating_sub(learned_at) as f64;
        let floor = f64::from(aging.floor);
        let plain = 2.0_f64.powf(-age_secs / aging.half_life_secs).max(floor);
        let stretch = 1.0 + f64::from(policy.arousal_stretch) * f64::from(arousal);
        let stretched = 2.0_f64
            .powf(-age_secs / (aging.half_life_secs * stretch))
            .max(floor);
        factor = (f64::from(factor) * stretched / plain).min(1.0) as f32;
    }
    if let Some(floor) = policy.availability_floor
        && (critical || arousal.is_some_and(|arousal| arousal >= policy.floor_arousal))
    {
        factor = factor.max(floor);
    }
    factor
}

/// Similarity of a stored VAD to the query's in `0..=1`: one minus the mean
/// squared per-axis distance, valence's double-width axis halved first (the
/// same measure as [`crate::rerank::EmotionSimilarityReranker`]).
fn emotion_similarity(stored: Vad, query: Vad) -> f32 {
    let dv = (stored.valence - query.valence) / 2.0;
    let da = stored.arousal - query.arousal;
    let dd = stored.dominance - query.dominance;
    (1.0 - (dv * dv + da * da + dd * dd) / 3.0).clamp(0.0, 1.0)
}

/// Each scored candidate's emotion-congruence multiplier
/// `1 + weight × (2 × similarity − 1)`, in `1 − weight ..= 1 + weight`.
/// Rows without stored VAD ([`stored_candidate_vad`]) are absent: they keep
/// their score.
pub(super) fn emotion_congruence_multipliers(
    scores: &[ScoredEntity],
    query: Vad,
    weight: f32,
    store: &StoreRead<'_>,
    rtxn: &RoTxn<'_>,
    metadata_cache: &mut EntityMetadataCache,
) -> Result<HashMap<EntityId, f32>> {
    let mut multipliers = HashMap::new();
    for scored in scores {
        let Some(meta) = metadata_cache.get(store, rtxn, &scored.id)? else {
            continue;
        };
        if let Some(stored) = stored_candidate_vad(store, rtxn, &scored.id, meta.entity_type)? {
            let similarity = emotion_similarity(stored, query);
            multipliers.insert(scored.id, 1.0 + weight * (2.0 * similarity - 1.0));
        }
    }
    Ok(multipliers)
}

/// Multiplies each row present in `multipliers`; other rows keep their score.
pub(super) fn apply_score_multipliers(
    scores: &mut [ScoredEntity],
    multipliers: &HashMap<EntityId, f32>,
) {
    for scored in scores {
        if let Some(multiplier) = multipliers.get(&scored.id) {
            scored.score *= multiplier;
        }
    }
}
