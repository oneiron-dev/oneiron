use std::str;

use heed::RwTxn;
use rmpv::Value;

use crate::affect::Vad;
use crate::claim::ClaimSubject;
use crate::edge::{DecodedEdgeValue, EdgeProvenanceFlags};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::write_envelope::ClaimCandidate;

pub(crate) const ENTITY_TYPE_OFFSET: usize = 0;
pub(crate) const ENTITY_OCCURRED_START_OFFSET: usize = 1;
pub(crate) const ENTITY_OCCURRED_END_OFFSET: usize = 9;
pub(crate) const ENTITY_LEARNED_AT_OFFSET: usize = 17;
pub(crate) const ENTITY_BODY_OFFSET: usize = 25;
pub(crate) const ENTITY_METADATA_HEADER_LEN: usize = ENTITY_BODY_OFFSET;
pub(crate) const LONG_INTERVAL_THRESHOLD_SECS: u64 = 14 * 86_400;
pub(super) const ERR_RAW_CLAIM_PUT_REQUIRES_ENVELOPE: &str = "raw claim put requires WriteEnvelope";
pub(super) const ERR_RAW_NOTE_PUT_REQUIRES_AUTHOR_TAKE: &str = "raw NOTE put requires author_take";
pub(super) fn conflict_claim_candidate(
    predicate: &'static str,
    subject: EntityId,
    value: Value,
    confidence: f32,
) -> ClaimCandidate {
    ClaimCandidate::new(predicate, ClaimSubject::Entity(subject), value, confidence)
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub(crate) struct EdgeValueFields {
    pub(crate) weight: f32,
    pub(crate) created_at: u64,
    pub(crate) vad: Vad,
    pub(crate) provenance: Option<EdgeProvenanceFlags>,
}

impl EdgeValueFields {
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn from_decoded(decoded: DecodedEdgeValue) -> Self {
        Self {
            weight: decoded.weight,
            created_at: decoded.created_at,
            vad: decoded.vad.unwrap_or(Vad::NEUTRAL),
            provenance: decoded.provenance,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct EntityMetadataHeader {
    pub(crate) entity_type: u8,
    pub(crate) occurred_start: u64,
    pub(crate) occurred_end: u64,
    pub(crate) learned_at: u64,
}

impl EntityMetadataHeader {
    pub(crate) fn parse(raw: &[u8]) -> Option<Self> {
        if raw.len() < ENTITY_METADATA_HEADER_LEN {
            return None;
        }

        let entity_type = raw[ENTITY_TYPE_OFFSET];
        let occurred_start = u64::from_be_bytes(
            raw[ENTITY_OCCURRED_START_OFFSET..ENTITY_OCCURRED_END_OFFSET]
                .try_into()
                .ok()?,
        );
        let occurred_end = u64::from_be_bytes(
            raw[ENTITY_OCCURRED_END_OFFSET..ENTITY_LEARNED_AT_OFFSET]
                .try_into()
                .ok()?,
        );
        let learned_at = u64::from_be_bytes(
            raw[ENTITY_LEARNED_AT_OFFSET..ENTITY_BODY_OFFSET]
                .try_into()
                .ok()?,
        );

        Some(Self {
            entity_type,
            occurred_start,
            occurred_end,
            learned_at,
        })
    }
}

pub(super) fn authority_observation_secs_for_write(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    candidate_secs: u64,
) -> Result<u64> {
    let floor_key = crate::authority::authority_first_seen_clock_key();
    let previous_floor = crate::authority::AUTHORITY_FIRST_SEEN
        .get(store, wtxn, &floor_key)?
        .unwrap_or(0);
    let observed_secs =
        crate::authority::authority_observation_secs(store, previous_floor, candidate_secs);
    if observed_secs != previous_floor {
        crate::authority::AUTHORITY_FIRST_SEEN.put(store, wtxn, &floor_key, &observed_secs)?;
    }
    Ok(observed_secs)
}
