use std::str;

use heed::RwTxn;
use rmpv::Value;

use crate::edge::{DecodedEdgeValue, EdgeProvenanceFlags};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::claim_body::ClaimSubject;
use oneiron_contracts::affect::Vad;

pub(crate) use oneiron_contracts::record_layout::{
    ENTITY_BODY_OFFSET, ENTITY_LEARNED_AT_OFFSET, ENTITY_METADATA_HEADER_LEN,
    ENTITY_OCCURRED_END_OFFSET, ENTITY_OCCURRED_START_OFFSET, ENTITY_TYPE_OFFSET,
};
pub(crate) use oneiron_store::long_interval::LONG_INTERVAL_THRESHOLD_SECS;
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

pub(crate) use oneiron_contracts::record_layout::EntityMetadataHeader;

pub(super) fn authority_observation_secs_for_write(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    candidate_secs: u64,
) -> Result<u64> {
    // Strict as before; a damaged floor now names itself, and an owner's
    // restriction-only act lands over it (FIX 10106).
    crate::authority::advance_authority_clock_strict_in_txn(store, wtxn, candidate_secs)
}
