use std::str;

use heed::RwTxn;
use rmpv::Value;

use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::claim_body::ClaimSubject;
use oneiron_base::edge::DecodedEdgeValue;
use oneiron_base::edge::EdgeProvenanceFlags;
use oneiron_base::error::Result;
use oneiron_contracts::affect::Vad;
use oneiron_contracts::entity_id::EntityId;

pub use crate::long_interval::LONG_INTERVAL_THRESHOLD_SECS;
pub use oneiron_contracts::record_layout::{
    ENTITY_BODY_OFFSET, ENTITY_LEARNED_AT_OFFSET, ENTITY_METADATA_HEADER_LEN,
    ENTITY_OCCURRED_END_OFFSET, ENTITY_OCCURRED_START_OFFSET, ENTITY_TYPE_OFFSET,
};
pub const ERR_RAW_CLAIM_PUT_REQUIRES_ENVELOPE: &str = "raw claim put requires WriteEnvelope";
pub const ERR_RAW_NOTE_PUT_REQUIRES_AUTHOR_TAKE: &str = "raw NOTE put requires author_take";
pub fn conflict_claim_candidate(
    predicate: &'static str,
    subject: EntityId,
    value: Value,
    confidence: f32,
) -> ClaimCandidate {
    ClaimCandidate::new(predicate, ClaimSubject::Entity(subject), value, confidence)
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub struct EdgeValueFields {
    pub weight: f32,
    pub created_at: u64,
    pub vad: Vad,
    pub provenance: Option<EdgeProvenanceFlags>,
}

impl EdgeValueFields {
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub fn from_decoded(decoded: DecodedEdgeValue) -> Self {
        Self {
            weight: decoded.weight,
            created_at: decoded.created_at,
            vad: decoded.vad.unwrap_or(Vad::NEUTRAL),
            provenance: decoded.provenance,
        }
    }
}

pub use oneiron_contracts::record_layout::EntityMetadataHeader;
