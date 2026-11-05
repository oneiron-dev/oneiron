//! Core half of `batch::types`: its store-layer items live in `oneiron_store::batch::types` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::batch::types::*;

use crate::edge::{DecodedEdgeValue, EdgeProvenanceFlags};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::claim_body::ClaimSubject;
use heed::RwTxn;
use oneiron_contracts::affect::Vad;
pub(crate) use oneiron_contracts::record_layout::EntityMetadataHeader;
pub(crate) use oneiron_contracts::record_layout::{
    ENTITY_BODY_OFFSET, ENTITY_LEARNED_AT_OFFSET, ENTITY_METADATA_HEADER_LEN,
    ENTITY_OCCURRED_END_OFFSET, ENTITY_OCCURRED_START_OFFSET, ENTITY_TYPE_OFFSET,
};
pub(crate) use oneiron_store::long_interval::LONG_INTERVAL_THRESHOLD_SECS;
use rmpv::Value;
use std::str;

pub(super) fn authority_observation_secs_for_write(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    candidate_secs: u64,
) -> Result<u64> {
    // Strict as before; a damaged floor now names itself, and an owner's
    // restriction-only act lands over it (FIX 10106).
    crate::authority::advance_authority_clock_strict_in_txn(store, wtxn, candidate_secs)
}
