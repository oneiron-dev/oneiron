//! Validation of synthetic lexical query hint CLAIMs at the shared write door.

use super::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, lexical_query_hint_claim_id};
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::{
    entity_id::EntityId,
    error::{Error, Result},
    store::Store,
    write_envelope::claim_body::ClaimBody,
};

pub(super) fn validate_lexical_query_hint(
    store: &Store,
    wtxn: &heed::RoTxn<'_>,
    id: EntityId,
    body: &ClaimBody,
    replicated: bool,
) -> Result<()> {
    if !id.as_bytes().starts_with(
        &crate::write_envelope::claim_body::lexical_query_hint::LEXICAL_QUERY_HINT_ID_PREFIX,
    ) {
        return Err(Error::InvalidClaimBody(
            "lexical query hint claim id must use LH prefix",
        ));
    }
    let hint_value =
        crate::write_envelope::claim_body::lexical_query_hint::decode_lexical_query_hint_value(
            &body.value,
        )?;
    let target = hint_value.target;
    let expected_id = lexical_query_hint_claim_id(&target, &hint_value.query)?;
    if expected_id != id {
        return Err(Error::InvalidClaimBody(
            "lexical query hint claim id must match target and query",
        ));
    }
    if !body.stale {
        return Err(Error::InvalidClaimBody(
            "lexical query hint claims must be stale",
        ));
    }
    if body.lifecycle != oneiron_contracts::claim::ClaimLifecycleStatus::Active {
        return Err(Error::InvalidClaimBody(
            "lexical query hint claims must be active",
        ));
    }
    if target == id {
        return Err(Error::InvalidClaimBody(
            "lexical query hint target must not be self",
        ));
    }
    // A hard-deleted or deleted target keeps no hint, whenever the hint
    // arrives: its purge removed the hints it held, and a hint delayed past
    // it would store the query text again after erasure (FIX 9601; ARCH-0038
    // hard-once-seen deletion). Only a target not arrived yet takes a
    // replayed hint out of order.
    if store.port_deletion_marked(wtxn, DeletionMarker::HardDelete, &target)?
        || store.port_deletion_marked(wtxn, DeletionMarker::RowFence, &target)?
    {
        return Err(Error::InvalidClaimBody(
            "lexical query hint target is deleted",
        ));
    }
    if let Some(target_raw) = crate::ports::EntityStoreRead::port_entity_raw(store, wtxn, &target)?
    {
        let Some(target_header) = EntityMetadataHeader::parse(&target_raw) else {
            return Err(Error::CorruptedIndex("entity header"));
        };
        if target_header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            return Err(Error::InvalidClaimBody(
                "lexical query hint target must be claim",
            ));
        }
        let Ok(target_body) = crate::write_envelope::claim_body::decode_claim_body(
            &target_raw[ENTITY_METADATA_HEADER_LEN..],
            true,
        ) else {
            return Err(Error::InvalidClaimBody(
                "lexical query hint target must be claim",
            ));
        };
        if target_body.predicate
            == crate::write_envelope::claim_body::lexical_query_hint::PREDICATE_LEXICAL_QUERY_HINT
        {
            return Err(Error::InvalidClaimBody(
                "lexical query hint target must not be synthetic hint",
            ));
        }
    } else if !replicated {
        return Err(Error::InvalidClaimBody(
            "lexical query hint target must be claim",
        ));
    }
    Ok(())
}
