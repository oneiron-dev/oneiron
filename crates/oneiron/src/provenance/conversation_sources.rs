//! The conversations a claim's words came from (FIX 11841), for recall's
//! narrowing by conversation. One level of the claim's sources, each hopped
//! to its conversation, in the caller's read. It grants nothing: the caller
//! has already admitted the claim.
//!
//! The sources are the claim's typed TURN and MESSAGE citations, its
//! consolidation envelope's refs and its registered dependency sources. A
//! TURN's conversation is its `ChildOf` target; a MESSAGE's is its
//! `BelongsTo` target, else its TURN's (`PartOf`, then `ChildOf`). Every read
//! is a point read: one claim row, one dependent's reverse rows, and the
//! first edge of one kind out of each source. No source is followed further,
//! so no walk and no type scan runs per recall candidate.

use std::collections::BTreeSet;

use heed::RoTxn;

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::claim::EvidenceKind;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN,
};
use crate::store::StoreRead;

/// The conversations `claim`'s words came from, read in `txn`: empty for a
/// row that is absent, no CLAIM or undecodable, or a claim that names no
/// conversation source. A source that is gone, malformed or of another kind
/// adds nothing.
pub(crate) fn claim_conversation_sources_in(
    store: &StoreRead<'_>,
    txn: &RoTxn<'_>,
    claim: &EntityId,
) -> Result<BTreeSet<EntityId>> {
    let mut conversations = BTreeSet::new();
    let body = store.port_entity_with_raw(txn, claim, |raw| {
        if raw.first() != Some(&ENTITY_TYPE_CLAIM) || raw.len() < ENTITY_METADATA_HEADER_LEN {
            return Ok(None);
        }
        Ok(crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true).ok())
    })?;
    let Some(body) = body.flatten() else {
        return Ok(conversations);
    };
    let mut sources: BTreeSet<EntityId> = body
        .evidence_refs()
        .unwrap_or_default()
        .into_iter()
        .filter(|evidence| matches!(evidence.kind, EvidenceKind::Turn | EvidenceKind::Message))
        .filter_map(|evidence| EntityId::from_hex(&evidence.entity).ok())
        .collect();
    sources.extend(consolidation_refs(&body));
    sources.extend(crate::ports::dependency_sources_in(store, txn, claim)?);
    for source in &sources {
        if let Some(conversation) = source_conversation_in(store, txn, source)? {
            conversations.insert(conversation);
        }
    }
    Ok(conversations)
}

/// The refs `claim`'s consolidation envelope names, kept under
/// `candidate_evidence` or as the whole evidence; none for a claim with no
/// envelope, or one that does not decode.
fn consolidation_refs(claim: &crate::ClaimBody) -> Vec<EntityId> {
    let Some(evidence) = claim.evidence.as_ref() else {
        return Vec::new();
    };
    let stored = evidence
        .as_map()
        .and_then(|fields| {
            fields
                .iter()
                .find(|(key, _)| key.as_str() == Some("candidate_evidence"))
                .map(|(_, value)| value)
        })
        .unwrap_or(evidence);
    crate::dreamer_consolidation::decode_consolidation_evidence(stored)
        .ok()
        .flatten()
        .map(|envelope| envelope.refs)
        .unwrap_or_default()
}

/// The conversation `source` is in: itself for a CONVERSATION, a TURN's
/// `ChildOf` target, a MESSAGE's `BelongsTo` target or else its TURN's.
fn source_conversation_in(
    store: &StoreRead<'_>,
    txn: &RoTxn<'_>,
    source: &EntityId,
) -> Result<Option<EntityId>> {
    match entity_type_in(store, txn, source)? {
        Some(ENTITY_TYPE_CONVERSATION) => Ok(Some(*source)),
        Some(ENTITY_TYPE_TURN) => first_target_of_type(
            store,
            txn,
            source,
            EdgeKind::ChildOf,
            ENTITY_TYPE_CONVERSATION,
        ),
        Some(ENTITY_TYPE_MESSAGE) => {
            if let Some(conversation) = first_target_of_type(
                store,
                txn,
                source,
                EdgeKind::BelongsTo,
                ENTITY_TYPE_CONVERSATION,
            )? {
                return Ok(Some(conversation));
            }
            let Some(turn) =
                first_target_of_type(store, txn, source, EdgeKind::PartOf, ENTITY_TYPE_TURN)?
            else {
                return Ok(None);
            };
            first_target_of_type(
                store,
                txn,
                &turn,
                EdgeKind::ChildOf,
                ENTITY_TYPE_CONVERSATION,
            )
        }
        _ => Ok(None),
    }
}

/// The first `kind` edge out of `source` whose target is of `entity_type`:
/// one adjacency read that stops at its first match.
fn first_target_of_type(
    store: &StoreRead<'_>,
    txn: &RoTxn<'_>,
    source: &EntityId,
    kind: EdgeKind,
    entity_type: u8,
) -> Result<Option<EntityId>> {
    for edge in store.port_edges(txn, source, EdgeDirection::Out, Some(kind), None)? {
        let target = edge?.target;
        if entity_type_in(store, txn, &target)? == Some(entity_type) {
            return Ok(Some(target));
        }
    }
    Ok(None)
}

/// `id`'s stored entity type, from its row's first byte, read in place.
fn entity_type_in(store: &StoreRead<'_>, txn: &RoTxn<'_>, id: &EntityId) -> Result<Option<u8>> {
    Ok(store
        .port_entity_with_raw(txn, id, |raw| Ok(raw.first().copied()))?
        .flatten())
}
