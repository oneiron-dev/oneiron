//! The stale door's provenance hook: a wrapper whose cited source was erased
//! stops justifying its semantic edge in the same transaction.

use super::queries::edge_provenance_cohort_in_txn;
use super::{
    EdgeRef, PREDICATE_EDGE_PROVENANCE, ProvenancePrecedence, StoredProvenanceClaim,
    decode_edge_provenance_body, resolve_persisted_actor_class, restamp_edge_flags, winner_index,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimLifecycleStatus, ClaimSubject};
use crate::edge::{EdgeConfirmationStatus, EdgeProvenanceFlags};
use crate::entity_id::EntityId;
use crate::error::{ClaimError, Error, Result};
use crate::ports::{EdgeStoreRead, EntityStoreRead};
use crate::ppr;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;
use heed::RwTxn;

/// Re-derives the subject edge's flags once `id` is dependency-stale.
///
/// A no-op unless `id` is a bodied, active `edge.provenance` Claim whose
/// semantic edge still exists. The caller has already set the stale bit, so
/// the cohort no longer counts `id` as live: the edge takes the D14 winner of
/// the wrappers still live, else the retracted stamp with this Claim's
/// persisted actor class (RETRACT's own rule). The edge and both endpoints are
/// kept: another wrapper may still justify the edge, and its head has its own
/// truth. Never a bare downgrade, which would propagate again. Changed flags
/// invalidate both endpoints' PPR and bump the graph version in this
/// transaction. Malformed provenance fails closed.
pub(crate) fn refresh_stale_wrapper_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(raw) = store.port_entity_record(txn, id)?.map(|row| row.encode()) else {
        return Ok(());
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_CLAIM || raw.len() == ENTITY_METADATA_HEADER_LEN {
        return Ok(());
    }
    let wrapper = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    if wrapper.predicate != PREDICATE_EDGE_PROVENANCE
        || wrapper.lifecycle != ClaimLifecycleStatus::Active
    {
        // A closed wrapper was not live before; its staleness moves no cohort.
        return Ok(());
    }
    let ClaimSubject::Edge {
        source,
        kind,
        target,
    } = wrapper.subject
    else {
        return Err(Error::Claim(ClaimError::InvalidProvenanceBody(
            "edge.provenance claim subject is not a 33-byte EdgeRef",
        )));
    };
    let record = decode_edge_provenance_body(&wrapper.value)?;
    let actor_class = resolve_persisted_actor_class(&record, wrapper.evidence.as_ref())?;
    let Some(edge) = store.port_edge_get(txn, &source, kind, &target)? else {
        return Ok(());
    };
    let subject = EdgeRef::new(source, kind, target);
    let live =
        edge_provenance_cohort_in_txn(store, txn, &subject, None, &[ClaimLifecycleStatus::Active])?;
    let precedence: Vec<ProvenancePrecedence> =
        live.iter().map(StoredProvenanceClaim::precedence).collect();
    let flags = match winner_index(&precedence) {
        Some(index) => live[index].flags(),
        None => EdgeProvenanceFlags {
            confirmation_status: EdgeConfirmationStatus::Retracted,
            actor_class,
        },
    };
    if edge.provenance == Some(flags) {
        return Ok(());
    }
    restamp_edge_flags(store, txn, &subject, flags)?;
    ppr::invalidate_ppr_for_edge(store, txn, &subject.source, &subject.target)?;
    // The edge bytes changed without an edge BatchOp, as in RETRACT.
    ppr::increment_graph_version(store, txn)
}
