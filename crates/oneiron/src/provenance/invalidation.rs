//! The stale door's provenance hook: a wrapper whose cited source was erased
//! stops justifying its semantic edge in the same transaction. Writing that
//! edge again, by replaying an older image or by a public put after its
//! removal, never brings the support back.

use super::queries::walk_edge_provenance_cohort_in_txn;
use super::{
    EdgeRef, PREDICATE_EDGE_PROVENANCE, ProvenancePrecedence, StoredProvenanceClaim,
    decode_edge_provenance_body, resolve_persisted_actor_class, restamp_edge_flags, winner_index,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimLifecycleStatus, ClaimSubject};
#[cfg(feature = "sync")]
use crate::edge::{EDGE_VALUE_SEMANTIC_LEN, EDGE_VALUE_SEMANTIC_PROVENANCED_LEN};
use crate::edge::{
    EdgeConfirmationStatus, EdgeKind, EdgeProvenanceFlags, EdgeValueLayout,
    edge_value_layout_for_kind,
};
use crate::entity_id::EntityId;
use crate::error::{ClaimError, Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::ppr;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;
use crate::vault::MAX_EDGE_QUERY_RESULTS;
use heed::RwTxn;
use std::ops::ControlFlow;

/// How many inbound `claim_of` rows the withdrawal check walks before
/// refusing. A WORK bound, like the claim lookup's walk (`claim::read`): the
/// walk holds only the written edge's own wrappers, never its source's whole
/// fan-in, so it sits an order of magnitude above the materialization cap,
/// and ordinary claims about a busy source do not turn a valid write into a
/// refusal.
const WITHDRAWAL_SCAN_CEILING: usize = MAX_EDGE_QUERY_RESULTS * 10;

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
/// transaction. Malformed provenance fails closed. The erasure that staled
/// `id` must complete, so the winner is folded over a streaming walk of the
/// source's `claim_of` rows, one candidate held, under no materialization cap:
/// ordinary claims about a busy source never refuse it.
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
    let mut winner: Option<(ProvenancePrecedence, EdgeProvenanceFlags)> = None;
    walk_edge_provenance_cohort_in_txn(
        store,
        txn,
        &subject,
        None,
        &[ClaimLifecycleStatus::Active],
        usize::MAX,
        |claim, _| {
            let candidate = claim.precedence();
            if winner
                .as_ref()
                .is_none_or(|(best, _)| winner_index(&[*best, candidate]) == Some(1))
            {
                winner = Some((candidate, claim.flags()));
            }
            ControlFlow::Continue(())
        },
    )?;
    let flags = winner.map_or(
        EdgeProvenanceFlags {
            confirmation_status: EdgeConfirmationStatus::Retracted,
            actor_class,
        },
        |(_, flags)| flags,
    );
    stamp_in_txn(store, txn, &subject, edge.provenance, flags)
}

/// Whether an edge image of `subject` carrying `incoming` flags, a replay or
/// a public put, must meet the local wrapper cohort once written (see
/// [`withdraw_image_support_in_txn`]); read before the write.
///
/// The surviving local wrappers decide, not the stored edge: an edge removal
/// drops the edge rows but keeps each wrapper and its `claim_of` link. Only a
/// semantic edge can carry provenance, and an image already stamped
/// retracted asserts no support. Nor does a bare image over a stored bare
/// edge: every local step that withdraws a stored edge's support (the stale
/// door, RETRACT) stamps it retracted in its own transaction, so that edge
/// has no withdrawn wrapper the image could outrank. Any other image, bare
/// over no stored edge or provenanced over any, is checked, unless its source
/// has no inbound `claim_of` link at all (one seek).
pub(crate) fn image_needs_cohort_check(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: &EdgeRef,
    incoming: Option<EdgeProvenanceFlags>,
) -> Result<bool> {
    if edge_value_layout_for_kind(subject.kind, false) == EdgeValueLayout::Structural
        || incoming
            .is_some_and(|flags| flags.confirmation_status == EdgeConfirmationStatus::Retracted)
    {
        return Ok(false);
    }
    if incoming.is_none()
        && store
            .port_edge_get(txn, &subject.source, subject.kind, &subject.target)?
            .is_some_and(|edge| edge.provenance.is_none())
    {
        return Ok(false);
    }
    Ok(store
        .port_edges(
            txn,
            &subject.source,
            EdgeDirection::In,
            Some(EdgeKind::ClaimOf),
            None,
        )?
        .next()
        .transpose()?
        .is_some())
}

/// Local invalidation outranks a written edge image. Run after a replay or a
/// public put wrote `subject` in this transaction: when local
/// `edge.provenance` wrappers for it exist and none is live (each closed or
/// dependency-stale), the support the image asserts was withdrawn here, so
/// the edge takes the retracted stamp with the D14 winner's persisted actor
/// class. A live wrapper, or no wrapper at all (none replicated yet), leaves
/// the image's flags as written. Changed flags invalidate both endpoints' PPR
/// and bump the graph version. The walk stops at the first live wrapper and
/// refuses past [`WITHDRAWAL_SCAN_CEILING`] `claim_of` rows, never reading a
/// crowded source as an empty cohort.
pub(crate) fn withdraw_image_support_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    subject: &EdgeRef,
) -> Result<()> {
    let Some(flags) = withdrawn_support(store, txn, subject)? else {
        return Ok(());
    };
    let Some(edge) = store.port_edge_get(txn, &subject.source, subject.kind, &subject.target)?
    else {
        return Ok(());
    };
    stamp_in_txn(store, txn, subject, edge.provenance, flags)
}

/// Whether `stored` is `image` of `subject` as the replay guard lands it over
/// local withdrawal ([`withdraw_image_support_in_txn`]): the image's own
/// value bytes under the retracted stamp the local cohort decides. Recovery
/// completion accepts that projection in place of the image's bytes. An
/// image that asserts no support (structural, or already retracted) is never
/// projected.
#[cfg(feature = "sync")]
pub(crate) fn holds_withdrawn_image(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: &EdgeRef,
    image: &[u8],
    stored: &[u8],
) -> Result<bool> {
    let retracted = EdgeConfirmationStatus::Retracted as u8;
    if !matches!(
        image.len(),
        EDGE_VALUE_SEMANTIC_LEN | EDGE_VALUE_SEMANTIC_PROVENANCED_LEN
    ) || image.get(EDGE_VALUE_SEMANTIC_LEN) == Some(&retracted)
        || stored.len() != EDGE_VALUE_SEMANTIC_PROVENANCED_LEN
        || image[..EDGE_VALUE_SEMANTIC_LEN] != stored[..EDGE_VALUE_SEMANTIC_LEN]
    {
        return Ok(false);
    }
    let Some(flags) = withdrawn_support(store, txn, subject)? else {
        return Ok(false);
    };
    Ok(stored[EDGE_VALUE_SEMANTIC_LEN..]
        == [flags.confirmation_status as u8, flags.actor_class as u8])
}

/// The retracted stamp `subject` takes when local `edge.provenance` wrappers
/// for it exist and none is live, with the D14 winner's persisted actor
/// class; `None` when a wrapper is live or there is none.
fn withdrawn_support(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: &EdgeRef,
) -> Result<Option<EdgeProvenanceFlags>> {
    let mut live = false;
    let mut withdrawn = Vec::new();
    walk_edge_provenance_cohort_in_txn(
        store,
        txn,
        subject,
        None,
        &[
            ClaimLifecycleStatus::Active,
            ClaimLifecycleStatus::Superseded,
            ClaimLifecycleStatus::Retracted,
        ],
        WITHDRAWAL_SCAN_CEILING,
        |claim, lifecycle| {
            if lifecycle == ClaimLifecycleStatus::Active {
                live = true;
                return ControlFlow::Break(());
            }
            withdrawn.push(claim);
            ControlFlow::Continue(())
        },
    )?;
    if live {
        return Ok(None);
    }
    let precedence: Vec<ProvenancePrecedence> = withdrawn
        .iter()
        .map(StoredProvenanceClaim::precedence)
        .collect();
    Ok(winner_index(&precedence).map(|index| EdgeProvenanceFlags {
        confirmation_status: EdgeConfirmationStatus::Retracted,
        actor_class: withdrawn[index].actor_class,
    }))
}

/// Restamps `subject` when its `current` flags differ from `flags`, then
/// invalidates both endpoints' PPR and bumps the graph version.
fn stamp_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    subject: &EdgeRef,
    current: Option<EdgeProvenanceFlags>,
    flags: EdgeProvenanceFlags,
) -> Result<()> {
    if current == Some(flags) {
        return Ok(());
    }
    restamp_edge_flags(store, txn, subject, flags)?;
    ppr::invalidate_ppr_for_edge(store, txn, &subject.source, &subject.target)?;
    // The stamp moves edge bytes outside any edge write's own bump, as in
    // RETRACT.
    ppr::increment_graph_version(store, txn)
}
