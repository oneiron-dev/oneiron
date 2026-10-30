use super::*;
use crate::error::RegistryError;
use crate::ppr;

/// Applies one op of the edge family and invalidates the PPR caches of both
/// endpoints when it changes an edge. Returns whether the graph changed: every
/// edge op changes it except a delete of an edge that is not stored.
pub(super) fn apply_edge_op(store: &Store, wtxn: &mut RwTxn<'_>, op: BatchOp) -> Result<bool> {
    match op {
        BatchOp::Edge {
            src,
            kind,
            tgt,
            weight,
            vad,
        } => {
            validate_facet_of_edge(store, wtxn, src, kind, tgt)?;
            write_under_local_withdrawal(store, wtxn, src, kind, tgt, None, |wtxn| {
                apply_edge(store, wtxn, src, kind, tgt, weight, vad)
            })?;
            unpark_local_stamp(store, wtxn, src, kind, tgt)?;
            ppr::invalidate_ppr_for_edge(store, wtxn, &src, &tgt)?;
            Ok(true)
        }
        BatchOp::PublicEdgeWithCreatedAt {
            src,
            kind,
            tgt,
            weight,
            created_at,
            vad,
        } => {
            validate_facet_of_edge(store, wtxn, src, kind, tgt)?;
            write_under_local_withdrawal(store, wtxn, src, kind, tgt, None, |wtxn| {
                apply_public_edge_with_created_at(
                    store, wtxn, src, kind, tgt, weight, created_at, vad,
                )
            })?;
            unpark_local_stamp(store, wtxn, src, kind, tgt)?;
            ppr::invalidate_ppr_for_edge(store, wtxn, &src, &tgt)?;
            Ok(true)
        }
        // UNGATED by design — this is the replicated/replay shape. A
        // bare-over-provenanced LWW edge is a legitimate remote winner;
        // gating here would turn a legitimate remote merge into a
        // permanent local sync-wedging abort (H2). The public timestamped
        // builders route through the gated `PublicEdgeWithCreatedAt` arm
        // instead.
        //
        // Ungated is not unvalidated: the ONE-1645 `FacetOf` type table
        // runs on every path INTO this arm instead, as a
        // quarantine-and-continue rejection rather than an abort —
        // `sync::window`'s forward-remat edge write and
        // `sync::bridge`'s Observer-B edge batch both call
        // `validate_facet_of_edge` after endpoint readiness, and
        // `sync::selector`'s federation admission door drops a provably
        // off-table row before it ever enters the admitted document. A
        // federation peer therefore cannot replay a facet stamp local
        // writers may not write.
        //
        // Nor does a replayed image outrank local invalidation
        // ([`write_under_local_withdrawal`]).
        BatchOp::EdgeWithCreatedAt {
            src,
            kind,
            tgt,
            weight,
            created_at,
            vad,
            provenance,
        } => {
            write_under_local_withdrawal(store, wtxn, src, kind, tgt, provenance, |wtxn| {
                apply_edge_with_created_at(
                    store, wtxn, src, kind, tgt, weight, created_at, vad, provenance,
                )
            })?;
            ppr::invalidate_ppr_for_edge(store, wtxn, &src, &tgt)?;
            Ok(true)
        }
        BatchOp::SetEdgeWeight {
            src,
            kind,
            tgt,
            weight,
        } => {
            apply_set_edge_weight(store, wtxn, src, kind, tgt, weight)?;
            // The weight at offset 0 is the PPR edge weight — invalidate
            // and bump exactly like the plain edge-write arms.
            ppr::invalidate_ppr_for_edge(store, wtxn, &src, &tgt)?;
            Ok(true)
        }
        BatchOp::SetEdgeVad {
            src,
            kind,
            tgt,
            vad,
        } => {
            apply_set_edge_vad(store, wtxn, src, kind, tgt, vad)?;
            // Mirror the existing edge-write behavior: every edge value
            // rewrite invalidates the endpoint PPR caches.
            ppr::invalidate_ppr_for_edge(store, wtxn, &src, &tgt)?;
            Ok(true)
        }
        BatchOp::DeleteEdge { src, kind, tgt } => {
            // Deleting or purging the source removes its stamp with it;
            // a live NOTE, ASSET or ASSET_TEXT keeps the one it was born with.
            if kind == crate::edge::EdgeKind::FacetOf
                && matches!(
                    stored_entity_type(store, wtxn, &src)?,
                    Some(
                        crate::registry::ENTITY_TYPE_NOTE
                            | crate::registry::ENTITY_TYPE_ASSET
                            | crate::registry::ENTITY_TYPE_ASSET_TEXT
                    )
                )
            {
                return Err(Error::Registry(RegistryError::FacetStampImmutable { src }));
            }
            let deleted = apply_delete_edge(store, wtxn, src, kind, tgt)?;
            if deleted {
                ppr::invalidate_ppr_for_edge(store, wtxn, &src, &tgt)?;
                // An epoch summary or an ASSET_TEXT keeps the words of a
                // source whose edge goes: losing it withdraws the dependent,
                // at this door and at the sync bridge's, which applies a
                // peer's removal here.
                if kind == crate::edge::EdgeKind::DerivedFrom {
                    crate::ports::withdraw_from_lost_source_in_txn(store, wtxn, &src, &tgt)?;
                }
            }
            Ok(deleted)
        }
        _ => Err(Error::InvariantViolation(
            "only an edge op reaches the edge applier",
        )),
    }
}

/// Writes one edge image of `src -kind-> tgt` carrying `incoming` flags
/// through `write`, then lets local invalidation outrank it: once written, an
/// image asserting support (any but a retracted one, or a bare one over a
/// stored bare edge) meets the local wrapper cohort, and support whose
/// wrappers are all closed or stale here goes back to retracted, even over a
/// removed edge. Every edge-creating arm writes through here, so neither a
/// replay nor a public put over a deleted edge restores support that an
/// erasure or a RETRACT withdrew.
fn write_under_local_withdrawal(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    src: EntityId,
    kind: crate::edge::EdgeKind,
    tgt: EntityId,
    incoming: Option<crate::edge::EdgeProvenanceFlags>,
    write: impl FnOnce(&mut RwTxn<'_>) -> Result<()>,
) -> Result<()> {
    let subject = crate::provenance::EdgeRef::new(src, kind, tgt);
    let check = crate::provenance::image_needs_cohort_check(store, wtxn, &subject, incoming)?;
    write(wtxn)?;
    if check {
        crate::provenance::withdraw_image_support_in_txn(store, wtxn, &subject)?;
    }
    Ok(())
}

/// A local public stamp comes from a writer that may place its row: the
/// owner, a row's own birth, or a credential its door judged. It discards any
/// federated copy of the same stamp held ahead of its row.
fn unpark_local_stamp(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    src: EntityId,
    kind: crate::edge::EdgeKind,
    tgt: EntityId,
) -> Result<()> {
    if kind == crate::edge::EdgeKind::FacetOf {
        crate::federation::facet_read::unpark_stamp(store, wtxn, src, tgt)?;
    }
    Ok(())
}

/// Both endpoints may acquire a PROJECT/CLAIM type later in this same batch.
/// Collect them so the final graph check sees that type change.
pub(super) fn edge_op_endpoints(op: &BatchOp) -> [EntityId; 2] {
    match op {
        BatchOp::Edge { src, tgt, .. }
        | BatchOp::PublicEdgeWithCreatedAt { src, tgt, .. }
        | BatchOp::EdgeWithCreatedAt { src, tgt, .. }
        | BatchOp::SetEdgeWeight { src, tgt, .. }
        | BatchOp::SetEdgeVad { src, tgt, .. }
        | BatchOp::DeleteEdge { src, tgt, .. } => [*src, *tgt],
        _ => unreachable!("edge arm contains only edge operations"),
    }
}
