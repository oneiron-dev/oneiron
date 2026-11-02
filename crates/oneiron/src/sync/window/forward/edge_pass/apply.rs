//! The edge pass's mandate-checked write: one edge's reserved-kind mandate,
//! endpoint readiness, stored-byte comparison, and paired write, sharing the
//! caller's transaction.

use super::super::RematCtx;
use super::EdgeWork;

use crate::batch::EdgeValueFields;
use crate::error::Result;
use crate::sync::bridge;
use crate::sync::quarantine::{self, QuarantineContainer};

/// One edge's write outcome.
pub(super) enum EdgeRematOutcome {
    Written,
    Unchanged,
    Deferred,
    // Owed in the exact `regenerates` ledger (FIX 6204), not under
    // its source's replay marker.
    Waiting,
    Quarantined,
}

/// The edge write itself: the reserved-kind mandate, endpoint readiness,
/// stored-byte comparison, and paired write share the caller's
/// transaction — the edge's own door transaction on the one-by-one path,
/// the chunk's door transaction inside the edge's savepoint on the
/// chunked path. A separate read check followed by `batch().commit()`
/// would let an intervening undo revoke the mandate before the edge
/// write.
pub(super) fn apply_edge_in_txn(
    ctx: &RematCtx<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    key: &str,
    buf: &[u8],
    work: &EdgeWork,
) -> Result<EdgeRematOutcome> {
    let vault = ctx.vault;
    let window_key = ctx.window_key;
    let EdgeWork {
        src,
        kind,
        tgt,
        decoded,
        soft_addressing,
    } = *work;
    if vault.local_hard_delete_marker_exists_in_txn(wtxn, &src)?
        || vault.local_hard_delete_marker_exists_in_txn(wtxn, &tgt)?
    {
        return Ok(EdgeRematOutcome::Deferred);
    }
    for endpoint in [&src, &tgt] {
        if vault.get_entity_type_in_txn(wtxn, endpoint)? == Some(crate::registry::ENTITY_TYPE_NOTE)
            && quarantine::unproven_remat_marker_exists_in_txn(
                vault,
                wtxn,
                window_key.as_str(),
                endpoint,
            )?
        {
            return Ok(EdgeRematOutcome::Deferred);
        }
    }
    if let Err(reserved) = crate::edge::validate_public_edge_kind(kind)
        && !matches!(
            kind,
            crate::edge::EdgeKind::Parent
                | crate::edge::EdgeKind::SpawnedBy
                | crate::edge::EdgeKind::RepliesTo
                | crate::edge::EdgeKind::AddressedTo
        )
    {
        let mandated_at =
            vault.identity_topology_mandated_shell_edge_in_txn(&*wtxn, &src, kind, &tgt)?;
        let door_echo = mandated_at.is_some_and(|at| {
            decoded.created_at == at && kind.default_weight() == Some(decoded.weight)
        });
        if !door_echo {
            quarantine::quarantine_rejected_op_in_txn(
                vault,
                wtxn,
                window_key.as_str(),
                QuarantineContainer::Edges,
                key,
                &reserved,
                buf,
            )?;
            return Ok(EdgeRematOutcome::Quarantined);
        }
    }

    let src_exists =
        crate::ports::EntityStoreRead::port_entity_present(&vault.store, &*wtxn, &src)?;
    let tgt_exists =
        crate::ports::EntityStoreRead::port_entity_present(&vault.store, &*wtxn, &tgt)?;
    if !src_exists || !tgt_exists {
        if kind == crate::edge::EdgeKind::SpawnedBy {
            bridge::defer_spawned_by(vault, wtxn, window_key.as_str(), &src, &tgt, buf)?;
        } else if kind == crate::edge::EdgeKind::ChildOf {
            bridge::defer_child_of(vault, wtxn, window_key.as_str(), &src, &tgt, buf)?;
        } else if kind == crate::edge::EdgeKind::Regenerates {
            // Endpoint arrival wakes the owed link (FIX 6204). A
            // missing source keeps its own entity outcome.
            bridge::owe_regenerates(vault, wtxn, window_key.as_str(), &src, &tgt, buf)?;
            if src_exists {
                return Ok(EdgeRematOutcome::Waiting);
            }
        }
        return Ok(EdgeRematOutcome::Deferred);
    }
    if soft_addressing
        && !matches!(
            crate::batch::stored_entity_type(&vault.store, &*wtxn, &tgt)?,
            Some(crate::registry::ENTITY_TYPE_PERSON | crate::registry::ENTITY_TYPE_AGENT_DEF)
        )
    {
        return Err(crate::error::ArtifactError::InvalidRecoveryArtifact(
            "retained addressing recipient missing or not a PERSON or AGENT_DEF",
        )
        .into());
    }
    if matches!(
        kind,
        crate::edge::EdgeKind::SpawnedBy | crate::edge::EdgeKind::RepliesTo
    ) {
        crate::conversation_dag::validate_received_edge(
            &vault.store,
            &*wtxn,
            src,
            kind,
            tgt,
            decoded,
        )?;
    }

    if kind == crate::edge::EdgeKind::AddressedTo
        && !soft_addressing
        && !crate::conversation_dag::addressed_to_echo_in_txn(
            &vault.store,
            &*wtxn,
            &src,
            &tgt,
            decoded,
        )?
    {
        quarantine::quarantine_rejected_op_in_txn(
            vault,
            wtxn,
            window_key.as_str(),
            QuarantineContainer::Edges,
            key,
            &crate::error::RegistryError::ReservedEdgeKind("conversation_dag").into(),
            buf,
        )?;
        return Ok(EdgeRematOutcome::Quarantined);
    }

    // ONE-1645 replay door for the FacetOf type table. The batch
    // arm this write lands on (`BatchOp::EdgeWithCreatedAt`) is
    // deliberately UNGATED — a hard abort there would wedge sync
    // permanently (H2) — so the table is enforced HERE, at the
    // remat chokepoint, as a quarantine-and-continue rejection.
    //
    // Without it a federation peer could replay an off-table
    // stamp (e.g. PERSON -> FACET) that no local public writer
    // can write, and it would reach LMDB — where the local query
    // door reads facet adjacency with no admitted-set filter of
    // its own. The federation selector no longer honors such a
    // source (`selector::facet_scope_by_source` mirrors this same
    // table on read), but the LMDB write is still an
    // authorization-boundary bypass via replay: this door is what
    // keeps the shape out of the retrieval truth at all.
    //
    // Ordered AFTER the endpoint-existence check on purpose: a
    // cross-window endpoint that has not arrived yet is a
    // DEFERRAL, not a rejection, and the type table reads
    // endpoint types from the entity rows this check just proved
    // present. Reversing the order would burn a legitimate
    // out-of-order replay as a permanent quarantine.
    //
    // The match is GUARDED (ONE-1124 fail-closed split): only a
    // remote-classifiable error may quarantine. The table also
    // surfaces LOCAL faults — `CorruptedIndex("entity header")`
    // on a stored row it cannot parse, and heed read errors on
    // the type lookups themselves — and those must ABORT the
    // drain. Quarantining one would be doubly wrong: it swallows
    // our own storage defect behind a continue, and the `x:` row
    // it writes is PERMANENT false evidence accusing the peer of
    // a forgery it never sent.
    match crate::batch::validate_replayed_facet_of_edge(&vault.store, &*wtxn, src, kind, tgt) {
        Ok(()) => {}
        Err(off_table) if quarantine::remote_rejection_reason(&off_table).is_some() => {
            quarantine::quarantine_rejected_op_in_txn(
                vault,
                wtxn,
                window_key.as_str(),
                QuarantineContainer::Edges,
                key,
                &off_table,
                buf,
            )?;
            return Ok(EdgeRematOutcome::Quarantined);
        }
        Err(local) => return Err(local),
    }

    let out_matches =
        crate::ports::EdgeStoreStaging::port_edge_encoded(&vault.store, &*wtxn, &src, kind, &tgt)?
            .as_deref()
            == Some(buf);
    if out_matches
        && crate::ports::EdgeStoreRead::port_edge_consistent(
            &vault.store,
            &*wtxn,
            &src,
            kind,
            &tgt,
        )?
    {
        if kind == crate::edge::EdgeKind::ChildOf {
            bridge::settle_child_of(vault, wtxn, window_key.as_str(), &src, &tgt)?;
        } else if kind == crate::edge::EdgeKind::Regenerates {
            bridge::settle_regenerates(vault, wtxn, window_key.as_str(), &src, &tgt)?;
        }
        return Ok(EdgeRematOutcome::Unchanged);
    }

    // FIX 5972: a `regenerates` pair this vault does not store
    // yet lands only once it proves what the stream proved. A
    // stored pair was proven when it landed, whatever has since
    // become of its MESSAGEs. Only canonical recovery's own row
    // may link an erased shell; fresh replay has no body left.
    if kind == crate::edge::EdgeKind::Regenerates
        && !crate::edge::regeneration_stored(&vault.store, &*wtxn, &src, &tgt)?
    {
        match crate::edge::regeneration_pair(&vault.store, &*wtxn, &src, &tgt)? {
            crate::edge::Regeneration::Admits => {}
            crate::edge::Regeneration::Erased
                if ctx.trusted.is_some_and(|snapshot| {
                    snapshot.base_edges.iter().any(|edge| {
                        edge.source == *src.as_bytes()
                            && edge.kind == kind as u8
                            && edge.target == *tgt.as_bytes()
                            && edge.value == buf
                    })
                }) => {}
            crate::edge::Regeneration::Erased => {
                bridge::settle_regenerates(vault, wtxn, window_key.as_str(), &src, &tgt)?;
                return Ok(EdgeRematOutcome::Deferred);
            }
            crate::edge::Regeneration::Pending => {
                bridge::owe_regenerates(vault, wtxn, window_key.as_str(), &src, &tgt, buf)?;
                return Ok(EdgeRematOutcome::Waiting);
            }
            crate::edge::Regeneration::Refuses => {
                quarantine::quarantine_rejected_op_in_txn(
                    vault,
                    wtxn,
                    window_key.as_str(),
                    QuarantineContainer::Edges,
                    key,
                    &crate::edge::reserved_regenerates(),
                    buf,
                )?;
                bridge::settle_regenerates(vault, wtxn, window_key.as_str(), &src, &tgt)?;
                return Ok(EdgeRematOutcome::Quarantined);
            }
        }
    }

    vault
        .batch_in()
        .edge_with_value_fields(&src, kind, &tgt, EdgeValueFields::from_decoded(decoded))
        .apply(wtxn)?;
    // FIX 6261: a deferred `PartOf` edge landing after its
    // MESSAGE row may complete a kept turn's missing words.
    if kind == crate::edge::EdgeKind::PartOf {
        crate::store::turn_missing::reconcile_in_txn(vault, wtxn, Some(&src))?;
    }
    if kind == crate::edge::EdgeKind::ChildOf {
        bridge::settle_child_of(vault, wtxn, window_key.as_str(), &src, &tgt)?;
    } else if kind == crate::edge::EdgeKind::Regenerates {
        bridge::settle_regenerates(vault, wtxn, window_key.as_str(), &src, &tgt)?;
    }
    Ok(EdgeRematOutcome::Written)
}
