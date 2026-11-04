//! The `regenerates` link proofs over stored rows (FIX 5972). They read the
//! store, so they stay in `oneiron` while the rest of [`crate::edge`] lives in
//! `oneiron-base`; `crate::edge` re-exports them at their old paths.

use crate::edge::{EdgeKind, Regeneration};
use crate::entity_id::EntityId;

/// The source a `regenerates` link from `new` names, judged against the axes
/// `new` has or will have: a live companion MESSAGE other than `new`, whose
/// sole `authored_by` is `actor` and whose sole `belongs_to` is
/// `conversation`. A Retry's seed proves this before its reply is born.
pub(crate) fn regeneration_source(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    new: &EntityId,
    source: &EntityId,
    actor: EntityId,
    conversation: EntityId,
) -> crate::error::Result<Regeneration> {
    if new == source {
        return Ok(Regeneration::Refuses);
    }
    let verdict = companion_message(store, txn, source)?;
    if verdict != Regeneration::Admits {
        return Ok(verdict);
    }
    for (kind, expected) in [
        (EdgeKind::AuthoredBy, actor),
        (EdgeKind::BelongsTo, conversation),
    ] {
        match message_axis(store, txn, source, kind)?.as_slice() {
            [] => return Ok(Regeneration::Pending),
            [target] if *target == expected => {}
            _ => return Ok(Regeneration::Refuses),
        }
    }
    Ok(Regeneration::Admits)
}

/// A stored `new -regenerates-> source` pair, proven as the stream proved it:
/// `new` is a live companion MESSAGE whose own sole axes name the actor and
/// conversation [`regeneration_source`] checks the source against. Peer
/// replay and restoration admit a carried link on [`Regeneration::Admits`]
/// alone.
pub(crate) fn regeneration_pair(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    new: &EntityId,
    source: &EntityId,
) -> crate::error::Result<Regeneration> {
    let verdict = companion_message(store, txn, new)?;
    if verdict != Regeneration::Admits {
        return Ok(verdict);
    }
    let actor = message_axis(store, txn, new, EdgeKind::AuthoredBy)?;
    let conversation = message_axis(store, txn, new, EdgeKind::BelongsTo)?;
    match (actor.as_slice(), conversation.as_slice()) {
        ([actor], [conversation]) => {
            regeneration_source(store, txn, new, source, *actor, *conversation)
        }
        (actor, conversation) if actor.len() > 1 || conversation.len() > 1 => {
            Ok(Regeneration::Refuses)
        }
        _ => Ok(Regeneration::Pending),
    }
}

/// True when this pair's `regenerates` row is already stored: it was proven
/// when it landed, so a carried copy, byte-equal or with new value fields
/// (an owner's weight), is no new pair, whatever has since become of its
/// MESSAGEs' bodies.
#[cfg(feature = "sync")]
pub(crate) fn regeneration_stored(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    new: &EntityId,
    source: &EntityId,
) -> crate::error::Result<bool> {
    Ok(crate::ports::EdgeStoreStaging::port_edge_encoded(
        store,
        txn,
        new,
        EdgeKind::Regenerates,
        source,
    )?
    .is_some())
}

/// Whether `id` is a live companion MESSAGE.
fn companion_message(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> crate::error::Result<Regeneration> {
    let body = match crate::vault::live_entity_row_in_txn(store, txn, id)? {
        crate::vault::LiveEntityRow::Absent => return Ok(Regeneration::Pending),
        crate::vault::LiveEntityRow::DeletedShell => return Ok(Regeneration::Erased),
        crate::vault::LiveEntityRow::Live { entity_type, body } => {
            if entity_type != crate::registry::ENTITY_TYPE_MESSAGE {
                return Ok(Regeneration::Refuses);
            }
            body
        }
    };
    #[cfg(feature = "sync")]
    let body = crate::entity_doc::resolve_record_body(store, txn, id, &body)?;
    let body: serde_json::Value = rmp_serde::from_slice(&body)
        .map_err(|_| crate::error::Error::CorruptedIndex("message body"))?;
    Ok(
        if body.get("author").and_then(serde_json::Value::as_str)
            == Some(crate::memory::WitnessAuthor::Companion.as_str())
        {
            Regeneration::Admits
        } else {
            Regeneration::Refuses
        },
    )
}

/// Up to two targets of `id`'s `kind` edges: a MESSAGE's axis has one.
fn message_axis(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    kind: EdgeKind,
) -> crate::error::Result<Vec<EntityId>> {
    let mut targets = Vec::new();
    for row in crate::ports::EdgeStoreRead::port_edges(
        store,
        txn,
        id,
        crate::ports::EdgeDirection::Out,
        Some(kind),
        None,
    )? {
        targets.push(row?.target);
        if targets.len() > 1 {
            break;
        }
    }
    Ok(targets)
}
