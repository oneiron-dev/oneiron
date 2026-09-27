//! Guard every raw and replicated REACTION put at the generic batch door.
use super::ReactionBody;
use crate::error::{Error, RecordError, Result};
use crate::registry::ENTITY_TYPE_REACTION;
use crate::store::Store;
use crate::{EntityId, TimeRange};
use heed::{RoTxn, RwTxn};
const PERMIT: &[u8] = b"reaction:typed_put:v1:";
fn key(id: &EntityId) -> Vec<u8> {
    [PERMIT, id.as_bytes()].concat()
}
const TRIPLE: &[u8] = b"reaction:triple:v1:";
fn triple_key(body: &ReactionBody) -> Vec<u8> {
    let mut key = Vec::with_capacity(TRIPLE.len() + 64);
    key.extend_from_slice(TRIPLE);
    key.extend_from_slice(body.msg.as_bytes());
    key.extend_from_slice(body.by.as_bytes());
    key.extend_from_slice(blake3::hash(body.glyph.as_bytes()).as_bytes());
    key
}

fn invalid(why: &'static str) -> Error {
    RecordError::InvalidReactionBody(why).into()
}

pub(super) fn permit(store: &Store, txn: &mut RwTxn<'_>, id: &EntityId) -> Result<()> {
    store.vault_meta.put(txn, &key(id), &[1])?;
    Ok(())
}
pub(super) fn finish(store: &Store, txn: &mut RwTxn<'_>, id: &EntityId) -> Result<()> {
    store.vault_meta.delete(txn, &key(id))?;
    Ok(())
}
pub(super) fn has_permit(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
    Ok(store.vault_meta.get(txn, &key(id))?.as_deref() == Some(&[1][..]))
}
pub(crate) fn guard_put(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    kind: u8,
    occurred: TimeRange,
    data: &[u8],
    replicated: bool,
) -> Result<()> {
    super::identity::guard_put(store, txn, id, kind, occurred, data, replicated)?;
    if kind != ENTITY_TYPE_REACTION {
        return Ok(());
    }
    let body = ReactionBody::from_bytes(data)?;
    if let Some(ext) = body.ext.clone()
        && super::identity::suppressed(store, txn, &ext.into())?
    {
        return Err(invalid("hard-erased provider generation"));
    }
    if occurred.start != body.at || occurred.end != body.at {
        return Err(invalid("occurrence differs from body"));
    }
    if !replicated && store.vault_meta.get(txn, &key(id))?.as_deref() != Some(&[1][..]) {
        return Err(invalid("reaction requires the typed door"));
    }
    // A replica can carry rows out of order, but an already-materialized
    // target or reactor must have the expected kind. The read projection
    // rechecks both after missing references arrive.
    for (reference, allowed) in [
        (
            body.msg,
            &[
                crate::registry::ENTITY_TYPE_MESSAGE,
                crate::registry::ENTITY_TYPE_TURN,
            ][..],
        ),
        (body.by, &[crate::registry::ENTITY_TYPE_PERSON][..]),
    ] {
        match crate::vault::live_entity_row_in_txn(store, txn, &reference)? {
            crate::vault::LiveEntityRow::Live { entity_type, .. }
                if allowed.contains(&entity_type) => {}
            crate::vault::LiveEntityRow::Absent if replicated => {}
            _ => return Err(invalid("reaction reference has wrong kind or is not live")),
        }
    }
    // Covers replay/batch puts too: a peer can deliver a body before either
    // edge, so an edges_in scan alone cannot guard this tuple.
    if let Some(prior) = store.vault_meta.get(txn, &triple_key(&body))? {
        let other = EntityId::from_bytes(
            prior
                .as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("reaction triple index"))?,
        )?;
        if other != *id
            && let crate::vault::LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_REACTION,
                body: existing,
            } = crate::vault::live_entity_row_in_txn(store, txn, &other)?
        {
            let existing = ReactionBody::from_bytes(&existing)
                .map_err(|_| Error::CorruptedIndex("reaction triple source"))?;
            if existing.msg != body.msg || existing.by != body.by || existing.glyph != body.glyph {
                return Err(Error::CorruptedIndex("reaction triple hash collision"));
            }
            // Concurrent offline adds are distinct audit records of one
            // logical OR-set element. Projection chooses one stable pill and
            // a local toggle removes every add this vault has observed.
        }
    }
    // Edges can precede a replicated body. Check everything already bound to
    // this id now; the reciprocal edge hook checks additions after the body.
    for edge in store.edges_out.prefix_iter(txn, id.as_bytes())? {
        let (key, _) = edge?;
        if key.len() != 33 {
            return Err(Error::CorruptedIndex("reaction edge key"));
        }
        let target = EntityId::from_bytes(
            key[17..33]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("reaction edge target"))?,
        )?;
        validate_binding(&body, key[16], target)?;
    }
    if let Some(prior) = store.entities.get(txn, id.as_bytes())? {
        let h = crate::batch::EntityMetadataHeader::parse(&prior)
            .ok_or(Error::CorruptedIndex("reaction header"))?;
        if h.entity_type != kind
            || h.occurred_start != body.at
            || h.occurred_end != body.at
            || prior.get(crate::batch::ENTITY_METADATA_HEADER_LEN..) != Some(data)
        {
            return Err(invalid("reaction ID is immutable"));
        }
    }
    Ok(())
}

/// A rebuildable local lookup for mirrored idempotency. It derives only from
/// the replicated body; the REACTION record remains the primary data.
pub(crate) fn index_external(
    store: &impl crate::store::ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    kind: u8,
    data: &[u8],
) -> Result<()> {
    if kind != ENTITY_TYPE_REACTION {
        return Ok(());
    }
    let body = ReactionBody::from_bytes(data)?;
    let Some(ext) = body.ext.as_ref() else {
        return Ok(());
    };
    let key = super::write::external_key(ext);
    let binding = super::write::external_binding(id, &body);
    if let Some(prior) = store.vault_meta().get(txn, &key)? {
        if prior.len() != binding.len() || prior[16..] != binding[16..] {
            return Err(invalid("external generation bound to another tuple"));
        }
        // Independently received copies of one provider generation are
        // aliases. This disposable lookup picks a stable physical id, never
        // decides which add is valid or blocks its replicated admission.
        if prior[..16] <= binding[..16] {
            return Ok(());
        }
    }
    store.vault_meta().put(txn, &key, &binding)?;
    Ok(())
}

/// Derived uniqueness projection, rebuilt on both typed and replicated puts.
pub(crate) fn index_triple(
    store: &impl crate::store::ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    kind: u8,
    data: &[u8],
) -> Result<()> {
    if kind != ENTITY_TYPE_REACTION {
        return Ok(());
    }
    let body = ReactionBody::from_bytes(data)?;
    let key = triple_key(&body);
    if let Some(prior) = store.vault_meta().get(txn, &key)? {
        let prior = EntityId::from_bytes(
            prior
                .as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("reaction triple index"))?,
        )?;
        if prior <= id {
            return Ok(());
        }
    }
    store.vault_meta().put(txn, &key, id.as_bytes())?;
    Ok(())
}

pub(super) fn clear_triple(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    body: &ReactionBody,
) -> Result<()> {
    let key = triple_key(body);
    if let Some(prior) = store.vault_meta.get(txn, &key)?
        && prior.as_ref() == id.as_bytes()
    {
        store.vault_meta.delete(txn, &key)?;
    }
    Ok(())
}

fn validate_binding(body: &ReactionBody, kind: u8, target: EntityId) -> Result<()> {
    if (kind == crate::EdgeKind::About as u8 && target == body.msg)
        || (kind == crate::EdgeKind::AuthoredBy as u8 && target == body.by)
    {
        Ok(())
    } else {
        Err(invalid("reaction edge differs from body"))
    }
}

/// All edge writers, including sync materialization, share this validation.
pub(crate) fn guard_edge(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    src: EntityId,
    kind: crate::EdgeKind,
    tgt: EntityId,
) -> Result<()> {
    let Some(raw) = store.entities().get(txn, src.as_bytes())? else {
        return Ok(());
    };
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("reaction edge source header"))?;
    if header.entity_type != ENTITY_TYPE_REACTION {
        return Ok(());
    }
    if raw.len() == crate::batch::ENTITY_METADATA_HEADER_LEN {
        // A tombstone can outrun its edges on a replica; the shell is never
        // rendered, and its original body cannot be checked at this point.
        return Ok(());
    }
    let body = ReactionBody::from_bytes(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
        .map_err(|_| Error::CorruptedIndex("reaction stored body"))?;
    validate_binding(&body, kind as u8, tgt)
}

/// Topology of a live reaction is immutable. DeleteEdge (including sync
/// replay) cannot detach the About/AuthoredBy binding and strand the triple.
pub(crate) fn guard_edge_delete(
    store: &Store,
    txn: &RoTxn<'_>,
    src: EntityId,
    kind: crate::EdgeKind,
    tgt: EntityId,
) -> Result<()> {
    if !matches!(kind, crate::EdgeKind::About | crate::EdgeKind::AuthoredBy) {
        return Ok(());
    }
    let crate::vault::LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_REACTION,
        body,
    } = crate::vault::live_entity_row_in_txn(store, txn, &src)?
    else {
        return Ok(());
    };
    let body = ReactionBody::from_bytes(&body)
        .map_err(|_| Error::CorruptedIndex("reaction stored body"))?;
    if (kind == crate::EdgeKind::About && tgt == body.msg)
        || (kind == crate::EdgeKind::AuthoredBy && tgt == body.by)
    {
        return Err(invalid("live reaction binding edges cannot be deleted"));
    }
    Ok(())
}

/// An existing REACTION id also owns its recorded-time envelope stamp.
/// Called at the same generic put chokepoint as `guard_put` before staging.
pub(crate) fn guard_recorded_at(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    kind: u8,
    learned_at: u64,
) -> Result<()> {
    if kind != ENTITY_TYPE_REACTION {
        return Ok(());
    }
    if let Some(prior) = store.entities.get(txn, id.as_bytes())? {
        let header = crate::batch::EntityMetadataHeader::parse(&prior)
            .ok_or(Error::CorruptedIndex("reaction header"))?;
        if header.learned_at != learned_at {
            return Err(invalid("reaction recorded time is immutable"));
        }
    }
    Ok(())
}
