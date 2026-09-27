//! One transaction-local lifecycle resolver for reaction admission projections.
//! Missing replay dependencies stay pending; malformed topology stays inert.
use super::ReactionBody;
use crate::error::{Error, Result};
use crate::registry::{
    ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON, ENTITY_TYPE_REACTION, ENTITY_TYPE_TURN,
};
use crate::store::ManifestDbs;
use crate::{EdgeKind, EntityId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReactionResolution {
    Pending,
    Invalid,
    Active { room: EntityId },
    Revoked { room: EntityId },
    SuppressedAlias,
    HardErased,
}
impl ReactionResolution {
    pub(crate) fn ready(self) -> bool {
        matches!(self, Self::Active { .. } | Self::Revoked { .. })
    }
    pub(crate) fn active(self) -> bool {
        matches!(self, Self::Active { .. })
    }
}

fn entity_kind(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<(u8, usize)>> {
    let Some(raw) = store.entities().get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let h = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("reaction resolver header"))?;
    Ok(Some((h.entity_type, raw.len())))
}
fn sole_target(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
) -> Result<std::result::Result<Option<EntityId>, ()>> {
    let mut prefix = src.as_bytes().to_vec();
    prefix.push(kind as u8);
    let mut entries = store.edges_out().prefix_iter(txn, &prefix)?;
    let Some((key, _)) = entries.next().transpose()? else {
        return Ok(Ok(None));
    };
    if entries.next().transpose()?.is_some() {
        return Ok(Err(()));
    }
    if key.len() != 33 {
        return Err(Error::CorruptedIndex("reaction resolver edge"));
    }
    Ok(Ok(Some(EntityId::from_bytes(
        key[17..33]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("reaction resolver target"))?,
    )?)))
}

pub(crate) fn room_in(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    message: EntityId,
) -> Result<Option<EntityId>> {
    let mut pending = vec![message];
    let mut seen = std::collections::BTreeSet::new();
    let mut room = None;
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
        }
        if seen.len() > crate::limits::MAX_ANCESTOR_DEPTH {
            return Err(Error::IndexOverflow("reaction room ancestry"));
        }
        let Some(raw) = store.entities().get(txn, id.as_bytes())? else {
            return Ok(None);
        };
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("reaction room ancestor"))?;
        if header.entity_type == crate::registry::ENTITY_TYPE_CONVERSATION {
            if room.is_some_and(|prior| prior != id) {
                return Ok(None);
            }
            room = Some(id);
            continue;
        }
        for kind in [
            EdgeKind::ChildOf,
            EdgeKind::PartOf,
            EdgeKind::Parent,
            EdgeKind::RepliesTo,
            EdgeKind::SpawnedBy,
            EdgeKind::BelongsTo,
        ] {
            let mut prefix = id.as_bytes().to_vec();
            prefix.push(kind as u8);
            for (n, entry) in store.edges_out().prefix_iter(txn, &prefix)?.enumerate() {
                if n >= crate::limits::MAX_ANCESTOR_DEPTH {
                    return Err(Error::IndexOverflow("reaction room edges"));
                }
                let (key, _) = entry?;
                if key.len() != 33 {
                    return Err(Error::CorruptedIndex("reaction room edge"));
                }
                pending.push(EntityId::from_bytes(
                    key[17..33]
                        .try_into()
                        .map_err(|_| Error::CorruptedIndex("reaction room target"))?,
                )?);
            }
        }
    }
    Ok(room)
}

/// Resolve the immutable add and its historical room audience in the
/// transaction that projects a pill, signal, or shared scoped read.
pub(crate) fn resolve(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    body: &ReactionBody,
) -> Result<ReactionResolution> {
    use ReactionResolution::{Active, HardErased, Invalid, Pending, Revoked, SuppressedAlias};
    if store
        .sync_state()
        .get(txn, &crate::deletion::local_hard_delete_key(&id))?
        .is_some()
    {
        return Ok(HardErased);
    }
    if let Some(ext) = body.ext.clone()
        && super::identity::suppressed(store, txn, &ext.into())?
    {
        return Ok(HardErased);
    }
    let Some((kind, size)) = entity_kind(store, txn, id)? else {
        return Ok(Pending);
    };
    if kind != ENTITY_TYPE_REACTION {
        return Ok(Invalid);
    }
    let shell = size == crate::batch::ENTITY_METADATA_HEADER_LEN;
    if !shell {
        let raw = store
            .entities()
            .get(txn, id.as_bytes())?
            .ok_or(Error::CorruptedIndex("reaction resolver source"))?;
        let persisted = ReactionBody::from_bytes(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])?;
        if persisted.msg != body.msg
            || persisted.by != body.by
            || persisted.glyph != body.glyph
            || persisted.at != body.at
        {
            return Ok(Invalid);
        }
        if let Some(ext) = persisted.ext
            && super::identity::suppressed(store, txn, &ext.into())?
        {
            return Ok(HardErased);
        }
    }
    match entity_kind(store, txn, body.msg)? {
        None => return Ok(Pending),
        Some((kind, size))
            if !matches!(kind, ENTITY_TYPE_MESSAGE | ENTITY_TYPE_TURN)
                || size == crate::batch::ENTITY_METADATA_HEADER_LEN =>
        {
            return Ok(Invalid);
        }
        _ => {}
    }
    match entity_kind(store, txn, body.by)? {
        None => return Ok(Pending),
        Some((kind, size))
            if kind != ENTITY_TYPE_PERSON || size == crate::batch::ENTITY_METADATA_HEADER_LEN =>
        {
            return Ok(Invalid);
        }
        _ => {}
    }
    for (kind, expected) in [(EdgeKind::About, body.msg), (EdgeKind::AuthoredBy, body.by)] {
        match sole_target(store, txn, id, kind)? {
            Ok(None) => return Ok(Pending),
            Ok(Some(target)) if target == expected => {}
            Ok(Some(_)) | Err(()) => return Ok(Invalid),
        }
    }
    let Some(room) = room_in(store, txn, body.msg)? else {
        return Ok(Pending);
    };
    if !crate::conversation::member_at_store(store, txn, room, body.by, body.at)? {
        return Ok(Invalid);
    }
    if !shell && super::identity::generation_revoked_for(store, txn, id, body)? {
        return Ok(SuppressedAlias);
    }
    Ok(if shell {
        Revoked { room }
    } else {
        Active { room }
    })
}
