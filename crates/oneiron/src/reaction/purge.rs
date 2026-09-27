//! Hard-erase cleanup for every derived reaction carrier, including sidecars.
use crate::EntityId;
use crate::batch::EntityMetadataHeader;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_REACTION;
use crate::store::Store;

pub(crate) fn purge_derived_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    reaction: EntityId,
) -> Result<()> {
    let Some(raw) = store.entities.get(txn, reaction.as_bytes())? else {
        return Ok(());
    };
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("reaction purge header"))?;
    if header.entity_type == crate::registry::ENTITY_TYPE_REACTION_BINDING {
        let body = raw[crate::batch::ENTITY_METADATA_HEADER_LEN..].to_vec();
        return super::identity::purge_binding(store, txn, &body);
    }
    if header.entity_type != ENTITY_TYPE_REACTION {
        return Ok(());
    }
    if raw.len() > crate::batch::ENTITY_METADATA_HEADER_LEN {
        let body =
            super::ReactionBody::from_bytes(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])?;
        if let Some(ext) = body.ext {
            super::identity::suppress_generation(store, txn, &ext.into())?;
        }
    }
    super::identity::purge_for_reaction(store, txn, reaction)?;
    crate::attempt_queue::purge_reaction_attempts_in_txn(store, txn, reaction)?;

    let mut keys = Vec::new();
    for entry in store.vault_meta.prefix_iter(txn, b"reaction_inbox:v1:")? {
        let (key, _) = entry?;
        let prefix = b"reaction_inbox:v1:".len();
        if key.len() != prefix + 41 {
            return Err(Error::CorruptedIndex("reaction inbox key"));
        }
        if &key[prefix + 24..prefix + 40] == reaction.as_bytes() {
            keys.push(key.to_vec());
        }
    }
    for entry in store
        .vault_meta
        .prefix_iter(txn, b"reaction:pending_signal:v1:")?
    {
        let (key, _) = entry?;
        let prefix = b"reaction:pending_signal:v1:".len();
        if key.len() != prefix + 32 {
            return Err(Error::CorruptedIndex("reaction pending key"));
        }
        if &key[prefix + 16..] == reaction.as_bytes() {
            keys.push(key.to_vec());
        }
    }
    for entry in store
        .vault_meta
        .prefix_iter(txn, b"reaction:pending_by:v1:")?
    {
        let (key, _) = entry?;
        let prefix = b"reaction:pending_by:v1:".len();
        if key.len() != prefix + 32 {
            return Err(Error::CorruptedIndex("reaction pending reactor key"));
        }
        if &key[prefix + 16..] == reaction.as_bytes() {
            keys.push(key.to_vec());
        }
    }
    for prefix in [
        b"reaction:triple:v1:".as_slice(),
        b"reaction:external:v1:".as_slice(),
    ] {
        for entry in store.vault_meta.prefix_iter(txn, prefix)? {
            let (key, value) = entry?;
            if value.len() < 16 {
                return Err(Error::CorruptedIndex("reaction index value"));
            }
            if &value[..16] == reaction.as_bytes() {
                keys.push(key.to_vec());
            }
        }
    }
    for key in keys {
        store.vault_meta.delete(txn, &key)?;
    }
    Ok(())
}
