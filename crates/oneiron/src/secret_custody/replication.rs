//! Name-index planning for admitted same-vault custody replay.

use crate::entity_id::EntityId;
use crate::error::{Error, Result, SecretError};
use crate::store::Store;

use super::SecretCustodyStatus;
use super::codec::{decode_secret_custody_body, invalid_body};
use super::doors::{name_index_key, read_secret_custody_in_txn, resolve_secret_ref_in_txn};

/// Read-only planning precedes all staging: rejected replay must not leave an
/// index behind when the caller quarantines the row and commits other writes.
pub(crate) fn plan_replicated_name_index(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<Option<Vec<u8>>> {
    let incoming = decode_secret_custody_body(body)?;
    if let Some(raw) = store.entities.get(txn, id.as_bytes())?
        && raw.first() == Some(&crate::registry::ENTITY_TYPE_SECRET_CUSTODY)
    {
        let previous = decode_secret_custody_body(
            raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
                .ok_or(Error::CorruptedIndex("secret custody entity header"))?,
        )?;
        if previous.name != incoming.name {
            return Err(invalid_body("replicated custody name is immutable"));
        }
    }
    if let Some(owner) = resolve_secret_ref_in_txn(store, txn, &incoming.name)?
        && owner != *id
        && let Some(existing) = read_secret_custody_in_txn(store, txn, &owner)?
    {
        // A replayed old tombstone must not displace a name's new life.
        if incoming.status == SecretCustodyStatus::Revoked {
            return Ok(None);
        }
        if existing.status != SecretCustodyStatus::Revoked {
            return Err(Error::Secret(SecretError::SecretNameInUse {
                name: incoming.name,
            }));
        }
        // Match registration's high-water rule without rewriting settled bytes.
        if incoming.rotation_generation <= existing.rotation_generation {
            return Err(invalid_body(
                "replicated name reclaim must advance generation",
            ));
        }
    }
    Ok(Some(name_index_key(&incoming.name)))
}
