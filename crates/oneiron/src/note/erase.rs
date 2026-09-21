//! Active-store erasure of NOTE snapshots and workflow text, including headerless residue.

use super::documents::{head_key, invalid};
use super::{NoteFork, NoteLandingReceipt, NoteReviewBundle};
use crate::{EntityId, Vault, error::Result};

fn decoded<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T> {
    rmp_serde::from_slice(raw).map_err(|_| invalid("stored NOTE workflow"))
}

pub(crate) fn scope_exists(vault: &Vault, txn: &heed::RoTxn<'_>, note: &EntityId) -> Result<bool> {
    if vault
        .store
        .sync_state
        .prefix_iter(txn, "note_inbox:v1:")?
        .next()
        .transpose()?
        .is_some()
    {
        return Ok(true);
    }

    if vault.store.vault_meta.get(txn, &head_key(*note))?.is_some()
        || vault
            .store
            .sync_state
            .prefix_iter(txn, &format!("note_proposal_doc:v1:{}:", note.to_hex()))?
            .next()
            .transpose()?
            .is_some()
    {
        return Ok(true);
    }
    for row in vault.store.vault_meta.prefix_iter(txn, b"note_fork:v1:")? {
        let (_, raw) = row?;
        if decoded::<NoteFork>(&raw)?.note == *note {
            return Ok(true);
        }
    }
    for row in vault
        .store
        .vault_meta
        .prefix_iter(txn, b"note_receipt:v1:")?
    {
        let (_, raw) = row?;
        if decoded::<NoteLandingReceipt>(&raw)?.note == *note {
            return Ok(true);
        }
    }
    for row in vault
        .store
        .vault_meta
        .prefix_iter(txn, b"note_proposal:v1:")?
    {
        let (_, raw) = row?;
        let bundle: NoteReviewBundle = decoded(&raw)?;
        if bundle.waiting.iter().any(|fork| fork.note == *note)
            || bundle.landed.iter().any(|receipt| receipt.note == *note)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Runs for every id, not just rows whose NOTE type header survived.
pub(crate) fn purge(vault: &Vault, txn: &mut heed::RwTxn<'_>, note: &EntityId) -> Result<bool> {
    let mut removed = vault.store.vault_meta.delete(txn, &head_key(*note))?;
    // Untrusted workflow inbox entries can span several notes and contain an
    // unpartitionable explainer. Conservatively discard all on hard erasure.
    let inbox = vault
        .store
        .sync_state
        .prefix_iter(txn, "note_inbox:v1:")?
        .map(|row| row.map(|(key, _)| key.to_string()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for key in inbox {
        removed |= vault.store.sync_state.delete(txn, &key)?;
    }

    let keys = vault
        .store
        .sync_state
        .prefix_iter(txn, &format!("note_proposal_doc:v1:{}:", note.to_hex()))?
        .map(|row| row.map(|(key, _)| key.to_string()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for key in keys {
        removed |= vault.store.sync_state.delete(txn, &key)?;
    }
    let mut metadata = Vec::new();
    for row in vault.store.vault_meta.prefix_iter(txn, b"note_fork:v1:")? {
        let (key, raw) = row?;
        if decoded::<NoteFork>(&raw)?.note == *note {
            metadata.push(key.to_vec());
        }
    }
    for row in vault
        .store
        .vault_meta
        .prefix_iter(txn, b"note_receipt:v1:")?
    {
        let (key, raw) = row?;
        if decoded::<NoteLandingReceipt>(&raw)?.note == *note {
            metadata.push(key.to_vec());
        }
    }
    let mut replacements = Vec::new();
    for row in vault
        .store
        .vault_meta
        .prefix_iter(txn, b"note_proposal:v1:")?
    {
        let (key, raw) = row?;
        let mut bundle: NoteReviewBundle = decoded(&raw)?;
        let before = bundle.waiting.len() + bundle.landed.len();
        bundle.waiting.retain(|fork| fork.note != *note);
        bundle.landed.retain(|receipt| receipt.note != *note);
        let after = bundle.waiting.len() + bundle.landed.len();
        if before == after {
            continue;
        }
        removed = true;
        if after == 0 {
            metadata.push(key.to_vec());
        } else {
            // The shared free-text explainer can quote any member. Keep only
            // unaffected membership, never its unpartitionable original text.
            bundle.explainer = "redacted".to_owned();
            replacements.push((
                key.to_vec(),
                rmp_serde::to_vec_named(&bundle).map_err(|_| invalid("NOTE proposal encode"))?,
            ));
        }
    }
    for key in metadata {
        removed |= vault.store.vault_meta.delete(txn, &key)?;
    }
    for (key, bytes) in replacements {
        vault.store.vault_meta.put(txn, &key, &bytes)?;
    }
    Ok(removed)
}
