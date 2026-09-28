//! Active-store erasure of NOTE snapshots and workflow text, including headerless residue.

use super::documents::{NOTE_HEAD, NOTE_PROPOSAL_DOC};
use super::proposals::{NOTE_FORK, NOTE_PROPOSAL_BUNDLE, NOTE_RECEIPT};
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Vault, error::Result};

/// Marks a window whose peer-authored NOTE inbox residue was staged.
const SYNC_NOTE_INBOX: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_NOTE_INBOX);

pub(crate) fn scope_exists(vault: &Vault, txn: &heed::RoTxn<'_>, note: &EntityId) -> Result<bool> {
    if !SYNC_NOTE_INBOX
        .scan_keys(&vault.store, txn, &[])?
        .is_empty()
    {
        return Ok(true);
    }

    if NOTE_HEAD.contains(&vault.store, txn, note)?
        || !NOTE_PROPOSAL_DOC
            .scan_keys(&vault.store, txn, format!("{}:", note.to_hex()).as_bytes())?
            .is_empty()
    {
        return Ok(true);
    }
    for (_, fork) in NOTE_FORK.scan(&vault.store, txn)? {
        if fork.note == *note {
            return Ok(true);
        }
    }
    for (_, receipt) in NOTE_RECEIPT.scan(&vault.store, txn)? {
        if receipt.note == *note {
            return Ok(true);
        }
    }
    for (_, bundle) in NOTE_PROPOSAL_BUNDLE.scan(&vault.store, txn)? {
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
    let mut removed = NOTE_HEAD.delete(&vault.store, txn, note)?;
    // Workflow markers can span several notes. Conservatively discard all on hard erasure.
    let inbox = SYNC_NOTE_INBOX.scan_keys(&vault.store, txn, &[])?;
    for key in inbox {
        removed |= SYNC_NOTE_INBOX.delete(&vault.store, txn, &key)?;
    }

    let keys =
        NOTE_PROPOSAL_DOC.scan_keys(&vault.store, txn, format!("{}:", note.to_hex()).as_bytes())?;
    for key in keys {
        removed |= NOTE_PROPOSAL_DOC.delete(&vault.store, txn, &key)?;
    }
    let mut metadata = Vec::new();
    for (key, fork) in NOTE_FORK.scan(&vault.store, txn)? {
        if fork.note == *note {
            metadata.push(Metadata::Fork(key));
        }
    }
    for (key, receipt) in NOTE_RECEIPT.scan(&vault.store, txn)? {
        if receipt.note == *note {
            metadata.push(Metadata::Receipt(key));
        }
    }
    let mut replacements = Vec::new();
    for (key, mut bundle) in NOTE_PROPOSAL_BUNDLE.scan(&vault.store, txn)? {
        let before = bundle.waiting.len() + bundle.landed.len();
        bundle.waiting.retain(|fork| fork.note != *note);
        bundle.landed.retain(|receipt| receipt.note != *note);
        let after = bundle.waiting.len() + bundle.landed.len();
        if before == after {
            continue;
        }
        removed = true;
        if after == 0 {
            metadata.push(Metadata::Bundle(key));
        } else {
            // The shared free-text explainer can quote any member. Keep only
            // unaffected membership, never its unpartitionable original text.
            bundle.explainer = "redacted".to_owned();
            replacements.push((key, bundle));
        }
    }
    for entry in metadata {
        removed |= match entry {
            Metadata::Fork(key) => NOTE_FORK.delete(&vault.store, txn, &key)?,
            Metadata::Receipt(key) => NOTE_RECEIPT.delete(&vault.store, txn, &key)?,
            Metadata::Bundle(key) => NOTE_PROPOSAL_BUNDLE.delete(&vault.store, txn, &key)?,
        };
    }
    for (key, bundle) in replacements {
        NOTE_PROPOSAL_BUNDLE.put(&vault.store, txn, &key, &bundle)?;
    }
    Ok(removed)
}

enum Metadata {
    Fork(EntityId),
    Receipt(EntityId),
    Bundle(EntityId),
}
