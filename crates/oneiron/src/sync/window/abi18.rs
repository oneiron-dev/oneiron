//! One-shot conversion of persisted v17 live window envelopes before replay.

use loro::LoroDoc;

use super::{
    export_history_free_window_snapshot, history_free_window_required, persist_window_doc_in_txn,
};
use crate::sync::WindowKey;
use crate::sync::loro_support::{
    doc_version_vector, export_snapshot, map_for_each_bytes, map_insert_bytes,
};
use crate::{Error, Result, Vault};

pub(crate) fn upgrade_persisted_windows(vault: &Vault) -> Result<()> {
    // Run before Vault::open publishes a handle. No v18 incoming update may
    // mix with the old envelopes while their meaning is being converted.
    let keys = {
        let txn = vault.store.env.read_txn()?;
        vault
            .store
            .sync_state
            .prefix_iter(&txn, "abi18:w:")?
            .map(|row| row.map(|(key, _)| key[8..].to_string()))
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    for key in keys {
        let key = WindowKey::try_new(key).ok_or(Error::CorruptedIndex("v17 sync window key"))?;
        match super::load_window_from_state(vault, "abi18", &key) {
            Ok(_) => {}
            Err(Error::Sync(crate::error::SyncError::WindowNotFound { .. })) => {
                let doc = LoroDoc::new();
                super::apply_pending_window_updates(vault, &doc, &key)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(super) fn upgrade_window(
    vault: &Vault,
    doc: &LoroDoc,
    key: &WindowKey,
    update_keys: &[String],
) -> Result<()> {
    let marker = format!("abi18:w:{key}");
    {
        let rtxn = vault.store.env.read_txn()?;
        if vault.store.sync_state.get(&rtxn, &marker)?.is_none() {
            return Ok(());
        }
    }
    let entities = doc.get_map("entities");
    let mut values = Vec::new();
    map_for_each_bytes(&entities, |id, blob| {
        values.push((id.to_owned(), blob.to_vec()));
    });
    for (id, mut blob) in values {
        if crate::batch::EntityMetadataHeader::parse(&blob).is_none() {
            return Err(Error::CorruptedIndex("v17 sync entity envelope"));
        }
        let next = crate::store::migrated_v17_type_byte(blob[0]);
        if next != blob[0] {
            blob[0] = next;
            map_insert_bytes(&entities, &id, &blob)?;
        }
    }
    // These are new CRDT operations over the live map, not a rewrite of old
    // immutable operations. Pending updates were imported before conversion.
    doc.commit();
    let state = if history_free_window_required(vault, key)? {
        export_history_free_window_snapshot(doc)?
    } else {
        export_snapshot(doc)?
    };
    let vv = doc_version_vector(doc);
    vault.with_write_txn(|txn| {
        persist_window_doc_in_txn(vault, txn, key, &state, &vv)?;
        for key in update_keys {
            vault.store.sync_state.delete(txn, key)?;
        }
        super::write_window_svf_in_txn(vault, txn, key)?;
        vault.store.sync_state.delete(txn, &marker)?;
        Ok(())
    })
}
