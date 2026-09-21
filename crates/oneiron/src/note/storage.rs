//! Canonical entity-document carriers shared by local NOTE edits and sync.
use super::documents::invalid;
use crate::{EntityId, Result, Vault};
use loro::{ExportMode, LoroDoc};

pub(crate) fn load(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<LoroDoc> {
    super::ensure_citations_ready(&vault.store, txn, id)?;
    load_for_erasure(vault, txn, id)
}

pub(crate) fn load_for_erasure(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<LoroDoc> {
    load_seeded(&vault.store, txn, id, || {
        Ok(super::document_birth_in_txn(vault, txn, id)?.unwrap_or_default())
    })
}

pub(super) fn load_seeded(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    birth: impl FnOnce() -> Result<LoroDoc>,
) -> Result<LoroDoc> {
    let hex = id.to_hex();
    let doc = match store.sync_state.get(txn, &format!("d:e:{hex}"))? {
        Some(bytes) => {
            let doc = LoroDoc::new();
            import_complete(&doc, &bytes)?;
            doc
        }
        None => birth()?,
    };
    let prefix = format!("u:e:{hex}:");
    for row in store.sync_state.prefix_iter(txn, &prefix)? {
        let (key, bytes) = row?;
        let seq = &key[prefix.len()..];
        if seq.len() != 8 || u32::from_str_radix(seq, 16).is_err() {
            return Err(invalid("invalid canonical document update key"));
        }
        import_complete(&doc, &bytes)?;
    }
    Ok(doc)
}

pub(crate) fn import_complete(doc: &LoroDoc, bytes: &[u8]) -> Result<()> {
    let status = doc
        .import(bytes)
        .map_err(|_| invalid("invalid canonical document bytes"))?;
    if status.pending.is_some() {
        return Err(invalid("canonical document has pending dependencies"));
    }
    Ok(())
}

pub(crate) fn snapshot(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    doc: &LoroDoc,
    shallow: bool,
) -> Result<()> {
    let hex = id.to_hex();
    let bytes = if shallow {
        state_copy(doc)?
    } else {
        doc.export(ExportMode::Snapshot)
            .map_err(|_| invalid("canonical document snapshot"))?
    };
    vault
        .store
        .sync_state
        .put(txn, &format!("d:e:{hex}"), &bytes)?;
    vault
        .store
        .sync_state
        .put(txn, &format!("sv:e:{hex}"), &doc.oplog_vv().encode())?;
    if shallow {
        vault
            .store
            .sync_state
            .put(txn, &format!("ssv:e:{hex}"), &doc.oplog_vv().encode())?;
    }
    let keys = vault
        .store
        .sync_state
        .prefix_iter(txn, &format!("u:e:{hex}:"))?
        .map(|r| r.map(|(k, _)| k.to_string()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for key in keys {
        vault.store.sync_state.delete(txn, &key)?;
    }
    Ok(())
}

pub(crate) fn state_copy(doc: &LoroDoc) -> Result<Vec<u8>> {
    doc.export(ExportMode::StateOnly(None))
        .map_err(|_| invalid("canonical document state"))
}
