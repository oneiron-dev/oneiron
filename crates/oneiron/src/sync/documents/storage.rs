//! Snapshot-then-update recovery and transactional text-plane persistence.

use crate::error::{Error, Result, SyncEngineContext, SyncProtocolValidation};
use crate::sync::loro_support::doc_from_snapshot;
use crate::{EntityId, Vault};
use loro::{ExportMode, LoroDoc, VersionVector};

pub(super) fn load(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<LoroDoc> {
    let hex = id.to_hex();
    let doc = match vault.store.sync_state.get(txn, &format!("d:e:{hex}"))? {
        Some(bytes) => doc_from_snapshot(&bytes)?,
        None => LoroDoc::new(),
    };
    let prefix = format!("u:e:{hex}:");
    for row in vault.store.sync_state.prefix_iter(txn, &prefix)? {
        let (key, bytes) = row?;
        let seq = &key[prefix.len()..];
        if seq.len() != 8 || u32::from_str_radix(seq, 16).is_err() {
            return Err(Error::sync_protocol(
                SyncProtocolValidation::InvalidDocumentKey,
            ));
        }
        import_complete(&doc, &bytes)?;
    }
    Ok(doc)
}

pub(super) fn import_complete(doc: &LoroDoc, bytes: &[u8]) -> Result<()> {
    let status = doc.import(bytes).map_err(|source| {
        crate::error::Error::Sync(crate::error::SyncError::CrdtDecodeError {
            context: "entity document import",
            source,
        })
    })?;
    if status.pending.is_some() {
        return Err(Error::sync_protocol(
            SyncProtocolValidation::DocumentPendingUpdate,
        ));
    }
    Ok(())
}

pub(super) fn append(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    bytes: &[u8],
) -> Result<u32> {
    let hex = id.to_hex();
    let seq_key = format!("m:u_seq:e:{hex}");
    let seq = match vault.store.sync_state.get(txn, &seq_key)? {
        Some(bytes) => u32::from_be_bytes(
            bytes[..]
                .try_into()
                .map_err(|_| Error::sync_protocol(SyncProtocolValidation::InvalidDocumentKey))?,
        ),
        None => 0,
    }
    .checked_add(1)
    .ok_or(Error::InvariantViolation("document sequence exhausted"))?;
    vault
        .store
        .sync_state
        .put(txn, &format!("u:e:{hex}:{seq:08x}"), bytes)?;
    vault
        .store
        .sync_state
        .put(txn, &seq_key, &seq.to_be_bytes())?;
    // Absence denotes a stale cached state vector. Recovery never trusts it.
    vault.store.sync_state.delete(txn, &format!("sv:e:{hex}"))?;
    Ok(seq)
}

pub(super) fn snapshot(
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
            .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportSnapshot, e))?
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
    let prefix = format!("u:e:{hex}:");
    let keys = vault
        .store
        .sync_state
        .prefix_iter(txn, &prefix)?
        .map(|r| r.map(|(k, _)| k.to_string()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for key in keys {
        vault.store.sync_state.delete(txn, &key)?;
    }
    Ok(())
}

pub(super) fn state_copy(doc: &LoroDoc) -> Result<Vec<u8>> {
    doc.export(ExportMode::StateOnly(None))
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportShallowSnapshot, e))
}

pub(super) fn decode_vv(bytes: &[u8]) -> Result<VersionVector> {
    VersionVector::decode(bytes).map_err(|source| {
        Error::Sync(crate::error::SyncError::CrdtDecodeError {
            context: "entity document version vector",
            source,
        })
    })
}

/// A closed document is compacted under the write lock, so no stale read can overwrite an append.
pub(crate) fn compact(vault: &Vault, id: EntityId, erased: bool) -> Result<()> {
    vault.with_write_txn(|txn| {
        let doc = load(vault, txn, id)?;
        // An erased entity has no editable state. Drop every container, including
        // unknown peer-authored containers, rather than scrubbing two known names.
        let doc = if erased {
            let keys: Vec<_> = vault
                .store
                .sync_state
                .prefix_iter(txn, &format!("qd:e:{}:", id.to_hex()))?
                .map(|row| row.map(|(key, _)| key.to_string()))
                .collect::<std::result::Result<_, _>>()?;
            for key in keys {
                vault.store.sync_state.delete(txn, &key)?;
            }
            LoroDoc::new()
        } else {
            doc
        };
        snapshot(vault, txn, id, &doc, true)
    })
}
