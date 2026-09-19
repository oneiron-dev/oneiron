//! Transactional revision ledger. All base put paths enter this capture seam.

use super::{ReadMode, RevisionRef};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::store::ManifestDbs;
use crate::{EntityId, Vault};
use heed::{RoTxn, RwTxn};
use loro::{ExportMode, Frontiers, LoroDoc, LoroValue, ValueOrContainer};
use serde::{Deserialize, Serialize};

pub(super) const STATE: &[u8] = b"entity_revision:state:";
const DOC: &[u8] = b"entity_revision:doc:";
const FRONTIER: &[u8] = b"entity_revision:frontier:";

#[derive(Serialize, Deserialize)]
pub(super) struct RevisionState {
    pub live: RevisionRef,
    pub indexed: RevisionRef,
    pub changed_at_ms: u64,
    pub has_doc: bool,
}

pub(super) fn key(prefix: &[u8], id: &EntityId) -> Vec<u8> {
    [prefix, id.as_bytes()].concat()
}

pub(super) fn state(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<RevisionState>> {
    store
        .vault_meta()
        .get(txn, &key(STATE, id))?
        .map(|raw| {
            rmp_serde::from_slice(&raw).map_err(|_| Error::CorruptedIndex("entity revision state"))
        })
        .transpose()
}

pub(super) fn put_state(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    value: &RevisionState,
) -> Result<()> {
    let raw = rmp_serde::to_vec_named(value)
        .map_err(|_| Error::InvariantViolation("entity revision encode"))?;
    store.vault_meta().put(txn, &key(STATE, id), &raw)?;
    Ok(())
}

pub(super) fn reference(id: &EntityId, raw: &[u8]) -> RevisionRef {
    let mut hash = blake3::Hasher::new();
    hash.update(id.as_bytes());
    hash.update(raw);
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&hash.finalize().as_bytes()[..16]);
    RevisionRef(bytes)
}

/// All top-level string leaves are independent text containers. The raw
/// register preserves the record codec exactly at every recorded frontier;
/// it is not used to merge independently edited text.
pub(super) fn text_fields(body: &[u8]) -> Vec<(String, String)> {
    let Ok(rmpv::Value::Map(fields)) = rmpv::decode::read_value(&mut std::io::Cursor::new(body))
    else {
        return Vec::new();
    };
    fields
        .into_iter()
        .filter_map(|(name, value)| {
            let name = name.as_str()?;
            if !matches!(
                name,
                "content" | "text" | "body" | "markdown" | "description" | "title" | "name" | "val"
            ) {
                return None;
            }
            Some((name.to_owned(), value.as_str()?.to_owned()))
        })
        .collect()
}

pub(super) fn write_doc_row(doc: &LoroDoc, raw: &[u8]) -> Result<()> {
    let fields = text_fields(
        raw.get(ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("entity revision header"))?,
    );
    // Removed fields are emptied, so later cursor resolution cannot mistake
    // an orphaned text container for a still-present body leaf.
    let names = doc.get_map("text_fields");
    let mut previous = Vec::new();
    names.for_each(|name, _| previous.push(name.to_owned()));
    for name in previous {
        if !fields.iter().any(|(current, _)| current == &name) {
            doc.get_text(format!("field:{name}"))
                .update("", Default::default())
                .map_err(|_| Error::InvariantViolation("entity text update"))?;
            names
                .delete(&name)
                .map_err(|_| Error::InvariantViolation("entity text field delete"))?;
        }
    }
    for (name, text) in fields {
        doc.get_text(format!("field:{name}"))
            .update(&text, Default::default())
            .map_err(|_| Error::InvariantViolation("entity text update"))?;
        names
            .insert(&name, true)
            .map_err(|_| Error::InvariantViolation("entity text field insert"))?;
    }
    doc.get_map("record")
        .insert("raw", raw)
        .map_err(|_| Error::InvariantViolation("entity revision insert"))?;
    doc.commit();
    Ok(())
}

fn frontier_key(id: &EntityId, revision: RevisionRef) -> Vec<u8> {
    [key(FRONTIER, id), revision.0.to_vec()].concat()
}

pub(super) fn retain_frontier(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    revision: RevisionRef,
    doc: &LoroDoc,
) -> Result<()> {
    store.vault_meta().put(
        txn,
        &frontier_key(id, revision),
        &doc.oplog_frontiers().encode(),
    )?;
    store.vault_meta().put(
        txn,
        &[b"entity_revision:identity:".as_slice(), &revision.0].concat(),
        id.as_bytes(),
    )?;
    Ok(())
}

pub(super) fn save_doc(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    doc: &LoroDoc,
) -> Result<()> {
    let bytes = doc
        .export(ExportMode::Snapshot)
        .map_err(|_| Error::InvariantViolation("entity document export"))?;
    store.vault_meta().put(txn, &key(DOC, id), &bytes)?;
    Ok(())
}

pub(super) fn load_doc(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<LoroDoc> {
    let bytes = store
        .vault_meta()
        .get(txn, &key(DOC, id))?
        .ok_or(Error::CorruptedIndex("entity document missing"))?;
    LoroDoc::from_snapshot(&bytes).map_err(|_| Error::CorruptedIndex("entity document"))
}

pub(super) fn fork_revision(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    revision: RevisionRef,
) -> Result<LoroDoc> {
    let raw = store
        .vault_meta()
        .get(txn, &frontier_key(id, revision))?
        .ok_or(Error::EntityNotFound)?;
    let frontier = Frontiers::decode(&raw).map_err(|_| Error::CorruptedIndex("entity frontier"))?;
    let doc = load_doc(store, txn, id)?
        .fork_at(&frontier)
        .map_err(|_| Error::CorruptedIndex("retained entity frontier"))?;
    if reference(id, &raw) != revision && reference(id, &doc_raw(&doc)?) != revision {
        return Err(Error::CorruptedIndex("entity frontier reference mismatch"));
    }
    Ok(doc)
}

pub(super) fn doc_raw(doc: &LoroDoc) -> Result<Vec<u8>> {
    match doc.get_map("record").get("raw") {
        Some(ValueOrContainer::Value(LoroValue::Binary(bytes))) => Ok(bytes.to_vec()),
        _ => Err(Error::CorruptedIndex("entity revision raw record")),
    }
}

/// Called before replacement, so both the old and new frontier are retained
/// atomically with the body write. Never copies secret custody into history.
pub(crate) fn capture_entity_revision(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    new_raw: &[u8],
) -> Result<()> {
    let header = EntityMetadataHeader::parse(new_raw)
        .ok_or(Error::CorruptedIndex("entity revision header"))?;
    if header.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY {
        return Ok(());
    }
    let prior = store
        .entities()
        .get(txn, id.as_bytes())?
        .map(|r| r.to_vec());
    let existing = state(store, txn, id)?;
    // Opaque/immutable structural rows need no document until explicitly pinned.
    if existing.is_none() && text_fields(&new_raw[ENTITY_METADATA_HEADER_LEN..]).is_empty() {
        return Ok(());
    }
    let next = reference(id, new_raw);
    let now_ms = unix_millis_at(std::time::SystemTime::now());
    let Some(mut current) = existing else {
        let mut current = RevisionState {
            live: next,
            indexed: next,
            changed_at_ms: now_ms,
            has_doc: false,
        };
        if let Some(old) = prior.as_deref().filter(|old| *old != new_raw) {
            let doc = LoroDoc::new();
            write_doc_row(&doc, old)?;
            current.indexed = reference(id, old);
            retain_frontier(store, txn, id, current.indexed, &doc)?;
            write_doc_row(&doc, new_raw)?;
            current.live = reference(id, &doc.oplog_frontiers().encode());
            retain_frontier(store, txn, id, current.live, &doc)?;
            save_doc(store, txn, id, &doc)?;
            current.has_doc = true;
        }
        store.vault_meta().put(
            txn,
            &[b"entity_revision:identity:".as_slice(), &current.live.0].concat(),
            id.as_bytes(),
        )?;
        return put_state(store, txn, id, &current);
    };
    if prior.as_deref() == Some(new_raw) {
        return Ok(());
    }
    let doc = if current.has_doc {
        load_doc(store, txn, id)?
    } else {
        let old = prior
            .as_deref()
            .ok_or(Error::CorruptedIndex("revision without entity"))?;
        if reference(id, old) != current.live {
            return Err(Error::CorruptedIndex("entity frontier mismatch"));
        }
        let doc = LoroDoc::new();
        write_doc_row(&doc, old)?;
        retain_frontier(store, txn, id, current.live, &doc)?;
        doc
    };
    write_doc_row(&doc, new_raw)?;
    let next = reference(id, &doc.oplog_frontiers().encode());
    retain_frontier(store, txn, id, next, &doc)?;
    save_doc(store, txn, id, &doc)?;
    current.live = next;
    current.has_doc = true;
    current.changed_at_ms = now_ms;
    put_state(store, txn, id, &current)
}

pub(crate) fn storage_manages_text(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<bool> {
    Ok(state(store, txn, id)?.is_some() || !text_fields(body).is_empty())
}

pub(crate) fn entity_has_pending_revision(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(state(store, txn, id)?.is_some_and(|s| s.live != s.indexed))
}

pub(crate) fn revision_for_mode_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    mode: ReadMode,
) -> Result<Option<RevisionRef>> {
    Ok(state(store, txn, id)?.map(|state| match mode {
        ReadMode::Live => state.live,
        ReadMode::Indexed => state.indexed,
        ReadMode::Pinned(revision) => revision,
    }))
}

/// A pack-level pin selects only its owning entity; unrelated hits are not errors.
pub(crate) fn entity_owns_revision_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    revision: RevisionRef,
) -> Result<bool> {
    let Some(raw) = store.entities().get(txn, id.as_bytes())? else {
        return Ok(false);
    };
    Ok(reference(id, &raw) == revision
        || store
            .vault_meta()
            .get(txn, &frontier_key(id, revision))?
            .is_some())
}

pub(crate) fn read_entity_revision_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: &EntityId,
    mode: ReadMode,
) -> Result<Option<Vec<u8>>> {
    read_entity_revision_from_store_in_txn(vault, &vault.store, txn, id, mode)
}

pub(crate) fn read_entity_revision_from_store_in_txn(
    vault: &Vault,
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    mode: ReadMode,
) -> Result<Option<Vec<u8>>> {
    let Some(raw) = store.entities().get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity metadata header"))?;
    if header.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY {
        return Err(crate::secret_custody::reject_secret_custody_byte());
    }
    if vault.archive_tombstone_in_txn(txn, id)?.is_some()
        || (raw.len() == ENTITY_METADATA_HEADER_LEN
            && vault
                .store
                .entity_deletion_present_in_txn(txn, id, header.learned_at)?)
    {
        return Ok(None);
    }
    if mode == ReadMode::Live {
        return Ok(Some(raw.to_vec()));
    }
    let current = state(store, txn, id)?;
    let target = match mode {
        ReadMode::Live => unreachable!(),
        ReadMode::Indexed => current
            .as_ref()
            .map_or_else(|| reference(id, &raw), |s| s.indexed),
        ReadMode::Pinned(revision) => revision,
    };
    if !current.as_ref().is_some_and(|value| value.has_doc) && reference(id, &raw) == target {
        return Ok(Some(raw.to_vec()));
    }
    Ok(Some(doc_raw(&fork_revision(store, txn, id, target)?)?))
}

pub(crate) fn ensure_document(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<(RevisionRef, LoroDoc)> {
    let raw = read_entity_revision_in_txn(vault, txn, id, ReadMode::Live)?
        .ok_or(Error::EntityNotFound)?;
    let mut current = state(&vault.store, txn, id)?.unwrap_or(RevisionState {
        live: reference(id, &raw),
        indexed: reference(id, &raw),
        changed_at_ms: unix_millis_at(std::time::SystemTime::now()),
        has_doc: false,
    });
    let doc = if current.has_doc {
        load_doc(&vault.store, txn, id)?
    } else {
        let doc = LoroDoc::new();
        write_doc_row(&doc, &raw)?;
        retain_frontier(&vault.store, txn, id, current.live, &doc)?;
        save_doc(&vault.store, txn, id, &doc)?;
        current.has_doc = true;
        put_state(&vault.store, txn, id, &current)?;
        doc
    };
    Ok((current.live, doc))
}

pub(crate) fn remove_entity_revisions(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    if let Some(current) = state(store, txn, id)? {
        for revision in [current.live, current.indexed] {
            store.vault_meta().delete(
                txn,
                &[b"entity_revision:identity:".as_slice(), &revision.0].concat(),
            )?;
        }
    }
    super::phonetic::clear_phonetic(store, txn, id)?;
    super::pending_index::clear(store, txn, id)?;
    store.vault_meta().delete(txn, &key(STATE, id))?;
    store.vault_meta().delete(txn, &key(DOC, id))?;
    let prefix = key(FRONTIER, id);
    let keys = store
        .vault_meta()
        .prefix_iter(txn, &prefix)?
        .map(|row| row.map(|(key, _)| key.to_vec()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for key in keys {
        let revision = &key[key.len() - 16..];
        store.vault_meta().delete(
            txn,
            &[b"entity_revision:identity:".as_slice(), revision].concat(),
        )?;
        store.vault_meta().delete(txn, &key)?;
    }
    Ok(())
}

impl Vault {
    /// Reads exactly the selected body version, preserving deletion/custody seals.
    pub fn get_raw_with_mode(&self, id: &EntityId, mode: ReadMode) -> Result<Option<Vec<u8>>> {
        let txn = self.store.env.read_txn()?;
        read_entity_revision_in_txn(self, &txn, id, mode)
    }

    /// Returns the current exact revision and retains its Loro frontier.
    pub fn pin_entity_revision(&self, id: &EntityId) -> Result<RevisionRef> {
        let mut txn = self.store.env.write_txn()?;
        let (revision, _) = ensure_document(self, &mut txn, id)?;
        txn.commit()?;
        Ok(revision)
    }
}

fn unix_millis_at(now: std::time::SystemTime) -> u64 {
    now.duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests;
