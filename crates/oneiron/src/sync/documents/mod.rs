//! Per-entity text documents. Only live edit sessions retain Loro residents.
//!
//! The serialized commit path performs Observer A's duty (durable append,
//! stale VV, then wire notice). There is no Observer B: text never overwrites
//! entity bodies in LMDB. Reads and socket imports use short-lived sessions.

mod note_requests;
pub(crate) mod storage;
#[cfg(test)]
mod tests;

use crate::error::{Error, Result, SyncEngineContext, SyncProtocolValidation};
use crate::sync::loro_support::doc_from_snapshot;
use crate::sync::transport::{document_sub_tags, encode_document};
use crate::{EntityId, Vault};
use loro::{ExportMode, LoroDoc, VersionVector};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::broadcast;

pub(crate) use storage::compact;

/// Maximum concurrent live-edit documents. Idle documents are evicted immediately.
const MAX_RESIDENTS: usize = 256;

pub struct DocumentRegistry {
    vault: Arc<Vault>,
    residents: Mutex<HashMap<EntityId, Weak<EntityDocument>>>,
    notices: broadcast::Sender<Vec<u8>>,
}

impl DocumentRegistry {
    pub(super) fn new(vault: Arc<Vault>) -> Self {
        Self {
            vault,
            residents: Mutex::new(HashMap::new()),
            notices: broadcast::channel(256).0,
        }
    }

    /// Only callers holding this edit handle keep the document resident.
    pub fn open(&self, id: EntityId) -> Result<Arc<EntityDocument>> {
        let mut residents = self
            .residents
            .lock()
            .map_err(|_| Error::InvariantViolation("document registry poisoned"))?;
        residents.retain(|_, doc| doc.strong_count() > 0);
        if let Some(doc) = residents.get(&id).and_then(Weak::upgrade) {
            return Ok(doc);
        }
        if residents.len() >= MAX_RESIDENTS {
            return Err(Error::InvariantViolation("live document limit reached"));
        }
        self.vault.with_write_txn(|txn| {
            eligible(&self.vault, txn, id)?;
            // Startup step 3: snapshot first, then ordered pending updates.
            let doc = storage::load(&self.vault, txn, id)?;
            storage::snapshot(&self.vault, txn, id, &doc, false)?;
            let handle = Arc::new(EntityDocument {
                id,
                vault: self.vault.clone(),
                doc: Mutex::new(doc),
                notices: self.notices.clone(),
            });
            residents.insert(id, Arc::downgrade(&handle));
            Ok(handle)
        })
    }

    /// The one text-plane export door. Authorization and entity selection use
    /// the same ledger selector; the text doc itself is never made synthetic.
    pub(super) fn export_selected(
        &self,
        id: EntityId,
        ledger: &LoroDoc,
        window: &super::WindowKey,
        scope: crate::FederationGrantScope,
        selector: &super::selector::SyncSelector,
        remote_vv: &[u8],
    ) -> Result<Vec<u8>> {
        let selected =
            super::selector::filtered_window_doc(&self.vault, ledger, window, scope, selector)?;
        if !super::loro_support::map_contains_binary(&selected.get_map("entities"), &id.to_hex()) {
            return Err(Error::sync_protocol(
                SyncProtocolValidation::DocumentAdmissionDenied,
            ));
        }
        self.open(id)?.export(
            &super::selector::encode_sync_selector(selector)?,
            remote_vv,
            scope,
        )
    }

    /// Register a document on the existing sync socket, including reconnects.
    pub fn subscribe_entity(
        &self,
        id: EntityId,
        selector: &super::selector::SyncSelector,
    ) -> Result<()> {
        let bytes = super::selector::encode_sync_selector(selector)?;
        self.vault.with_write_txn(|txn| {
            eligible(&self.vault, txn, id)?;
            self.vault
                .store
                .sync_state
                .put(txn, &format!("ds:e:{}", id.to_hex()), &bytes)?;
            Ok(())
        })?;
        let frame = self.request_frame(id, selector)?;
        let _ = self.notices.send(frame);
        Ok(())
    }

    pub fn request_frames(&self) -> Result<Vec<Vec<u8>>> {
        let rows: Vec<_> = {
            let txn = self.vault.store.env.read_txn()?;
            self.vault
                .store
                .sync_state
                .prefix_iter(&txn, "ds:e:")?
                .map(|row| row.map(|(key, bytes)| (key.to_string(), bytes.to_vec())))
                .collect::<std::result::Result<_, _>>()?
        };
        let mut out = Vec::new();
        for (key, bytes) in rows {
            let id = EntityId::from_hex(&key[5..])?;
            let selector = super::selector::decode_sync_selector(&bytes)?;
            // A deleted/unshared entity never gets resurrected by reconnect.
            if self.vault.get_raw(&id)?.is_some() {
                out.push(self.request_frame(id, &selector)?);
            }
        }
        Ok(out)
    }

    fn request_frame(
        &self,
        id: EntityId,
        selector: &super::selector::SyncSelector,
    ) -> Result<Vec<u8>> {
        let vv = self.open(id)?.version_vector()?;
        let payload = super::selector::encode_selector_vv_request(selector, &vv)?;
        encode_document(id, document_sub_tags::REQUEST, &payload)
            .into_result()
            .map_err(|_| Error::InvariantViolation("document request exceeds wire limit"))
    }

    /// Invalidation frames only after a local edit is durable. Lag requires VV resync.
    pub fn subscribe(&self) -> broadcast::Receiver<Vec<u8>> {
        self.notices.subscribe()
    }

    pub(crate) fn notify_note(&self, id: EntityId) {
        // This is an invalidation, never an export. Every socket recipient
        // reconstructs its own selector-admitted state before sending.
        if let Ok(frame) = encode_document(id, document_sub_tags::UPDATE, &[]).into_result() {
            let _ = self.notices.send(frame);
        }
    }

    pub fn resident_count(&self) -> usize {
        self.residents.lock().map_or(MAX_RESIDENTS, |r| {
            r.values().filter(|v| v.strong_count() > 0).count()
        })
    }

    pub(crate) fn compact_closed(&self, id: EntityId, erased: bool) -> Result<bool> {
        let residents = self
            .residents
            .lock()
            .map_err(|_| Error::InvariantViolation("document registry poisoned"))?;
        if residents.get(&id).is_some_and(|v| v.strong_count() > 0) {
            return Ok(false);
        }
        storage::compact(&self.vault, id, erased)?;
        drop(residents);
        Ok(true)
    }
}

/// A live editable document. No raw Loro handle escapes the serialization lock.
pub struct EntityDocument {
    id: EntityId,
    vault: Arc<Vault>,
    doc: Mutex<LoroDoc>,
    notices: broadcast::Sender<Vec<u8>>,
}

impl EntityDocument {
    pub fn text(&self) -> Result<String> {
        let txn = self.vault.store.env.read_txn()?;
        eligible(&self.vault, &txn, self.id)?;
        if self.vault.get_entity_type_in_txn(&txn, &self.id)?
            == Some(crate::registry::ENTITY_TYPE_NOTE)
        {
            return Ok(storage::load(&self.vault, &txn, self.id)?
                .get_text("body")
                .to_string());
        }
        Ok(self.lock()?.get_text("body").to_string())
    }

    pub fn version_vector(&self) -> Result<Vec<u8>> {
        let txn = self.vault.store.env.read_txn()?;
        eligible(&self.vault, &txn, self.id)?;
        if self.vault.get_entity_type_in_txn(&txn, &self.id)?
            == Some(crate::registry::ENTITY_TYPE_NOTE)
        {
            return Ok(storage::load(&self.vault, &txn, self.id)?
                .oplog_vv()
                .encode());
        }
        Ok(self.lock()?.oplog_vv().encode())
    }

    /// Edit a Unicode-scalar range. The update is durable before return or notice.
    pub fn edit_text(&self, start: usize, delete: usize, insert: &str) -> Result<Vec<u8>> {
        self.refuse_raw_note()?;
        let mut resident = self.lock()?;
        let staged = clone_doc(&resident)?;
        let before = staged.oplog_vv();
        let text = staged.get_text("body");
        text.delete(start, delete)
            .map_err(|e| Error::sync_engine(SyncEngineContext::LoroMapDelete, e))?;
        text.insert(start, insert)
            .map_err(|e| Error::sync_engine(SyncEngineContext::LoroMapInsert, e))?;
        staged.commit();
        let bytes = staged
            .export(ExportMode::updates(&before))
            .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportUpdates, e))?;
        let frame = encode_document(self.id, document_sub_tags::UPDATE, &bytes)
            .into_result()
            .map_err(|_| Error::InvariantViolation("document edit exceeds wire limit"))?;
        self.vault.with_write_txn(|txn| {
            eligible(&self.vault, txn, self.id)?;
            let seq = storage::append(&self.vault, txn, self.id, &bytes)?;
            self.vault.store.sync_state.put(
                txn,
                &format!("qd:e:{}:{seq:08x}", self.id.to_hex()),
                &frame,
            )?;
            Ok(())
        })?;
        *resident = staged;
        let _ = self.notices.send(frame.clone());
        Ok(frame)
    }

    /// Privileged embedding/authority import, without peer grant admission.
    /// STATE replaces, never merges a shallow copy. NOTE still refuses raw bytes.
    /// Socket writes must use [`Self::import_from_peer`] instead.
    pub fn import(&self, kind: u8, bytes: &[u8]) -> Result<()> {
        self.import_admitted(kind, bytes, |_| Ok(()))
    }

    /// Append a peer update only if its grant and live ledger selector still
    /// permit writing this document in the SAME transaction as the append.
    /// This door never lets an upstream peer replace state or import raw NOTE.
    pub fn import_from_peer(
        &self,
        kind: u8,
        bytes: &[u8],
        scope: crate::FederationGrantScope,
        selector: &super::selector::SyncSelector,
    ) -> Result<()> {
        if kind != document_sub_tags::UPDATE {
            return Err(Error::sync_protocol(
                SyncProtocolValidation::DocumentAdmissionDenied,
            ));
        }
        self.import_admitted(kind, bytes, |txn| {
            super::selector::admit_document_write_in_txn(&self.vault, txn, self.id, scope, selector)
        })
    }

    fn import_admitted(
        &self,
        kind: u8,
        bytes: &[u8],
        admit: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<()>,
    ) -> Result<()> {
        self.refuse_raw_note()?;
        let mut resident = self.lock()?;
        let staged = match kind {
            document_sub_tags::STATE => LoroDoc::new(),
            document_sub_tags::UPDATE => clone_doc(&resident)?,
            _ => {
                return Err(Error::sync_protocol(
                    SyncProtocolValidation::DocumentAdmissionDenied,
                ));
            }
        };
        storage::import_complete(&staged, bytes)?;
        if kind == document_sub_tags::STATE {
            for frame in self.pending_frames()? {
                let frame = crate::sync::transport::decode_document(&frame[1..]).map_err(|_| {
                    Error::sync_protocol(SyncProtocolValidation::InvalidDocumentKey)
                })?;
                storage::import_complete(&staged, frame.payload)?;
            }
        }
        if kind == document_sub_tags::STATE && !covers(&staged.oplog_vv(), &resident.oplog_vv()) {
            return Err(Error::sync_protocol(
                SyncProtocolValidation::DocumentPendingUpdate,
            ));
        }
        self.vault.with_write_txn(|txn| {
            eligible(&self.vault, txn, self.id)?;
            if self.vault.get_entity_type_in_txn(txn, &self.id)?
                == Some(crate::registry::ENTITY_TYPE_NOTE)
            {
                return Err(Error::sync_protocol(
                    SyncProtocolValidation::DocumentAdmissionDenied,
                ));
            }
            admit(txn)?;
            if kind == document_sub_tags::STATE {
                storage::snapshot(&self.vault, txn, self.id, &staged, true)
            } else {
                storage::append(&self.vault, txn, self.id, bytes).map(|_| ())
            }
        })?;
        *resident = staged;
        Ok(())
    }

    /// Export after the selector has admitted this entity. `admission_key` is the
    /// canonical selector encoding, not peer-controlled claims about prior admission.
    fn export(
        &self,
        admission_key: &[u8],
        remote_vv: &[u8],
        scope: crate::FederationGrantScope,
    ) -> Result<Vec<u8>> {
        let peer = storage::decode_vv(remote_vv)?;
        let resident = self.lock()?;
        let key = format!(
            "ad:e:{}:{}",
            self.id.to_hex(),
            blake3::hash(admission_key).to_hex()
        );
        self.vault.with_write_txn(|txn| {
            eligible(&self.vault, txn, self.id)?;
            let note_doc;
            let doc = if self.vault.get_entity_type_in_txn(txn, &self.id)?
                == Some(crate::registry::ENTITY_TYPE_NOTE)
            {
                let selector = super::selector::decode_sync_selector(admission_key)?;
                crate::note::validate_note_export(&self.vault, txn, self.id, scope, &selector)?;
                note_doc = storage::load(&self.vault, txn, self.id)?;
                &note_doc
            } else {
                &*resident
            };
            let admitted = self.vault.store.sync_state.get(txn, &key)?;
            let mut state_copy = match admitted {
                Some(bytes) => !covers(&peer, &storage::decode_vv(&bytes)?),
                None => true,
            };
            if let Some(bytes) = self
                .vault
                .store
                .sync_state
                .get(txn, &format!("ssv:e:{}", self.id.to_hex()))?
            {
                state_copy |= !covers(&peer, &storage::decode_vv(&bytes)?);
            }
            state_copy |= !covers(&peer, &doc.shallow_since_vv().to_vv());
            let (kind, bytes) = if state_copy {
                // Each state copy resets the disclosure floor, including first admission.
                self.vault
                    .store
                    .sync_state
                    .put(txn, &key, &doc.oplog_vv().encode())?;
                (document_sub_tags::STATE, storage::state_copy(doc)?)
            } else {
                (
                    document_sub_tags::UPDATE,
                    doc.export(ExportMode::updates(&peer))
                        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportUpdates, e))?,
                )
            };
            encode_document(self.id, kind, &bytes)
                .into_result()
                .map_err(|_| Error::InvariantViolation("document export exceeds wire limit"))
        })
    }

    /// Durable, unacknowledged local updates. This journal is separate from the
    /// month-key-only window queue and survives registry eviction and restart.
    pub fn pending_frames(&self) -> Result<Vec<Vec<u8>>> {
        let txn = self.vault.store.env.read_txn()?;
        self.vault
            .store
            .sync_state
            .prefix_iter(&txn, &format!("qd:e:{}:", self.id.to_hex()))?
            .map(|row| row.map(|(_, bytes)| bytes.to_vec()))
            .collect()
    }

    /// Clear only after the remote VV proves it holds every local operation.
    pub fn acknowledge(&self, remote_vv: &[u8]) -> Result<()> {
        let remote = storage::decode_vv(remote_vv)?;
        let doc = self.lock()?;
        if !covers(&remote, &doc.oplog_vv()) {
            return Ok(());
        }
        self.vault.with_write_txn(|txn| {
            let keys: Vec<_> = self
                .vault
                .store
                .sync_state
                .prefix_iter(txn, &format!("qd:e:{}:", self.id.to_hex()))?
                .map(|row| row.map(|(key, _)| key.to_string()))
                .collect::<std::result::Result<_, _>>()?;
            for key in keys {
                self.vault.store.sync_state.delete(txn, &key)?;
            }
            Ok(())
        })
    }

    pub(crate) fn is_note(&self) -> Result<bool> {
        Ok(self.vault.get_entity_type(&self.id)? == Some(crate::registry::ENTITY_TYPE_NOTE))
    }

    fn refuse_raw_note(&self) -> Result<()> {
        if self.is_note()? {
            return Err(Error::sync_protocol(
                SyncProtocolValidation::DocumentAdmissionDenied,
            ));
        }
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, LoroDoc>> {
        self.doc
            .lock()
            .map_err(|_| Error::InvariantViolation("entity document poisoned"))
    }
}

fn covers(peer: &VersionVector, floor: &VersionVector) -> bool {
    matches!(
        peer.partial_cmp(floor),
        Some(std::cmp::Ordering::Equal | std::cmp::Ordering::Greater)
    )
}

fn clone_doc(doc: &LoroDoc) -> Result<LoroDoc> {
    doc_from_snapshot(
        &doc.export(ExportMode::Snapshot)
            .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportSnapshot, e))?,
    )
}

fn eligible(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<()> {
    crate::note::ensure_citations_ready(&vault.store, txn, id)?;
    let raw = vault
        .store
        .entities
        .get(txn, id.as_bytes())?
        .ok_or_else(|| Error::sync_protocol(SyncProtocolValidation::DocumentAdmissionDenied))?;
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or_else(|| Error::sync_protocol(SyncProtocolValidation::DocumentAdmissionDenied))?;
    // Credentials never own editable text, including portable credentials.
    if header.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY
        || vault.local_hard_delete_marker_exists_in_txn(txn, &id)?
        || (header.entity_type == crate::registry::ENTITY_TYPE_NOTE
            && raw.len() == crate::batch::ENTITY_METADATA_HEADER_LEN)
        || vault.store.off_record_sessions.contains_entity(&id)?
    {
        return Err(Error::sync_protocol(
            SyncProtocolValidation::DocumentAdmissionDenied,
        ));
    }
    Ok(())
}
