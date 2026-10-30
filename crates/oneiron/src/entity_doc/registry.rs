//! Per-vault sharing of the documents reads are using; durable bytes, not
//! the registry, own truth. A document stays resident while a read uses it,
//! and its entry goes when the last such read ends (FIX 9849).

use super::{EntityDoc, invalid, storage};
use crate::error::Result;
use crate::{EntityId, Vault};
use std::collections::HashMap;
use std::sync::{Arc, Weak};

/// Observable registry residency and configured limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryStatus {
    /// Maximum documents in use the registry shares between reads. Zero
    /// shares none: each read loads its own.
    pub capacity: usize,
    /// Documents in use the registry shares now.
    pub resident: usize,
}

/// The current head pointer and the versions used by live and retrieval reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityDocumentHead {
    pub document: EntityId,
    pub field: super::TextField,
    pub frontier: Vec<u8>,
    pub live: crate::vault::entity_revision::RevisionRef,
    pub indexed: crate::vault::entity_revision::RevisionRef,
}

/// One coherent body/metadata view, with the head resolved in the same snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct EntityDocumentView {
    pub head: EntityDocumentHead,
    pub frontier: Vec<u8>,
    pub revision: crate::vault::entity_revision::RevisionRef,
    pub text: String,
    pub metadata: std::collections::BTreeMap<String, rmpv::Value>,
    pub birth: super::Birth,
}

pub(crate) struct EntityDocRegistry {
    capacity: usize,
    /// Each shared document, with the incarnation and generation it was
    /// loaded at. The registry owns none of them: an entry stands only while
    /// a read holds its document.
    entries: HashMap<EntityId, (String, u64, Weak<EntityDoc>)>,
}

impl Default for EntityDocRegistry {
    fn default() -> Self {
        Self {
            capacity: 64,
            entries: HashMap::new(),
        }
    }
}
impl EntityDocRegistry {
    pub(super) fn remove(&mut self, id: &EntityId) {
        self.entries.remove(id);
    }
    pub(super) fn clear(&mut self) {
        self.entries.clear();
    }
    /// The document a read is using for `id` at `incarnation` and
    /// `generation`, when the registry shares one.
    fn shared(&self, id: &EntityId, incarnation: &str, generation: u64) -> Option<Arc<EntityDoc>> {
        self.entries
            .get(id)
            .filter(|(held, at, _)| *at == generation && held == incarnation)
            .and_then(|(_, _, doc)| doc.upgrade())
    }
    /// Shares `doc`, which a read is now using, while fewer than `capacity`
    /// documents are shared; past it the read keeps its own, unshared, and
    /// is neither refused nor delayed.
    fn share(&mut self, id: EntityId, incarnation: String, generation: u64, doc: &Arc<EntityDoc>) {
        self.entries
            .retain(|_, (_, _, held)| held.strong_count() > 0);
        if self.entries.contains_key(&id) || self.entries.len() < self.capacity {
            self.entries
                .insert(id, (incarnation, generation, Arc::downgrade(doc)));
        }
    }
    /// Drops `id`'s entry once no read uses its document. An entry a later
    /// read shares, at any generation, stays.
    fn release(&mut self, id: &EntityId) {
        if self
            .entries
            .get(id)
            .is_some_and(|(_, _, doc)| doc.strong_count() == 0)
        {
            self.entries.remove(id);
        }
    }
    /// The documents in use the registry shares now.
    fn resident(&self) -> usize {
        self.entries
            .values()
            .filter(|(_, _, doc)| doc.strong_count() > 0)
            .count()
    }
}

impl Vault {
    /// Changes how many documents in use the registry shares. A lowered
    /// bound stops sharing the excess at once: their reads keep their own
    /// documents to their end, and none is refused or delayed. Every edit is
    /// already durable, so this never races a write-behind flush.
    pub fn set_entity_doc_capacity(&self, capacity: usize) -> Result<()> {
        let mut registry = self
            .entity_docs
            .lock()
            .map_err(|_| invalid("document registry poisoned"))?;
        registry.capacity = capacity;
        registry
            .entries
            .retain(|_, (_, _, doc)| doc.strong_count() > 0);
        let excess: Vec<EntityId> = registry.entries.keys().skip(capacity).copied().collect();
        for id in excess {
            registry.entries.remove(&id);
        }
        Ok(())
    }

    /// Reports residency, allowing callers to verify the configured bound.
    pub fn entity_doc_registry_status(&self) -> Result<RegistryStatus> {
        let registry = self
            .entity_docs
            .lock()
            .map_err(|_| invalid("document registry poisoned"))?;
        Ok(RegistryStatus {
            capacity: registry.capacity,
            resident: registry.resident(),
        })
    }

    /// Resolves the document identity and both frontiers in one read snapshot.
    pub fn entity_document_head(&self, entity: &EntityId) -> Result<EntityDocumentHead> {
        self.entity_document(entity, crate::vault::entity_revision::ReadMode::Live)
            .map(|view| view.head)
    }

    /// Reads live, indexed or pinned text and metadata without moving the head.
    pub fn entity_document(
        &self,
        entity: &EntityId,
        version: crate::vault::entity_revision::ReadMode,
    ) -> Result<EntityDocumentView> {
        let txn = self.store.env.read_txn()?;
        let head = storage::head(&self.store, &txn, entity)?;
        let live = storage::load(&self.store, &txn, &head)?;
        let live_revision = crate::vault::entity_revision::revision_for_mode_in_txn(
            &self.store,
            &txn,
            entity,
            crate::vault::entity_revision::ReadMode::Live,
        )?
        .ok_or(invalid("document revision is missing"))?;
        let indexed = crate::vault::entity_revision::revision_for_mode_in_txn(
            &self.store,
            &txn,
            entity,
            crate::vault::entity_revision::ReadMode::Indexed,
        )?
        .ok_or(invalid("document indexed revision is missing"))?;
        let revision = crate::vault::entity_revision::revision_for_mode_in_txn(
            &self.store,
            &txn,
            entity,
            version,
        )?
        .ok_or(invalid("document revision is missing"))?;
        let selected = EntityDoc::from_loro(crate::vault::entity_revision::fork_revision(
            &self.store,
            &txn,
            entity,
            revision,
        )?)?;
        Ok(EntityDocumentView {
            head: EntityDocumentHead {
                document: EntityId::from_hex(&head.document)?,
                field: head.field,
                frontier: live.frontier(),
                live: live_revision,
                indexed,
            },
            frontier: selected.frontier(),
            revision,
            text: selected.text(),
            metadata: selected.metadata()?,
            // The birth's stamp token reads as its actor (FIX 11964).
            birth: live.birth().resolved_in(&self.store, &txn)?,
        })
    }

    /// A typed record-body projection at the requested document version. Raw
    /// ledger reads still return only immutable fields and the head pointer.
    pub fn entity_document_body(
        &self,
        entity: &EntityId,
        version: crate::vault::entity_revision::ReadMode,
    ) -> Result<Vec<u8>> {
        let txn = self.store.env.read_txn()?;
        storage::head(&self.store, &txn, entity)?;
        let raw = crate::vault::entity_revision::read_entity_revision_in_txn(
            self, &txn, entity, version,
        )?
        .ok_or(crate::Error::EntityNotFound)?;
        Ok(raw[crate::batch::ENTITY_METADATA_HEADER_LEN..].to_vec())
    }

    /// The live text and metadata of `entity`'s document, read in the
    /// caller's `txn`: no new snapshot and no cache, so they agree with the
    /// rest of that read. The caller admits `entity` first.
    pub(crate) fn entity_live_text_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        entity: &EntityId,
    ) -> Result<(String, std::collections::BTreeMap<String, rmpv::Value>)> {
        let head = storage::head(&self.store, txn, entity)?;
        let live = storage::load(&self.store, txn, &head)?;
        Ok((live.text(), live.metadata()?))
    }

    /// Reads authoritative live text, lazily restoring a cold doc's snapshot
    /// before its ordered updates. A deleted entity cannot resolve from cache.
    pub fn entity_text(&self, entity: &EntityId) -> Result<String> {
        self.read_entity_doc(entity, EntityDoc::text)
    }

    /// Reads a head frontier suitable for a fork, pin or whole-text update.
    pub fn entity_text_frontier(&self, entity: &EntityId) -> Result<Vec<u8>> {
        self.read_entity_doc(entity, EntityDoc::frontier)
    }

    /// Returns the birth provenance retained after all edits and cache
    /// evictions, its stamp token read as its actor, or no one (FIX 11964).
    pub fn entity_text_birth(&self, entity: &EntityId) -> Result<super::Birth> {
        let birth = self.read_entity_doc(entity, |doc| doc.birth().clone())?;
        let txn = self.store.env.read_txn()?;
        birth.resolved_in(&self.store, &txn)
    }

    pub(super) fn read_entity_doc<T>(
        &self,
        entity: &EntityId,
        read: impl FnOnce(&EntityDoc) -> T,
    ) -> Result<T> {
        let txn = self.store.env.read_txn()?;
        let h = storage::head(&self.store, &txn, entity)?;
        let shared = self
            .entity_docs
            .lock()
            .map_err(|_| invalid("document registry poisoned"))?
            .shared(entity, &h.incarnation, h.generation);
        let doc = match shared {
            Some(doc) => doc,
            None => {
                let doc = Arc::new(storage::load(&self.store, &txn, &h)?);
                self.entity_docs
                    .lock()
                    .map_err(|_| invalid("document registry poisoned"))?
                    .share(*entity, h.incarnation, h.generation, &doc);
                doc
            }
        };
        let out = read(&doc);
        // This read's document goes with it, under the registry's lock, so
        // the last read to end drops the entry: no read keeps a cold one.
        let mut registry = self
            .entity_docs
            .lock()
            .map_err(|_| invalid("document registry poisoned"))?;
        drop(doc);
        registry.release(entity);
        Ok(out)
    }
}
