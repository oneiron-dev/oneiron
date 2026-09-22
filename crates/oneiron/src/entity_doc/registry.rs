//! Bounded per-vault insertion-ordered residency; durable bytes, not the cache, own truth.

use super::{EntityDoc, invalid, storage};
use crate::error::Result;
use crate::{EntityId, Vault};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

/// Observable registry residency and configured limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryStatus {
    /// Maximum resident documents. Zero disables caching.
    pub capacity: usize,
    /// Current resident document count.
    pub resident: usize,
}

pub(crate) struct EntityDocRegistry {
    capacity: usize,
    entries: HashMap<EntityId, (String, u64, Arc<EntityDoc>)>,
    cold: VecDeque<EntityId>,
}

impl Default for EntityDocRegistry {
    fn default() -> Self {
        Self {
            capacity: 64,
            entries: HashMap::new(),
            cold: VecDeque::new(),
        }
    }
}
impl EntityDocRegistry {
    pub(super) fn remove(&mut self, id: &EntityId) {
        self.entries.remove(id);
        self.cold.retain(|candidate| candidate != id);
    }
    pub(super) fn clear(&mut self) {
        self.entries.clear();
        self.cold.clear();
    }
    pub(super) fn insert(
        &mut self,
        id: EntityId,
        incarnation: String,
        generation: u64,
        doc: EntityDoc,
    ) {
        self.remove(&id);
        if self.capacity == 0 {
            return;
        }
        while self.entries.len() >= self.capacity {
            if let Some(cold) = self.cold.pop_front() {
                self.entries.remove(&cold);
            }
        }
        self.cold.push_back(id);
        self.entries
            .insert(id, (incarnation, generation, Arc::new(doc)));
    }
}

impl Vault {
    /// Changes the bound and immediately evicts excess cold documents. Every
    /// edit is already durable, so eviction never races a write-behind flush.
    pub fn set_entity_doc_capacity(&self, capacity: usize) -> Result<()> {
        let mut registry = self
            .entity_docs
            .lock()
            .map_err(|_| invalid("document registry poisoned"))?;
        registry.capacity = capacity;
        while registry.entries.len() > capacity {
            if let Some(cold) = registry.cold.pop_front() {
                registry.entries.remove(&cold);
            }
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
            resident: registry.entries.len(),
        })
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

    /// Returns the birth provenance retained after all edits and cache evictions.
    pub fn entity_text_birth(&self, entity: &EntityId) -> Result<super::Birth> {
        self.read_entity_doc(entity, |doc| doc.birth().clone())
    }

    pub(super) fn read_entity_doc<T>(
        &self,
        entity: &EntityId,
        read: impl FnOnce(&EntityDoc) -> T,
    ) -> Result<T> {
        let txn = self.store.env.read_txn()?;
        let h = storage::head(&self.store, &txn, entity)?;
        let cached = {
            let registry = self
                .entity_docs
                .lock()
                .map_err(|_| invalid("document registry poisoned"))?;
            registry
                .entries
                .get(entity)
                .filter(|(incarnation, generation, _)| {
                    *generation == h.generation && *incarnation == h.incarnation
                })
                .map(|(_, _, doc)| Arc::clone(doc))
        };
        if let Some(doc) = cached {
            return Ok(read(&doc));
        }
        let doc = storage::load(&self.store, &txn, &h)?;
        let out = read(&doc);
        self.entity_docs
            .lock()
            .map_err(|_| invalid("document registry poisoned"))?
            .insert(*entity, h.incarnation, h.generation, doc);
        Ok(out)
    }
}
