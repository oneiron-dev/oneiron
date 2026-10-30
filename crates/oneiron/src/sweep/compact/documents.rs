//! The entity each persisted `e:` slot holds the document of (FIX 10159).
//! An entity document's slot is the one its retained head names, never
//! presumed to be its entity, so the sweep decides erasure, withdrawal and
//! holds for that entity, and its compaction goes to the entity document's
//! owner ahead of the NOTE and text-plane loader
//! (`crate::sync::documents::compact`).

use std::collections::BTreeMap;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// Each slot a retained entity-document head names, with that head's
/// entity, as one read of the pass found them.
pub(super) struct SlotOwners(BTreeMap<String, EntityId>);

impl SlotOwners {
    pub(super) fn read(vault: &Vault) -> Result<Self> {
        let rtxn = vault.store.env.read_txn()?;
        let slots = crate::entity_doc::entity_doc_slots_in(&vault.store, &rtxn)?;
        Ok(Self(slots))
    }

    /// The entity whose document slot `hex` holds, if a live one owns it:
    /// the one whose retained head names it, else the slot's own id, as
    /// NOTE and text-plane rows are keyed — but only when that id is a
    /// live entity. A slot no retained head names and whose own id is not
    /// live (orphan, moved away, shared) has no owner to compact it as, so
    /// it reports none and the slot loop leaves its rows as they are
    /// (FIX 11188).
    pub(super) fn entity(&self, vault: &Vault, hex: &str) -> Result<Option<EntityId>> {
        if let Some(entity) = self.0.get(hex) {
            return Ok(Some(*entity));
        }
        let id = EntityId::from_hex(hex)?;
        let rtxn = vault.store.env.read_txn()?;
        let live = crate::vault::live_entity_row_in_txn(&vault.store, &rtxn, &id)?.is_live();
        Ok(live.then_some(id))
    }
}
