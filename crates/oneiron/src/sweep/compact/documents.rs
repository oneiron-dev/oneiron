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

    /// The entity whose document slot `hex` holds: the one whose retained
    /// head names it, else the slot's own id, as NOTE and text-plane rows
    /// are keyed.
    pub(super) fn entity(&self, hex: &str) -> Result<EntityId> {
        match self.0.get(hex) {
            Some(entity) => Ok(*entity),
            None => Ok(EntityId::from_hex(hex)?),
        }
    }
}
