//! Geographic entity doors consume PlaceStore, never concrete database handles.
use super::Vault;
use crate::error::Result;
use crate::ports::{EntityRecord, PlaceStore};
use crate::{EntityId, TimeRange};
impl Vault {
    /// Returns a live PLACE body, or None after source invalidation or deletion.
    pub fn get_place(&self, id: &EntityId) -> Result<Option<Vec<u8>>> {
        let txn = self.store.env.read_txn()?;
        Ok(self.port_place_get(&txn, id)?.map(|row| row.body))
    }
    /// Writes a PLACE through the same validators and indexes as an entity put.
    pub fn put_place(
        &self,
        id: &EntityId,
        occurred: TimeRange,
        learned_at: u64,
        body: &[u8],
    ) -> Result<()> {
        self.with_write_txn(|txn| {
            self.port_place_put(
                txn,
                id,
                &EntityRecord {
                    entity_type: crate::registry::ENTITY_TYPE_PLACE,
                    occurred,
                    learned_at,
                    body: body.to_vec(),
                },
            )
        })
    }
    /// Resolves places by an exact provider and provider id pair.
    pub fn find_places_by_provider_id(
        &self,
        provider: &str,
        provider_id: &str,
    ) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        self.port_place_find_by_provider_id(&txn, provider, provider_id)
    }
    /// Finds all live places with an exact name.
    pub fn find_places_by_name(&self, name: &str) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        self.port_place_find_by_name(&txn, name)
    }
    /// Lists PLACE children of a PLACE parent.
    pub fn place_children(&self, id: &EntityId) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        self.port_place_list_children(&txn, id)
    }
}
