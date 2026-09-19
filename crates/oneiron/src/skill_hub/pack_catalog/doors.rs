//! Source staging/readback. These doors never install predicates, adapters or grants.
use super::{PackSource, codec, invalid};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::registry::ENTITY_TYPE_ASSET;
use crate::{EntityId, TimeRange, Vault, error::Result};

impl Vault {
    /// Persist exact future pack sources in the replicated evidence ledger.
    /// Staging is inert: runtime installation is a separate local admission act.
    pub fn stage_pack_source(
        &self,
        source: &PackSource,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        let bytes = codec::encode(source)?;
        let id = codec::source_id(source)?;
        let mut txn = self.store.env.write_txn()?;
        if let Some(raw) = self.store.entities.get(&txn, id.as_bytes())? {
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or_else(|| invalid("invalid source row header"))?;
            if !crate::vault::live_entity_row_in_txn(&self.store, &txn, &id)?.is_live() {
                return Err(invalid("source is deleted; explicit restore required"));
            }
            if header.entity_type != ENTITY_TYPE_ASSET || raw[ENTITY_METADATA_HEADER_LEN..] != bytes
            {
                return Err(invalid("source identity collision"));
            }
            return Ok(id);
        }
        self.batch_in()
            .put(&id, ENTITY_TYPE_ASSET, occurred, learned_at, &bytes)
            .apply(&mut txn)?;
        txn.commit()?;
        Ok(id)
    }
    pub fn get_pack_source(&self, id: &EntityId) -> Result<Option<PackSource>> {
        let Some(raw) = self.get_raw(id)? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or_else(|| invalid("invalid source header"))?;
        if header.entity_type != ENTITY_TYPE_ASSET {
            return Ok(None);
        }
        codec::decode(&raw[ENTITY_METADATA_HEADER_LEN..])
    }
    pub fn list_pack_sources(&self) -> Result<Vec<(EntityId, PackSource)>> {
        let txn = self.store.env.read_txn()?;
        self.pack_sources_in_txn(&txn)
    }
    pub(crate) fn pack_sources_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Vec<(EntityId, PackSource)>> {
        let mut sources = Vec::new();
        for (n, entry) in self
            .store
            .type_index
            .prefix_iter(txn, &[ENTITY_TYPE_ASSET])?
            .enumerate()
        {
            if n >= 100_000 {
                return Err(invalid("pack catalog scan exceeds bound"));
            }
            let (key, _) = entry?;
            let id = crate::vault::entity_id_from_type_index_key(&key)?;
            if !crate::vault::live_entity_row_in_txn(&self.store, txn, &id)?.is_live() {
                continue;
            }
            let raw = self
                .store
                .entities
                .get(txn, id.as_bytes())?
                .ok_or_else(|| invalid("source index row absent"))?;
            let header =
                EntityMetadataHeader::parse(&raw).ok_or_else(|| invalid("source index header"))?;
            if header.entity_type != ENTITY_TYPE_ASSET {
                return Err(invalid("source index type drift"));
            }
            if let Some(source) = codec::decode(&raw[ENTITY_METADATA_HEADER_LEN..])? {
                if codec::source_id(&source)? != id {
                    return Err(invalid("stored source identity drift"));
                }
                sources.push((id, source));
            }
        }
        Ok(sources)
    }
}
