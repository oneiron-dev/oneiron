//! Key minting: both register doors, shared in-txn core, unbudgeted mint, entity-body writer.

use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CONNECTOR_KEY;
use crate::secret_custody::resolve_secret_ref_in_txn;
use crate::temporal::TimeRange;

use super::super::codec::{decode_connector_key_body, encode_connector_key_body};
use super::super::record::{
    ConnectorCatalogEntry, ConnectorKeyRecord, ConnectorKeySpec, ConnectorKeyStatus,
    EffectorBudget, invalid_body, normalize_connector_key,
};
use super::super::txn::{
    ConnectorKeyGeneration, append_connector_key_op_record, connector_catalog_name_index_key,
    connector_key_index_entity_id, connector_key_index_key, connector_key_index_prefix,
    read_connector_key_in_txn, write_connector_key_generation_in_txn,
};
use crate::error::RecordError;

/// Normalizes every `channel_class` narrowing in place: row matching compares
/// against the already-normalized effect channel, so a non-canonical stored
/// narrowing would never match a dispatch.
fn normalize_budget_channel_classes(budgets: &mut [EffectorBudget]) {
    for budget in budgets {
        if let Some(channel_class) = budget.channel_class.take() {
            budget.channel_class = Some(normalize_connector_key(&channel_class));
        }
    }
}
// --- Vault registry API -----------------------------------------------------------
impl Vault {
    /// Registers a connector key. Rejects a second non-revoked key for the
    /// same `(connector, actor_entity_ref)` tuple, a non-Active status, and a
    /// pre-stamped charter (a charter must enter via the receipted
    /// propose/approve pair, never via register).
    pub fn register_connector_key(
        &self,
        id: &EntityId,
        record: ConnectorKeyRecord,
    ) -> Result<ConnectorKeyRecord> {
        let mut record = record;
        record.connector = normalize_connector_key(&record.connector);
        normalize_budget_channel_classes(&mut record.budgets);
        normalize_budget_channel_classes(&mut record.suggested_budgets);
        // A catalog entry is MINTED BY registration, never carried into it:
        // the composed door is the only writer of the permanent name index,
        // so a catalogued key can never exist without its reserved name.
        // Rejected pre-write, before any transaction opens.
        if record.catalog.is_some() {
            return Err(invalid_body("catalog requires composed registration"));
        }
        record.validate()?;

        let mut wtxn = self.store.env.write_txn()?;
        self.register_connector_key_in_txn(&mut wtxn, id, &record)?;
        wtxn.commit()?;
        Ok(record)
    }
    /// Registration IS "catalog entry + key mint" — one entity id, one
    /// transaction, one `gate.connector_key.register` receipt.
    ///
    /// The entry's own `registered_at` is advisory input and is OVERWRITTEN by
    /// the `registered_at` parameter, so a stale entry cannot date the catalog
    /// row. Both connector tokens and the catalog name normalize before the
    /// uniqueness checks, so `"my-connector"` and `"my_connector"` are the
    /// same registration. Every leg — entity body, connector index, permanent
    /// name index, generation-0 log row, receipt — commits together or not at
    /// all.
    pub fn register_connector(
        &self,
        entry: ConnectorCatalogEntry,
        key_spec: ConnectorKeySpec,
        registered_at: u64,
    ) -> Result<(EntityId, ConnectorKeyRecord)> {
        let mut entry = entry;
        entry.name = normalize_connector_key(&entry.name);
        entry.connector = normalize_connector_key(&entry.connector);
        entry.registered_at = registered_at;
        entry.validate()?;

        let mut record = ConnectorKeyRecord::active(
            normalize_connector_key(&key_spec.connector),
            key_spec.actor_entity_ref,
            key_spec.budgets,
            registered_at,
        );
        normalize_budget_channel_classes(&mut record.budgets);
        record.secret_ref = key_spec.secret_ref;
        record.catalog = Some(entry);
        // `validate` binds the entry to the key: a catalog naming a different
        // connector than the key governs is rejected here, pre-write.
        record.validate()?;

        let id = EntityId::now();
        let mut wtxn = self.store.env.write_txn()?;
        self.register_connector_key_in_txn(&mut wtxn, &id, &record)?;
        wtxn.commit()?;
        Ok((id, record))
    }
    /// The in-txn registration core shared by BOTH register doors, so the
    /// legacy and composed paths cannot drift on what registration MEANS:
    /// entity-id collision, `(connector, actor)` tuple uniqueness against
    /// non-revoked siblings, custody-reference resolution, catalog-name
    /// reservation, the entity body + connector index, the generation-0 log
    /// row, and the register receipt. The caller owns the transaction, which
    /// is what makes a composed registration atomic.
    fn register_connector_key_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        record: &ConnectorKeyRecord,
    ) -> Result<()> {
        record.validate()?;
        if record.status != ConnectorKeyStatus::Active {
            return Err(invalid_body("registration requires status active"));
        }
        if record.charter.is_some() || record.pending_charter.is_some() {
            return Err(invalid_body("registration must not carry a charter"));
        }
        // Rotation counts from the registration, so registration is the ONE
        // op that mints generation 0; a caller cannot register mid-history.
        if record.key_generation != 0 {
            return Err(invalid_body("registration mints generation 0"));
        }

        let data = encode_connector_key_body(record)?;
        if self.store.entities.get(&*wtxn, id.as_bytes())?.is_some() {
            return Err(Error::Record(RecordError::ConnectorKeyAlreadyExists));
        }
        let prefix = connector_key_index_prefix(&record.connector)?;
        let mut sibling_ids = Vec::new();
        for entry in self.store.vault_meta.prefix_iter(&*wtxn, &prefix)? {
            let (key, _) = entry?;
            sibling_ids.push(connector_key_index_entity_id(&key, &record.connector)?);
        }
        for sibling_id in sibling_ids {
            let sibling = read_connector_key_in_txn(&self.store, &*wtxn, &sibling_id)?
                .ok_or(Error::CorruptedIndex("connector key index row"))?;
            if sibling.status != ConnectorKeyStatus::Revoked
                && sibling.actor_entity_ref == record.actor_entity_ref
            {
                return Err(Error::Record(RecordError::ConnectorKeyAlreadyExists));
            }
        }
        // The custody reference must NAME a live record before anything is
        // written: a dangling ref fails the whole registration closed rather
        // than minting a key that can never authenticate. This resolves a
        // name to an id — the value door is never opened here.
        if let Some(secret_ref) = record.secret_ref.as_deref()
            && resolve_secret_ref_in_txn(&self.store, &*wtxn, secret_ref)?.is_none()
        {
            return Err(invalid_body("secret_ref does not resolve"));
        }
        // The catalog name is reserved for the life of the VAULT, not of the
        // key: `remove_connector_key` leaves this row standing, so a taken
        // name stays taken even after removal.
        if let Some(catalog) = record.catalog.as_ref() {
            let name_key = connector_catalog_name_index_key(&catalog.name);
            if self.store.vault_meta.get(&*wtxn, &name_key)?.is_some() {
                return Err(Error::Record(RecordError::ConnectorKeyAlreadyExists));
            }
            self.store.vault_meta.put(wtxn, &name_key, id.as_bytes())?;
        }

        self.apply_connector_key_body(wtxn, id, record.registered_at, data)?;
        write_connector_key_generation_in_txn(
            &self.store,
            wtxn,
            id,
            &ConnectorKeyGeneration {
                generation: 0,
                secret_ref: record.secret_ref.clone(),
                rotated_at: record.registered_at,
            },
        )?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &*wtxn)?;
        append_connector_key_op_record(
            &self.store,
            wtxn,
            id,
            "gate.connector_key.register",
            record,
            policy.read_frontier_hash()?,
            record.registered_at,
        )
    }
    /// Mints an Active connector key whose budget table is necessarily empty.
    /// Optional budget rows can only enter through the owner mutation APIs.
    pub fn mint_unbudgeted_connector_key(
        &self,
        connector: &str,
        actor_entity_ref: Option<EntityId>,
        registered_at: u64,
    ) -> Result<ConnectorKeyRecord> {
        self.register_connector_key(
            &EntityId::now(),
            ConnectorKeyRecord::active(connector, actor_entity_ref, Vec::new(), registered_at),
        )
    }
    fn apply_connector_key_body(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        learned_at: u64,
        data: Vec<u8>,
    ) -> Result<()> {
        let new_record = decode_connector_key_body(&data)?;
        let new_index_key = connector_key_index_key(&new_record.connector, id)?;
        let old_index_key = if let Some(raw) = self.store.entities.get(&*wtxn, id.as_bytes())? {
            let Some(header) = EntityMetadataHeader::parse(&raw) else {
                return Err(Error::CorruptedIndex("connector key entity header"));
            };
            if header.entity_type != ENTITY_TYPE_CONNECTOR_KEY {
                return Err(Error::CorruptedIndex("connector key entity type"));
            }
            let old_record = decode_connector_key_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            Some(connector_key_index_key(&old_record.connector, id)?)
        } else {
            None
        };
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_CONNECTOR_KEY,
                occurred: TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        if let Some(old_index_key) = old_index_key.as_ref()
            && old_index_key != &new_index_key
        {
            self.store.vault_meta.delete(wtxn, old_index_key)?;
        }
        self.store.vault_meta.put(wtxn, &new_index_key, &[])?;
        Ok(())
    }
}
