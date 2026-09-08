//! Read lenses: HISTORY/EXECUTION/DISCOVERY views over the catalog plus key lookups.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::super::record::{
    ConnectorCallClass, ConnectorCatalogEntry, ConnectorKeyRecord, ConnectorKeyStatus,
    normalize_connector_key,
};
use super::super::txn::{
    CONNECTOR_CATALOG_NAME_INDEX_PREFIX, connector_catalog_index_entity_id,
    connector_catalog_name_index_key, governing_connector_key, read_connector_key_in_txn,
};

/// The HISTORY lens over one catalogued connector: what it is, plus the
/// VALUE-LESS metadata of the key that governs it. `secret_ref` is a custody
/// record NAME (ONE-1919), never a secret value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorDescription {
    /// The governing CONNECTOR_KEY entity.
    pub key_ref: EntityId,
    pub entry: ConnectorCatalogEntry,
    /// The connector token the key governs.
    pub connector: String,
    /// Resolves for a REMOVED connector too, reporting `Revoked`.
    pub status: ConnectorKeyStatus,
    pub secret_ref: Option<String>,
    pub key_generation: u32,
    pub registered_at: u64,
    pub status_changed_at: Option<u64>,
    /// Entry-wide ARCH-0054 classification: `call_class.debits_sends()`.
    pub budgeted_as_sends: bool,
}
/// The EXECUTION lens over one catalogued connector. Produced only while the
/// governing key is Active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorCallRoute {
    pub key_ref: EntityId,
    pub connector: String,
    pub call_class: ConnectorCallClass,
    /// ENTRY-WIDE (ARCH-0054): there is no verb parameter, so a mixed-verb
    /// `CounterpartyComm` connector budgets every call as a send.
    pub budgeted_as_sends: bool,
    /// Descriptive verb list from the catalog entry.
    pub verbs: Vec<String>,
    /// Custody record NAME to authenticate with; never a value.
    pub secret_ref: Option<String>,
}
impl Vault {
    /// Reads and decodes a connector-key record.
    pub fn get_connector_key(&self, id: &EntityId) -> Result<Option<ConnectorKeyRecord>> {
        let rtxn = self.store.env.read_txn()?;
        read_connector_key_in_txn(&self.store, &rtxn, id)
    }
    /// Resolves the key governing `(connector, actor_entity_ref)` (read-txn
    /// wrapper over the gate's resolution order).
    pub fn connector_key_for(
        &self,
        connector: &str,
        actor_entity_ref: Option<&EntityId>,
    ) -> Result<Option<(EntityId, ConnectorKeyRecord)>> {
        let rtxn = self.store.env.read_txn()?;
        governing_connector_key(
            &self.store,
            &rtxn,
            &normalize_connector_key(connector),
            actor_entity_ref,
        )
    }
    /// Engine-catalog search — the DISCOVERY lens, Active keys only.
    ///
    /// The query is matched two ways at once: normalized against the catalog
    /// name (so a hyphenated query finds an underscored name, the same
    /// normalization every connector token gets) and case-insensitively as a
    /// substring of the summary. A blank query lists the whole live catalog.
    /// Results come back in name order — the index walk is the ordering.
    pub fn search_connector_catalog(&self, query: &str) -> Result<Vec<ConnectorCatalogEntry>> {
        let name_query = normalize_connector_key(query);
        let summary_query = query.trim().to_lowercase();
        let rtxn = self.store.env.read_txn()?;
        let mut ids = Vec::new();
        for entry in self
            .store
            .vault_meta
            .prefix_iter(&rtxn, CONNECTOR_CATALOG_NAME_INDEX_PREFIX)?
        {
            let (_, raw_id) = entry?;
            ids.push(connector_catalog_index_entity_id(&raw_id)?);
        }
        let mut hits = Vec::new();
        for id in ids {
            let record = read_connector_key_in_txn(&self.store, &rtxn, &id)?
                .ok_or(Error::CorruptedIndex("connector catalog name index row"))?;
            // Removed connectors keep their index row and their entry; the
            // discovery lens is live-only, so the status filter is what
            // hides them here while `describe_connector` still resolves them.
            if record.status != ConnectorKeyStatus::Active {
                continue;
            }
            let Some(catalog) = record.catalog else {
                continue;
            };
            if catalog.name.contains(&name_query)
                || catalog.summary.to_lowercase().contains(&summary_query)
            {
                hits.push(catalog);
            }
        }
        Ok(hits)
    }
    /// Describes one catalogued connector — the HISTORY lens. Resolves a
    /// REMOVED connector too (reporting `Revoked`), because the name index is
    /// permanent. The key metadata it reports is value-less: `secret_ref`
    /// names a custody record, it is never a secret.
    pub fn describe_connector(&self, name: &str) -> Result<Option<ConnectorDescription>> {
        let rtxn = self.store.env.read_txn()?;
        let Some((key_ref, record)) = self.catalog_record_in_txn(&rtxn, name)? else {
            return Ok(None);
        };
        let Some(entry) = record.catalog else {
            return Ok(None);
        };
        let budgeted_as_sends = entry.call_class.debits_sends();
        Ok(Some(ConnectorDescription {
            key_ref,
            entry,
            connector: record.connector,
            status: record.status,
            secret_ref: record.secret_ref,
            key_generation: record.key_generation,
            registered_at: record.registered_at,
            status_changed_at: record.status_changed_at,
            budgeted_as_sends,
        }))
    }
    /// Routes a call to one catalogued connector — the EXECUTION lens, so
    /// `Some` ONLY while the governing key is Active (a removed or suspended
    /// connector reports `None` and stops execution at the lookup).
    ///
    /// `budgeted_as_sends` is ENTRY-WIDE and there is deliberately no verb
    /// parameter: ARCH-0054's Send class is a property of what the connector
    /// IS, not of which verb a caller reaches for. An UNCLASSIFIED key
    /// (`catalog = None`) has no route at all, which leaves the executor on
    /// the canon default — scoped-MCP tool calls unbudgeted.
    ///
    /// This is metadata only. The live chokepoint keeps charging through
    /// `charge_effector_budgets` until the named wiring follow-on consults
    /// this route.
    pub fn route_connector_call(&self, name: &str) -> Result<Option<ConnectorCallRoute>> {
        let rtxn = self.store.env.read_txn()?;
        let Some((key_ref, record)) = self.catalog_record_in_txn(&rtxn, name)? else {
            return Ok(None);
        };
        if record.status != ConnectorKeyStatus::Active {
            return Ok(None);
        }
        let Some(entry) = record.catalog else {
            return Ok(None);
        };
        Ok(Some(ConnectorCallRoute {
            key_ref,
            connector: record.connector,
            call_class: entry.call_class,
            budgeted_as_sends: entry.call_class.debits_sends(),
            verbs: entry.verbs,
            secret_ref: record.secret_ref,
        }))
    }
    /// Resolves a catalog name (normalized) to its key through the permanent
    /// name index, regardless of status.
    fn catalog_record_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        name: &str,
    ) -> Result<Option<(EntityId, ConnectorKeyRecord)>> {
        let name_key = connector_catalog_name_index_key(&normalize_connector_key(name));
        let Some(raw_id) = self.store.vault_meta.get(rtxn, &name_key)? else {
            return Ok(None);
        };
        let id = connector_catalog_index_entity_id(&raw_id)?;
        let record = read_connector_key_in_txn(&self.store, rtxn, &id)?
            .ok_or(Error::CorruptedIndex("connector catalog name index row"))?;
        Ok(Some((id, record)))
    }
}
