//! Device-lease registry: reads, registration, revocation, and commit/mirror.
use loro::{ExportMode, Frontiers, LoroValue, ValueOrContainer, VersionVector};
use oneiron::SyncEngineContext;
use oneiron::sync::lease::{self, LeaseRecord, LeaseStatus, ROOT_LEASES_MAP};
use oneiron::sync::server_state;

use super::core::SyncServer;

/// Numeric lease ABI vault id for the legacy local single-vault server path.
/// Hosted paths set `SyncServerConfig::lease_vault_id` per tenant/vault.
pub(super) const SERVER_LEASE_VAULT_ID: u64 = 0;

#[derive(Debug, Clone)]
pub(super) struct RootLeaseEntry {
    pub(super) key: String,
    pub(super) vault_id: u64,
    pub(super) client_id: u64,
    pub(super) record: LeaseRecord,
}

impl SyncServer {
    pub(super) fn root_lease_entries(&self) -> Result<Vec<RootLeaseEntry>, oneiron::Error> {
        let leases = self.root_doc.get_map(ROOT_LEASES_MAP);
        let mut raw_entries: Vec<(String, Vec<u8>)> = Vec::new();
        let mut corrupt = false;
        leases.for_each(|key, value| {
            if let ValueOrContainer::Value(LoroValue::Binary(blob)) = value {
                raw_entries.push((key.to_string(), blob.to_vec()));
            } else {
                corrupt = true;
            }
        });
        if corrupt {
            return Err(oneiron::Error::CorruptedIndex(
                "non-binary root lease entry",
            ));
        }

        raw_entries
            .into_iter()
            .map(|(key, raw)| Self::decode_root_lease_entry(key, &raw))
            .collect()
    }

    fn root_lease_entry_for_vault_client(
        &self,
        vault_id: u64,
        client_id: u64,
    ) -> Result<Option<RootLeaseEntry>, oneiron::Error> {
        let leases = self.root_doc.get_map(ROOT_LEASES_MAP);
        let scoped_key = lease::lease_registry_key(vault_id, client_id);
        if let Some(value) = leases.get(&scoped_key) {
            return Self::decode_root_lease_value(scoped_key, value).map(Some);
        }

        let legacy_key = lease::client_id_hex(client_id);
        let Some(value) = leases.get(&legacy_key) else {
            return Ok(None);
        };
        let entry = Self::decode_root_lease_value(legacy_key, value)?;
        if entry.vault_id == vault_id {
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    fn decode_root_lease_value(
        key: String,
        value: ValueOrContainer,
    ) -> Result<RootLeaseEntry, oneiron::Error> {
        match value {
            ValueOrContainer::Value(LoroValue::Binary(raw)) => {
                Self::decode_root_lease_entry(key, &raw)
            }
            _ => Err(oneiron::Error::CorruptedIndex(
                "non-binary root lease entry",
            )),
        }
    }

    fn decode_root_lease_entry(key: String, raw: &[u8]) -> Result<RootLeaseEntry, oneiron::Error> {
        let record = lease::decode_lease_record(raw)?;
        let registry_key = lease::decode_lease_registry_key(&key)?;
        let vault_id = registry_key.effective_vault_id(&record)?;
        Ok(RootLeaseEntry {
            key,
            vault_id,
            client_id: registry_key.client_id,
            record,
        })
    }

    // ─── Device-lease registry (ONE-1140, OD-3) ──────────────────────────

    /// Retired device enrollment frame. Always refuses and never mutates the
    /// registry, including when an old device private key still signs a valid
    /// proof. Historical registry rows can only expire or be revoked.
    pub(crate) async fn register_lease(
        &self,
        client_id: u64,
        pubkey: &[u8; 32],
        pop_sig: &[u8; 64],
    ) -> Result<LeaseDecision, oneiron::Error> {
        self.register_lease_for_vault(self.config.lease_vault_id, client_id, pubkey, pop_sig)
            .await
    }

    pub(super) async fn register_lease_for_vault(
        &self,
        _vault_id: u64,
        _client_id: u64,
        _pubkey: &[u8; 32],
        _pop_sig: &[u8; 64],
    ) -> Result<LeaseDecision, oneiron::Error> {
        // Device-key enrollment is retired. Even a valid proof over leftover
        // m:device_sk cannot create authority. Use one-use slip pairing.
        Ok(LeaseDecision::rejected())
    }

    /// Revokes a binding (owner recovery surface, OD-8). Terminal: the
    /// record keeps its timestamps, status flips to REVOKED. Returns the
    /// decision with `granted == false` and a `root_update` delta when the
    /// binding existed; `Ok(None)`-equivalent (no update) when it did not.
    pub(crate) async fn revoke_lease(
        &self,
        client_id: u64,
    ) -> Result<Option<Vec<u8>>, oneiron::Error> {
        self.revoke_lease_for_vault(self.config.lease_vault_id, client_id)
            .await
    }

    pub(super) async fn revoke_lease_for_vault(
        &self,
        vault_id: u64,
        client_id: u64,
    ) -> Result<Option<Vec<u8>>, oneiron::Error> {
        let _guard = self.lease_registrar.lock().await;
        let leases = self.root_doc.get_map(ROOT_LEASES_MAP);
        let Some(entry) = self.root_lease_entry_for_vault_client(vault_id, client_id)? else {
            return Ok(None);
        };
        let mut record = entry.record;
        let vv_before = self.root_doc.oplog_vv();
        let frontiers_before = self.root_doc.state_frontiers();
        record.status = LeaseStatus::Revoked;
        let key_hex = lease::lease_registry_key(vault_id, client_id);
        if entry.key != key_hex {
            leases
                .delete(entry.key.as_str())
                .map_err(|e| oneiron::Error::sync_engine(SyncEngineContext::LoroMapDelete, e))?;
        }
        leases
            .insert(
                key_hex.as_str(),
                lease::encode_lease_record(&record).as_slice(),
            )
            .map_err(|e| oneiron::Error::sync_engine(SyncEngineContext::LoroMapInsert, e))?;
        self.commit_lease_changes(true, &vv_before, &frontiers_before)
    }

    /// Commits + persists + mirrors a registry mutation: root doc commit,
    /// `d:root` snapshot persist, `ls:` row mirror — then exports the
    /// update delta for broadcast. No-op (None) when nothing changed.
    ///
    /// ATOMICITY (ONE-1140): the `d:root` snapshot persist and the `ls:`
    /// mirror run in ONE `with_write_txn`, so a crash/failure after the
    /// `d:root` put rolls back the whole txn — never a new `d:root` over a
    /// stale/missing `ls:` mirror (which would let a revoked lease appear
    /// active at a replay door reading `ls:`). The `ls:` mirror derives from
    /// the in-memory (already-committed) `root_doc`, not by re-reading the
    /// staged `d:root`.
    pub(super) fn commit_lease_changes(
        &self,
        changed: bool,
        vv_before: &VersionVector,
        frontiers_before: &Frontiers,
    ) -> Result<Option<Vec<u8>>, oneiron::Error> {
        if !changed {
            return Ok(None);
        }
        self.root_doc.commit();
        if let Err(err) = self.vault.with_write_txn(|wtxn| {
            server_state::persist_root_snapshot_in_txn(&self.vault, wtxn, &self.root_doc)?;
            lease::mirror_leases_from_root_in_txn(&self.vault, wtxn, &self.root_doc)?;
            Ok(())
        }) {
            if let Err(revert_err) = self.root_doc.revert_to(frontiers_before) {
                return Err(oneiron::Error::sync_engine_rollback(
                    SyncEngineContext::LoroRevert,
                    err,
                    revert_err,
                ));
            }
            return Err(err);
        }
        let delta = self
            .root_doc
            .export(ExportMode::updates(vv_before))
            .map_err(|e| oneiron::Error::sync_engine(SyncEngineContext::LoroExportUpdates, e))?;
        Ok(Some(delta))
    }
}

/// Outcome of a lease registration attempt (ONE-1140).
#[derive(Debug)]
pub(crate) struct LeaseDecision {
    pub(crate) granted: bool,
    /// `expires_at` for the GRANTED ack; 0 when rejected (wire literal).
    pub(crate) expires_at: u64,
    /// Root-doc update delta to broadcast when the registry changed.
    pub(crate) root_update: Option<Vec<u8>>,
}

impl LeaseDecision {
    fn granted(expires_at: u64) -> Self {
        Self {
            granted: true,
            expires_at,
            root_update: None,
        }
    }

    pub(super) const fn rejected() -> Self {
        Self {
            granted: false,
            expires_at: 0,
            root_update: None,
        }
    }
}
