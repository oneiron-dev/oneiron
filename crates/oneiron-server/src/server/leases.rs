//! Device-lease registry: reads, registration, revocation, and commit/mirror.
use loro::{ExportMode, Frontiers, LoroValue, ValueOrContainer, VersionVector};
use oneiron::SyncEngineContext;
use oneiron::sync::lease::{self, LEASE_DURATION_SECS, LeaseRecord, LeaseStatus, ROOT_LEASES_MAP};
use oneiron::sync::server_state;

use super::core::{SyncServer, unix_seconds_now};

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

    /// Handles a TAG_LEASE_REQUEST: verify proof of possession, then apply
    /// the pinned binding rules under the registrar lock —
    ///
    /// * binding absent → unless this pubkey is revoked under ANY client_id
    ///   (OD-8 amended, pubkey-bound floor: refuse, write NO row), write an
    ///   ACTIVE record (`granted_at = renewed_at = now`, `expires_at = now +
    ///   90 d`), grant;
    /// * same pubkey, status ≠ revoked → renew (`renewed_at`/`expires_at`
    ///   refreshed; an expired binding flips back to active), grant;
    /// * same client id, DIFFERENT pubkey → reject, binding untouched
    ///   (first-binding-wins);
    /// * revoked → reject, terminal (OD-8).
    ///
    /// Revocation binds to the Ed25519 PUBKEY, not the mintable client_id
    /// (OD-8 amended, RULING A): a revoked pubkey can never obtain a fresh
    /// active lease under ANY client_id, so a device that rotates client_id
    /// while reusing its key cannot recover — recovery requires a fresh
    /// KEYPAIR. The public wrapper uses `SyncServerConfig::lease_vault_id`
    /// so hosted callers scope the floor to `(vault, pubkey)` while the
    /// default config preserves the existing single-vault server id.
    ///
    /// Scan-at-connect expiry (OD-7): any ACTIVE binding past its
    /// `expires_at` flips to EXPIRED first — server-side liveness
    /// bookkeeping only; replay doors never enforce time.
    ///
    /// Registry writes go to the root doc's `leases` map (server-write-only
    /// by the existing client-root-update rejection), are persisted to
    /// `d:root`, and are mirrored to this vault's `ls:` rows in the same
    /// logical op. The returned `root_update` delta must be broadcast to
    /// ALL connections (conn_id 0 — the requester needs its own record).
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
        vault_id: u64,
        client_id: u64,
        pubkey: &[u8; 32],
        pop_sig: &[u8; 64],
    ) -> Result<LeaseDecision, oneiron::Error> {
        // Invalid proof of possession: reject without touching state. The
        // transcript binds client_id AND pubkey, so a forged binding for a
        // key the requester does not hold can never reach the registry.
        if !lease::verify_lease_pop(client_id, pubkey, pop_sig) {
            return Ok(LeaseDecision::rejected());
        }

        let _guard = self.lease_registrar.lock().await;
        let now = unix_seconds_now();
        let leases = self.root_doc.get_map(ROOT_LEASES_MAP);
        let vv_before = self.root_doc.oplog_vv();
        let frontiers_before = self.root_doc.state_frontiers();
        let mut changed = false;

        // Scan-at-connect expiry flip (liveness bookkeeping, OD-7).
        //
        // The server is the SOLE registry writer and always stores BINARY
        // lease records, so ANY non-binary entry is local corruption that
        // could hide a revoked-pubkey row from the registration floor below.
        // Capture it out-of-band (Loro's `for_each` closure returns `()`) and
        // fail closed-HARD: refuse the WHOLE registration before any expiry
        // flip or registration decision — never best-effort skip the entry.
        let mut entries = self.root_lease_entries()?;
        for entry in &mut entries {
            // The server is the SOLE registry writer — a malformed record
            // is local corruption, fail closed (never best-effort decode).
            let mut record = entry.record;
            if record.status == LeaseStatus::Active && record.expires_at < now {
                record.status = LeaseStatus::Expired;
                let scoped_key = lease::lease_registry_key(entry.vault_id, entry.client_id);
                if entry.key != scoped_key {
                    leases.delete(entry.key.as_str()).map_err(|e| {
                        oneiron::Error::sync_engine(SyncEngineContext::LoroMapDelete, e)
                    })?;
                    entry.key = scoped_key;
                }
                leases
                    .insert(
                        entry.key.as_str(),
                        lease::encode_lease_record(&record).as_slice(),
                    )
                    .map_err(|e| {
                        oneiron::Error::sync_engine(SyncEngineContext::LoroMapInsert, e)
                    })?;
                entry.record = record;
                changed = true;
            }
        }

        let key_hex = lease::lease_registry_key(vault_id, client_id);
        let existing = entries
            .iter()
            .find(|entry| entry.key == key_hex)
            .or_else(|| {
                entries
                    .iter()
                    .find(|entry| entry.vault_id == vault_id && entry.client_id == client_id)
            });
        let pubkey_revoked = entries.iter().any(|entry| {
            entry.vault_id == vault_id
                && entry.record.pubkey == *pubkey
                && entry.record.status == LeaseStatus::Revoked
        });

        let decision = match existing {
            None => {
                // Pubkey-bound revocation FLOOR (OD-8 amended, RULING A):
                // refuse a fresh ACTIVE lease for a pubkey that ANY ls: row
                // has revoked — a revoked pubkey is terminal across all
                // client_ids, so a fresh client_id reusing a revoked key
                // cannot recover (recovery requires a fresh KEYPAIR). Reuses
                // the already-materialized `entries`; the server is the sole
                // writer, so a malformed record is local corruption and
                // propagates fail-closed (never best-effort decode).
                if pubkey_revoked {
                    // Binding refused — write NO row, grant nothing.
                    LeaseDecision::rejected()
                } else {
                    let record = LeaseRecord {
                        vault_id,
                        status: LeaseStatus::Active,
                        pubkey: *pubkey,
                        granted_at: now,
                        renewed_at: now,
                        expires_at: now + LEASE_DURATION_SECS,
                    };
                    leases
                        .insert(
                            key_hex.as_str(),
                            lease::encode_lease_record(&record).as_slice(),
                        )
                        .map_err(|e| {
                            oneiron::Error::sync_engine(SyncEngineContext::LoroMapInsert, e)
                        })?;
                    changed = true;
                    LeaseDecision::granted(record.expires_at)
                }
            }
            Some(entry) if entry.record.status == LeaseStatus::Revoked => {
                // Terminal (OD-8): a revoked binding never re-activates.
                LeaseDecision::rejected()
            }
            Some(entry) if entry.record.pubkey == *pubkey && pubkey_revoked => {
                // Renewal arm also honors the pubkey-bound revocation floor:
                // a sibling revoked row for this key is terminal across
                // client_ids, so an existing active binding cannot refresh.
                LeaseDecision::rejected()
            }
            Some(entry) if entry.record.pubkey == *pubkey => {
                let record = entry.record;
                let renewed = LeaseRecord {
                    vault_id: record.vault_id,
                    status: LeaseStatus::Active,
                    pubkey: record.pubkey,
                    granted_at: record.granted_at,
                    renewed_at: now,
                    expires_at: now + LEASE_DURATION_SECS,
                };
                if entry.key != key_hex {
                    leases.delete(entry.key.as_str()).map_err(|e| {
                        oneiron::Error::sync_engine(SyncEngineContext::LoroMapDelete, e)
                    })?;
                }
                leases
                    .insert(
                        key_hex.as_str(),
                        lease::encode_lease_record(&renewed).as_slice(),
                    )
                    .map_err(|e| {
                        oneiron::Error::sync_engine(SyncEngineContext::LoroMapInsert, e)
                    })?;
                changed = true;
                LeaseDecision::granted(renewed.expires_at)
            }
            // Same client id, different pubkey: first-binding-wins, the
            // existing binding is untouched.
            Some(_) => LeaseDecision::rejected(),
        };

        let root_update = self.commit_lease_changes(changed, &vv_before, &frontiers_before)?;
        Ok(LeaseDecision {
            root_update,
            ..decision
        })
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

    const fn rejected() -> Self {
        Self {
            granted: false,
            expires_at: 0,
            root_update: None,
        }
    }
}
