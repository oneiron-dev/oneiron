//! Owner-authorized atomic rekey: revoke the old binding and grant a fresh one.
use super::{SyncServer, core::unix_seconds_now, leases::LeaseDecision};
use oneiron::{
    Error, SyncEngineContext,
    sync::lease::{self, LEASE_DURATION_SECS, LeaseRecord, LeaseStatus, ROOT_LEASES_MAP},
};
impl SyncServer {
    pub(crate) async fn rotate_lease(
        &self,
        old_client: u64,
        new_client: u64,
        key: &[u8; 32],
        proof: &[u8; 64],
    ) -> Result<LeaseDecision, Error> {
        if old_client == new_client || !lease::verify_lease_pop(new_client, key, proof) {
            return Ok(LeaseDecision::rejected());
        }
        let _guard = self.lease_registrar.lock().await;
        let vault_id = self.config.lease_vault_id;
        let entries = self.root_lease_entries()?;
        let Some(old) = entries
            .iter()
            .find(|e| e.vault_id == vault_id && e.client_id == old_client)
        else {
            return Ok(LeaseDecision::rejected());
        };
        if old.record.status == LeaseStatus::Revoked
            || old.record.pubkey == *key
            || entries.iter().any(|e| {
                e.vault_id == vault_id && (e.client_id == new_client || e.record.pubkey == *key)
            })
        {
            return Ok(LeaseDecision::rejected());
        }
        let before = self.root_doc.oplog_vv();
        let frontiers = self.root_doc.state_frontiers();
        let now = unix_seconds_now();
        let new = LeaseRecord {
            vault_id,
            status: LeaseStatus::Active,
            pubkey: *key,
            granted_at: now,
            renewed_at: now,
            expires_at: now + LEASE_DURATION_SECS,
        };
        let map = self.root_doc.get_map(ROOT_LEASES_MAP);
        let mut revoked = old.record;
        revoked.status = LeaseStatus::Revoked;
        map.insert(&old.key, lease::encode_lease_record(&revoked).as_slice())
            .map_err(|e| Error::sync_engine(SyncEngineContext::LoroMapInsert, e))?;
        map.insert(
            &lease::lease_registry_key(vault_id, new_client),
            lease::encode_lease_record(&new).as_slice(),
        )
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroMapInsert, e))?;
        let root_update = self.commit_lease_changes(true, &before, &frontiers)?;
        Ok(LeaseDecision {
            granted: true,
            expires_at: new.expires_at,
            root_update,
        })
    }
}
