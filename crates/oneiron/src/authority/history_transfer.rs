//! Signed-history migration and independently authorized per-vault re-root doors.
use super::*;
use crate::batch::{BatchOp, apply_ops};
use crate::error::{Error, RecordError, Result};
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::{EntityId, TimeRange, Vault};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn history_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<BTreeMap<AuthorityEntryHash, (Vec<u8>, AuthorityLogEntry)>> {
    let mut history = BTreeMap::new();
    for (id, bytes) in authority_log_rows_in_txn(&vault.store, txn)? {
        let entry = decode_authority_log_entry_body(&bytes)?;
        let hash = authority_entry_hash(&entry)?;
        if authority_log_entity_id_from_hash(&hash)? != id {
            return Err(Error::CorruptedIndex("authority history key"));
        }
        history.insert(hash, (bytes, entry));
    }
    Ok(history)
}

fn history_root(
    history: &BTreeMap<AuthorityEntryHash, (Vec<u8>, AuthorityLogEntry)>,
) -> Result<Option<AuthorityVaultId>> {
    let roots: BTreeSet<_> = history
        .iter()
        .filter_map(|(hash, (_, entry))| {
            matches!(entry.op, AuthorityOp::Genesis { .. }).then_some(*hash)
        })
        .collect();
    if roots.len() > 1 {
        return Err(invalid_authority());
    }
    let root = roots.first().copied();
    for (_, entry) in history.values() {
        if !matches!(entry.op, AuthorityOp::Genesis { .. }) && entry.vault_id != root {
            return Err(invalid_authority());
        }
        if entry
            .parent_hashes
            .iter()
            .any(|hash| !history.contains_key(hash))
        {
            return Err(invalid_authority());
        }
    }
    Ok(root)
}

impl Vault {
    /// Exports the full origin-signed history, including signed quarantined forks.
    /// Original bytes and the genesis identity are preserved. No local secret leaves.
    pub fn export_signed_authority_history(&self) -> Result<Vec<Vec<u8>>> {
        let txn = self.store.env.read_txn()?;
        let mut history = history_in_txn(self, &txn)?;
        history_root(&history)?;
        let mut emitted = BTreeSet::new();
        let mut result = Vec::with_capacity(history.len());
        while !history.is_empty() {
            let Some(hash) = history.iter().find_map(|(hash, (_, entry))| {
                entry
                    .parent_hashes
                    .iter()
                    .all(|parent| emitted.contains(parent))
                    .then_some(*hash)
            }) else {
                return Err(invalid_authority());
            };
            let (bytes, _) = history
                .remove(&hash)
                .ok_or(Error::InvariantViolation("authority export order"))?;
            emitted.insert(hash);
            result.push(bytes);
        }
        Ok(result)
    }

    /// Imports a complete signed history, atomically, before an in-chain ReRoot.
    /// A different genesis, invalid signature or missing parent writes nothing.
    /// Imported history is refolded locally; it never imports a trusted roster snapshot.
    pub fn import_signed_authority_history(&self, blobs: &[Vec<u8>]) -> Result<Vec<EntityId>> {
        let mut decoded = Vec::with_capacity(blobs.len());
        for bytes in blobs {
            let entry = decode_authority_log_entry_body(bytes)?;
            decoded.push((authority_entry_hash(&entry)?, bytes.clone(), entry));
        }
        let mut txn = self.store.env.write_txn()?;
        let mut merged = history_in_txn(self, &txn)?;
        for (hash, bytes, entry) in &decoded {
            merged.insert(*hash, (bytes.clone(), entry.clone()));
        }
        history_root(&merged)?.ok_or_else(invalid_authority)?;
        let now = crate::unix_seconds_now();
        let mut ids = Vec::new();
        let mut ops = Vec::new();
        for (hash, bytes, _) in decoded {
            let id = authority_log_entity_id_from_hash(&hash)?;
            ids.push(id);
            ops.push(BatchOp::Put {
                id,
                entity_type: ENTITY_TYPE_AUTHORITY_LOG,
                occurred: TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                data: bytes,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            });
        }
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut txn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        // Read-side fold checks local sidecars as well as the signed chain.
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        if fold.vault_root_is_conflicted() {
            return Err(invalid_authority());
        }
        txn.commit()?;
        Ok(ids)
    }

    /// Appends an already-signed ReRoot only if its transition is valid in this vault.
    /// Each vault consumes its own independently signed history; there is no master share.
    pub fn apply_signed_re_root(&self, entry: &AuthorityLogEntry) -> Result<EntityId> {
        if !matches!(entry.op, AuthorityOp::ReRoot { .. }) {
            return Err(invalid_authority());
        }
        let hash = authority_entry_hash(entry)?;
        let now = crate::unix_seconds_now();
        let mut txn = self.store.env.write_txn()?;
        let before = self.authority_fold_readonly_in_txn(&txn)?;
        if before.vault_id.is_none() || entry.vault_id != before.vault_id {
            return Err(invalid_authority());
        }
        let ids = self.put_authority_log_entries_in_txn(
            &mut txn,
            &[(
                entry.clone(),
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )],
        )?;
        let after = self.authority_fold_readonly_in_txn(&txn)?;
        if after.vault_id != before.vault_id
            || !after.valid_entries.contains(&hash)
            || after.pending_widens.contains_key(&hash)
        {
            return Err(Error::Record(RecordError::InvalidAuthorityLogBody(
                "re-root transition refused",
            )));
        }
        txn.commit()?;
        ids.into_iter().next().ok_or_else(invalid_authority)
    }

    /// Constructs and appends one root migration under the current root's signature.
    /// The signer callback receives only the domain-separated transcript.
    pub fn re_root_authority<S>(
        &self,
        new_device: DeviceAuthority,
        signer_key: AuthorityKey,
        signer: S,
    ) -> Result<AuthorityLogEntry>
    where
        S: FnOnce(&[u8]) -> Result<Vec<u8>>,
    {
        let txn = self.store.env.read_txn()?;
        let history = history_in_txn(self, &txn)?;
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let mut parents = fold.valid_entries.clone();
        for hash in &fold.valid_entries {
            for parent in &history[hash].1.parent_hashes {
                parents.remove(parent);
            }
        }
        let seq = history
            .values()
            .filter(|(_, entry)| entry.signer_key() == &signer_key)
            .map(|(_, entry)| entry.seq)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(invalid_authority)?;
        drop(txn);
        let mut entry = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some(vault_id),
            seq,
            parent_hashes: parents.into_iter().collect(),
            op: AuthorityOp::ReRoot { new_device },
            signer: AuthoritySignature {
                suite: signer_key.suite(),
                public_key: signer_key,
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: crate::unix_seconds_now(),
        };
        entry.signer.signature = signer(&authority_transcript(&entry)?)?;
        self.apply_signed_re_root(&entry)?;
        Ok(entry)
    }

    /// Account-authenticated managed-vault recovery. The existing host root signs
    /// migration; account authentication never fabricates a second genesis or a widen.
    pub fn recover_cloud_account<S>(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        new_device: DeviceAuthority,
        signer_key: AuthorityKey,
        signer: S,
    ) -> Result<AuthorityLogEntry>
    where
        S: FnOnce(&[u8]) -> Result<Vec<u8>>,
    {
        if self.privacy_posture() != crate::HostingPrivacyPosture::Hosted {
            return Err(invalid_authority());
        }
        self.authenticate_owner(
            owner.actor(),
            owner.principal_ref(),
            true,
            owner.decision_id(),
        )?;
        let txn = self.store.env.read_txn()?;
        self.verify_owner_write_actor_in_txn(
            &txn,
            &crate::WriteActor::new(owner.actor(), crate::EdgeActorClass::Human),
        )?;
        drop(txn);
        self.re_root_authority(new_device, signer_key, signer)
    }
}

/// One vault and its independently signed migration entry.
pub struct VaultRecoveryRequest<'a> {
    pub vault: &'a Vault,
    pub entry: AuthorityLogEntry,
}

/// Recovers independent vaults. Results are per-vault: there is no cross-vault
/// transaction and a failed member cannot roll back another vault's recovery.
/// Co-located printed kits remain an explicit owner custody choice, not shared key material.
pub fn recover_vaults_independently(
    requests: &[VaultRecoveryRequest<'_>],
) -> Vec<Result<EntityId>> {
    requests
        .iter()
        .map(|request| request.vault.apply_signed_re_root(&request.entry))
        .collect()
}
