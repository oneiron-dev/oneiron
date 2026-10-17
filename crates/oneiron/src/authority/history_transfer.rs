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
        let watch = crate::federation::StaleSweepWatch::begin(self);
        let mut txn = self.store.env.write_txn()?;
        let mut merged = history_in_txn(self, &txn)?;
        let resident: BTreeSet<AuthorityEntryHash> = merged.keys().copied().collect();
        for (hash, bytes, entry) in &decoded {
            merged
                .entry(*hash)
                .or_insert_with(|| (bytes.clone(), entry.clone()));
        }
        // A key a handoff here retired signs nothing new into this history,
        // and nothing new stands on a row one signed.
        let local = self.authority_fold_readonly_in_txn(&txn)?;
        for (hash, _, entry) in &decoded {
            if !resident.contains(hash)
                && super::door_refuses_retired_standing(
                    &self.store,
                    &local,
                    hash,
                    entry,
                    &mut |parent| Ok(merged.get(parent).map(|(_, row)| row.clone())),
                )?
            {
                return Err(Error::Record(RecordError::InvalidAuthorityLogBody(
                    "authority history standing on a key a handoff retired",
                )));
            }
        }
        history_root(&merged)?.ok_or_else(invalid_authority)?;
        let now = crate::unix_seconds_now();
        let mut ids = Vec::new();
        let mut ops = Vec::new();
        // The store door judges each row against the rows already staged
        // (H72), so stage each after its parents, its consent and its
        // signer's lower sequences, whatever order the caller gave.
        let stored = merged
            .iter()
            .filter(|(hash, _)| resident.contains(*hash))
            .map(|(_, (_, entry))| entry);
        let own_roots = super::log_structure::LocalRoots::read_in_txn(&self.store, &txn)?;
        for (hash, bytes, _) in
            super::import_order::import_order(stored, &resident, own_roots, decoded)
        {
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
        watch.finish()?;
        // A row written after its window loaded reaches it only through the
        // live mirror.
        #[cfg(feature = "sync")]
        self.note_committed_rows(ids.iter().copied().collect());
        Ok(ids)
    }

    /// Appends an already-signed ReRoot only if its transition is valid in this vault.
    /// Each vault consumes its own independently signed history; there is no master share.
    pub fn apply_signed_re_root(&self, entry: &AuthorityLogEntry) -> Result<EntityId> {
        let mut txn = self.store.env.write_txn()?;
        let id = self.apply_signed_re_root_in_txn(&mut txn, entry)?;
        txn.commit()?;
        Ok(id)
    }

    fn apply_signed_re_root_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        entry: &AuthorityLogEntry,
    ) -> Result<EntityId> {
        if !matches!(entry.op, AuthorityOp::ReRoot { .. }) {
            return Err(invalid_authority());
        }
        let hash = authority_entry_hash(entry)?;
        let now = crate::unix_seconds_now();
        let before = self.authority_fold_readonly_in_txn(txn)?;
        if before.vault_id.is_none() || entry.vault_id != before.vault_id {
            return Err(invalid_authority());
        }
        let ids = self.put_authority_log_entries_in_txn(
            txn,
            &[(
                entry.clone(),
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )],
        )?;
        let after = self.authority_fold_readonly_in_txn(txn)?;
        if after.vault_id != before.vault_id || !after.valid_entries.contains(&hash) {
            return Err(Error::Record(RecordError::InvalidAuthorityLogBody(
                "re-root transition refused",
            )));
        }
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
        let mut entry = self.unsigned_re_root_in_txn(&txn, new_device, signer_key)?;
        drop(txn);
        entry.signer.signature = signer(&authority_transcript(&entry)?)?;
        self.apply_signed_re_root(&entry)?;
        Ok(entry)
    }

    /// The same move inside the caller's write transaction. `signer` runs
    /// while that transaction is open, so it must not open another.
    pub(super) fn re_root_authority_in_txn<S>(
        &self,
        txn: &mut heed::RwTxn<'_>,
        new_device: DeviceAuthority,
        signer_key: AuthorityKey,
        signer: S,
    ) -> Result<AuthorityLogEntry>
    where
        S: FnOnce(&[u8]) -> Result<Vec<u8>>,
    {
        let mut entry = self.unsigned_re_root_in_txn(txn, new_device, signer_key)?;
        entry.signer.signature = signer(&authority_transcript(&entry)?)?;
        self.apply_signed_re_root_in_txn(txn, &entry)?;
        Ok(entry)
    }

    fn unsigned_re_root_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        new_device: DeviceAuthority,
        signer_key: AuthorityKey,
    ) -> Result<AuthorityLogEntry> {
        let history = history_in_txn(self, txn)?;
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        // The main-log heads: a world's side entries are never a main entry's parent.
        let parents = fold.append_heads;
        let seq = history
            .values()
            .filter(|(_, entry)| entry.signer_key() == &signer_key)
            .map(|(_, entry)| entry.seq)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(invalid_authority)?;
        Ok(AuthorityLogEntry {
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
        })
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
        let actor = owner.revalidate(self)?;
        let txn = self.store.env.read_txn()?;
        self.verify_owner_write_actor_in_txn(
            &txn,
            &crate::WriteActor::new(actor, crate::EdgeActorClass::Human),
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

/// [`history_root`] for a page added to a history held in part: one genesis
/// and one vault, as there, but only the rows not yet `resident` must find
/// their parents. The store door never needs a row's parents stored, so a
/// machine that syncs what it opened holds the authority rows its windows
/// carry, some above a gap a later page closes.
fn page_root(
    history: &BTreeMap<AuthorityEntryHash, (Vec<u8>, AuthorityLogEntry)>,
    resident: &BTreeSet<AuthorityEntryHash>,
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
    for (hash, (_, entry)) in history {
        if !matches!(entry.op, AuthorityOp::Genesis { .. }) && entry.vault_id != root {
            return Err(invalid_authority());
        }
        if !resident.contains(hash)
            && entry
                .parent_hashes
                .iter()
                .any(|parent| !history.contains_key(parent))
        {
            return Err(invalid_authority());
        }
    }
    Ok(root)
}

impl Vault {
    /// [`Self::import_signed_authority_history`] for one delivery page of a
    /// history this vault holds in part (OF-469): each new entry's parents
    /// are held here or earlier in `blobs`, while a row already held may
    /// stand above a gap ([`page_root`]). Every other check of that door
    /// stands: one genesis and vault, retired standing, the store door's
    /// order and judgement, and the refold before commit. One refused entry
    /// writes nothing.
    pub fn import_signed_authority_page(&self, blobs: &[Vec<u8>]) -> Result<Vec<EntityId>> {
        let mut decoded = Vec::with_capacity(blobs.len());
        for bytes in blobs {
            let entry = decode_authority_log_entry_body(bytes)?;
            decoded.push((authority_entry_hash(&entry)?, bytes.clone(), entry));
        }
        let watch = crate::federation::StaleSweepWatch::begin(self);
        let mut txn = self.store.env.write_txn()?;
        let mut merged = history_in_txn(self, &txn)?;
        let resident: BTreeSet<AuthorityEntryHash> = merged.keys().copied().collect();
        for (hash, bytes, entry) in &decoded {
            merged
                .entry(*hash)
                .or_insert_with(|| (bytes.clone(), entry.clone()));
        }
        // A key a handoff here retired signs nothing new into this history,
        // and nothing new stands on a row one signed.
        let local = self.authority_fold_readonly_in_txn(&txn)?;
        for (hash, _, entry) in &decoded {
            if !resident.contains(hash)
                && super::door_refuses_retired_standing(
                    &self.store,
                    &local,
                    hash,
                    entry,
                    &mut |parent| Ok(merged.get(parent).map(|(_, row)| row.clone())),
                )?
            {
                return Err(Error::Record(RecordError::InvalidAuthorityLogBody(
                    "authority history standing on a key a handoff retired",
                )));
            }
        }
        page_root(&merged, &resident)?.ok_or_else(invalid_authority)?;
        let now = crate::unix_seconds_now();
        let mut ids = Vec::new();
        let mut ops = Vec::new();
        // The store door judges each row against the rows already staged
        // (H72), so stage each after its parents, its consent and its
        // signer's lower sequences, whatever order the caller gave.
        let stored = merged
            .iter()
            .filter(|(hash, _)| resident.contains(*hash))
            .map(|(_, (_, entry))| entry);
        let own_roots = super::log_structure::LocalRoots::read_in_txn(&self.store, &txn)?;
        for (hash, bytes, _) in
            super::import_order::import_order(stored, &resident, own_roots, decoded)
        {
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
        watch.finish()?;
        // A row written after its window loaded reaches it only through the
        // live mirror.
        #[cfg(feature = "sync")]
        self.note_committed_rows(ids.iter().copied().collect());
        Ok(ids)
    }
}
