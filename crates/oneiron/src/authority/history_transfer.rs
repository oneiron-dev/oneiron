//! Signed-history migration and independently authorized per-vault re-root doors.
use super::*;
use crate::batch::{BatchOp, apply_ops};
use crate::error::{Error, RecordError, Result};
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::{EntityId, TimeRange, Vault};
use std::collections::{BTreeMap, BTreeSet};

use super::adopted_evidence::AdoptedEvidence;

#[cfg(feature = "sync")]
mod handoff;

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

/// Refuses the import when an arriving row stands on a key a handoff retired
/// in `fold` ([`retired_standing`]).
fn refuse_retired_standing(
    store: &crate::store::Store,
    fold: &AuthorityFold,
    merged: &BTreeMap<AuthorityEntryHash, (Vec<u8>, AuthorityLogEntry)>,
    evidence: Option<&AdoptedEvidence>,
    arriving: &[AuthorityEntryHash],
) -> Result<()> {
    match retired_standing(store, fold, merged, evidence, arriving)? {
        Some(_) => Err(retired_standing_refusal()),
        None => Ok(()),
    }
}

fn retired_standing_refusal() -> Error {
    Error::Record(RecordError::InvalidAuthorityLogBody(
        "authority history standing on a key a handoff retired",
    ))
}

/// The first arriving row that stands on a key a handoff retired in `fold`:
/// such a key signs nothing new into this history, and nothing new stands on
/// a row one signed. `merged` holds the resident and arriving rows. On a
/// vault that adopted a checkpoint image (`evidence`), an ancestor `merged`
/// lacks is what the image holds of it
/// ([`super::adopted_evidence::AdoptedEvidence::ancestor`]), its refusal
/// for history the image does not carry included.
fn retired_standing(
    store: &crate::store::Store,
    fold: &AuthorityFold,
    merged: &BTreeMap<AuthorityEntryHash, (Vec<u8>, AuthorityLogEntry)>,
    evidence: Option<&AdoptedEvidence>,
    arriving: &[AuthorityEntryHash],
) -> Result<Option<AuthorityEntryHash>> {
    for hash in arriving {
        let Some((_, entry)) = merged.get(hash) else {
            continue;
        };
        if super::door_refuses_retired_standing(
            store,
            fold,
            hash,
            entry,
            &mut |parent| match merged.get(parent) {
                Some((_, row)) => Ok(Some(row.clone())),
                None => evidence.map_or(Ok(None), |evidence| evidence.ancestor(parent)),
            },
        )? {
            return Ok(Some(*hash));
        }
    }
    Ok(None)
}

/// What an import reads beside the rows it holds on a vault that adopted a
/// checkpoint image (OF-469, slice E): the adopted, attested prefix the
/// signed incoming tail extends, never a full prefix to replay. The genesis
/// its verified pin names is the root, which a resident or arriving Genesis
/// must be, and each row the image covers stands as held for a parent check.
/// A covered row the import carries is hydration: it is not resident until
/// it lands, and the store door judges it as any arriving row. With no
/// adoption an import reads the rows it holds alone, as before (CALLS:
/// OF-469 slice E import context on an adopted vault).
#[derive(Clone, Copy)]
pub(super) struct AdoptedPrefix<'a> {
    genesis: AuthorityVaultId,
    covered: &'a BTreeMap<AuthorityEntryHash, AuthorityCheckpointRow>,
}

impl<'a> AdoptedPrefix<'a> {
    /// The prefix the verified, adopted image `adopted` stands for.
    pub(super) fn of(adopted: &'a VerifiedAuthorityCheckpoint) -> Self {
        Self {
            genesis: adopted.pin().genesis,
            covered: &adopted.image().rows,
        }
    }
}

/// The one genesis among `history`'s rows and, on an adopted vault,
/// `adopted`'s pin; more than one refuses.
fn import_root(
    history: &BTreeMap<AuthorityEntryHash, (Vec<u8>, AuthorityLogEntry)>,
    adopted: Option<AdoptedPrefix<'_>>,
) -> Result<Option<AuthorityVaultId>> {
    let mut roots: BTreeSet<_> = history
        .iter()
        .filter_map(|(hash, (_, entry))| {
            matches!(entry.op, AuthorityOp::Genesis { .. }).then_some(*hash)
        })
        .collect();
    roots.extend(adopted.map(|adopted| adopted.genesis));
    if roots.len() > 1 {
        return Err(invalid_authority());
    }
    Ok(roots.first().copied())
}

/// Whether `hash` is held for an imported row's parent check: in `history`,
/// or covered by the adopted image.
fn parent_held(
    history: &BTreeMap<AuthorityEntryHash, (Vec<u8>, AuthorityLogEntry)>,
    adopted: Option<AdoptedPrefix<'_>>,
    hash: &AuthorityEntryHash,
) -> bool {
    history.contains_key(hash) || adopted.is_some_and(|adopted| adopted.covered.contains_key(hash))
}

fn history_root(
    history: &BTreeMap<AuthorityEntryHash, (Vec<u8>, AuthorityLogEntry)>,
    adopted: Option<AdoptedPrefix<'_>>,
) -> Result<Option<AuthorityVaultId>> {
    let root = import_root(history, adopted)?;
    for (_, entry) in history.values() {
        if !matches!(entry.op, AuthorityOp::Genesis { .. }) && entry.vault_id != root {
            return Err(invalid_authority());
        }
        if entry
            .parent_hashes
            .iter()
            .any(|hash| !parent_held(history, adopted, hash))
        {
            return Err(invalid_authority());
        }
    }
    Ok(root)
}

/// The refusal a full export gives on a vault that adopted a checkpoint
/// image while it does not physically hold every covered row (OF-469, slice
/// E): the full signed history includes the covered prefix, so the export
/// names what this vault lacks (the adopted pin's genesis, the image, the
/// covered rows not stored) and returns no suffix and no partial shape.
/// None once every covered row is held: the export runs as on any vault
/// (CALLS: OF-469 slice E full export on an adopted vault).
fn unheld_prefix(
    adopted: &VerifiedAuthorityCheckpoint,
    history: &BTreeMap<AuthorityEntryHash, (Vec<u8>, AuthorityLogEntry)>,
) -> Option<Error> {
    let missing: BTreeSet<AuthorityEntryHash> = adopted
        .image()
        .covered
        .iter()
        .filter(|hash| !history.contains_key(*hash))
        .copied()
        .collect();
    (!missing.is_empty()).then(|| {
        super::readonly_fold::history_required(&AuthorityHistoryRequest {
            vault_id: Some(adopted.pin().genesis),
            checkpoint: Some(adopted.id()),
            missing,
        })
    })
}

/// The rows an import's consent structure reads past the `resident` ones on
/// a vault that adopted a checkpoint image: the bodies the image carries of
/// rows not stored here, as [`super::import_order::write_stage_order`] reads
/// them. None of them is resident.
fn carried_structure<'a>(
    evidence: Option<&'a AdoptedEvidence>,
    resident: &'a BTreeSet<AuthorityEntryHash>,
) -> impl Iterator<Item = &'a AuthorityLogEntry> {
    evidence
        .into_iter()
        .flat_map(move |evidence| evidence.carried_past(resident))
        .map(|(_, entry)| entry)
}

/// The verified image this vault adopted, as an import reads it, and its
/// evidence, read only when there is one.
fn adopted_context_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
) -> Result<(
    Option<VerifiedAuthorityCheckpoint>,
    Option<std::sync::Arc<AdoptedEvidence>>,
)> {
    let Some(adopted) = super::checkpoint_adopt::adopted_authority_checkpoint_in_txn(store, txn)?
    else {
        return Ok((None, None));
    };
    let evidence = super::adopted_evidence::adopted_evidence_in_txn(store, txn)?;
    Ok((Some(adopted), evidence))
}

impl Vault {
    /// Exports the full origin-signed history, including signed quarantined forks.
    /// Original bytes and the genesis identity are preserved. No local secret leaves.
    /// On a vault that adopted a checkpoint image, the full history includes
    /// the covered prefix: until every covered row is physically held here,
    /// the export refuses with the history it lacks ([`unheld_prefix`]).
    pub fn export_signed_authority_history(&self) -> Result<Vec<Vec<u8>>> {
        let txn = self.store.env.read_txn()?;
        let mut history = history_in_txn(self, &txn)?;
        if let Some(adopted) =
            super::checkpoint_adopt::adopted_authority_checkpoint_in_txn(&self.store, &txn)?
            && let Some(refusal) = unheld_prefix(&adopted, &history)
        {
            return Err(refusal);
        }
        history_root(&history, None)?;
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
    /// On a vault that adopted a checkpoint image, complete means the adopted,
    /// attested prefix plus the signed incoming tail, not an independent
    /// replay of the whole prefix ([`AdoptedPrefix`]); a covered row the
    /// blobs carry lands as hydration.
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
        let (adopted, evidence) = adopted_context_in_txn(&self.store, &txn)?;
        let prefix = adopted.as_ref().map(AdoptedPrefix::of);
        for (hash, bytes, entry) in &decoded {
            merged
                .entry(*hash)
                .or_insert_with(|| (bytes.clone(), entry.clone()));
        }
        let arriving: Vec<AuthorityEntryHash> = decoded
            .iter()
            .map(|(hash, _, _)| *hash)
            .filter(|hash| !resident.contains(hash))
            .collect();
        // A vault missing history it must hold has no fold until an import
        // closes the gap (OF-469): its arriving rows are judged against the
        // fold that closes it, after staging, and an import that leaves it
        // open still refuses there.
        let local = match self.authority_fold_readonly_in_txn(&txn) {
            Ok(local) => Some(local),
            Err(error) if super::readonly_fold::is_history_incomplete(&error) => None,
            Err(error) => return Err(error),
        };
        if let Some(local) = &local {
            refuse_retired_standing(&self.store, local, &merged, evidence.as_deref(), &arriving)?;
        }
        history_root(&merged, prefix)?.ok_or_else(invalid_authority)?;
        let now = crate::unix_seconds_now();
        let mut ids = Vec::new();
        let mut ops = Vec::new();
        // The store door judges each row against the rows already staged
        // (H72), so stage each after its parents, its consent and its
        // signer's lower sequences, whatever order the caller gave.
        let stored = merged
            .iter()
            .filter(|(hash, _)| resident.contains(*hash))
            .map(|(_, (_, entry))| entry)
            .chain(carried_structure(evidence.as_deref(), &resident));
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
        if local.is_none() {
            refuse_retired_standing(&self.store, &fold, &merged, evidence.as_deref(), &arriving)?;
        }
        if fold.vault_root_is_conflicted() {
            return Err(invalid_authority());
        }
        txn.commit()?;
        watch.finish()?;
        // A home pick the import landed re-elected this node's MACRO home in
        // the write (DOOR-101): its watchers re-read it now.
        self.store.notify_proactivity_changes();
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
        // On a vault that adopted a checkpoint image, the signer's covered
        // rows count by their summaries, stored or not (OF-469, slice E).
        let adopted =
            super::checkpoint_adopt::adopted_authority_checkpoint_in_txn(&self.store, txn)?;
        let covered = adopted
            .iter()
            .flat_map(|adopted| adopted.image().rows.values())
            .filter(|row| row.signer == signer_key)
            .map(|row| row.seq);
        let seq = history
            .values()
            .filter(|(_, entry)| entry.signer_key() == &signer_key)
            .map(|(_, entry)| entry.seq)
            .chain(covered)
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
/// On a vault that adopted a checkpoint image, `adopted` adds its prefix
/// ([`AdoptedPrefix`]).
pub(super) fn page_root(
    history: &BTreeMap<AuthorityEntryHash, (Vec<u8>, AuthorityLogEntry)>,
    resident: &BTreeSet<AuthorityEntryHash>,
    adopted: Option<AdoptedPrefix<'_>>,
) -> Result<Option<AuthorityVaultId>> {
    let root = import_root(history, adopted)?;
    for (hash, (_, entry)) in history {
        if !matches!(entry.op, AuthorityOp::Genesis { .. }) && entry.vault_id != root {
            return Err(invalid_authority());
        }
        if !resident.contains(hash)
            && entry
                .parent_hashes
                .iter()
                .any(|parent| !parent_held(history, adopted, parent))
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
        match self.import_page_in(decode_page(blobs)?, false)? {
            PageVerdict::Landed(ids) => Ok(ids),
            PageVerdict::Retired(_) => Err(retired_standing_refusal()),
        }
    }

    /// [`Self::import_signed_authority_page`] for `decoded`. With `staged`,
    /// the rows a repair staged earlier arrive beside the page
    /// ([`super::history_repair`]), and the stage empties as they land.
    /// A row refused for retired standing writes nothing and is named.
    pub(super) fn import_page_in(
        &self,
        mut decoded: Vec<DecodedRow>,
        staged: bool,
    ) -> Result<PageVerdict> {
        let watch = crate::federation::StaleSweepWatch::begin(self);
        let mut txn = self.store.env.write_txn()?;
        let mut merged = history_in_txn(self, &txn)?;
        let resident: BTreeSet<AuthorityEntryHash> = merged.keys().copied().collect();
        let (adopted, evidence) = adopted_context_in_txn(&self.store, &txn)?;
        let prefix = adopted.as_ref().map(AdoptedPrefix::of);
        if staged {
            let paged: BTreeSet<AuthorityEntryHash> =
                decoded.iter().map(|(hash, _, _)| *hash).collect();
            decoded.extend(
                super::history_repair::staged_rows_in_txn(&self.store, &txn)?
                    .into_iter()
                    .filter(|(hash, _, _)| !resident.contains(hash) && !paged.contains(hash)),
            );
        }
        for (hash, bytes, entry) in &decoded {
            merged
                .entry(*hash)
                .or_insert_with(|| (bytes.clone(), entry.clone()));
        }
        let arriving: Vec<AuthorityEntryHash> = decoded
            .iter()
            .map(|(hash, _, _)| *hash)
            .filter(|hash| !resident.contains(hash))
            .collect();
        // A vault missing history it must hold has no fold until an import
        // closes the gap (OF-469): its arriving rows are judged against the
        // fold that closes it, after staging, and an import that leaves it
        // open still refuses there.
        let local = match self.authority_fold_readonly_in_txn(&txn) {
            Ok(local) => Some(local),
            Err(error) if super::readonly_fold::is_history_incomplete(&error) => None,
            Err(error) => return Err(error),
        };
        if let Some(local) = &local
            && let Some(refused) =
                retired_standing(&self.store, local, &merged, evidence.as_deref(), &arriving)?
        {
            return Ok(PageVerdict::Retired(refused));
        }
        page_root(&merged, &resident, prefix)?.ok_or_else(invalid_authority)?;
        let now = crate::unix_seconds_now();
        let mut ids = Vec::new();
        let mut ops = Vec::new();
        // The store door judges each row against the rows already staged
        // (H72), so stage each after its parents, its consent and its
        // signer's lower sequences, whatever order the caller gave.
        let stored = merged
            .iter()
            .filter(|(hash, _)| resident.contains(*hash))
            .map(|(_, (_, entry))| entry)
            .chain(carried_structure(evidence.as_deref(), &resident));
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
        if local.is_none()
            && let Some(refused) =
                retired_standing(&self.store, &fold, &merged, evidence.as_deref(), &arriving)?
        {
            return Ok(PageVerdict::Retired(refused));
        }
        if fold.vault_root_is_conflicted() {
            return Err(invalid_authority());
        }
        if staged {
            super::history_repair::clear_stage_in_txn(&self.store, &mut txn)?;
        }
        txn.commit()?;
        watch.finish()?;
        self.store.notify_proactivity_changes();
        // A row written after its window loaded reaches it only through the
        // live mirror.
        #[cfg(feature = "sync")]
        self.note_committed_rows(ids.iter().copied().collect());
        Ok(PageVerdict::Landed(ids))
    }
}

/// What a page import found, short of an error.
pub(super) enum PageVerdict {
    /// The page landed: the rows written.
    Landed(Vec<EntityId>),
    /// This arriving row stands on a key a handoff retired; nothing landed.
    Retired(AuthorityEntryHash),
}

/// One signed authority row as a page carries it: its hash, its original
/// bytes and the entry they decode to.
pub(super) type DecodedRow = (AuthorityEntryHash, Vec<u8>, AuthorityLogEntry);

/// A page's rows, decoded and hashed, in the caller's order.
pub(super) fn decode_page(blobs: &[Vec<u8>]) -> Result<Vec<DecodedRow>> {
    let mut decoded = Vec::with_capacity(blobs.len());
    for bytes in blobs {
        let entry = decode_authority_log_entry_body(bytes)?;
        decoded.push((authority_entry_hash(&entry)?, bytes.clone(), entry));
    }
    Ok(decoded)
}

#[cfg(feature = "sync")]
impl Vault {
    /// This vault's folded roster carried on, in memory, by `handoff`: signed
    /// ReRoot rows in chain order that hand the root on from where this
    /// vault's fold stands (FIX 2053). Each row is judged as the fold judges
    /// a ReRoot ([`handoff_row_stands`]) against the roster the rows before
    /// it leave, and applied as the fold applies one: every key it stood on
    /// is revoked and its successor stands. A row this fold already holds is
    /// skipped while no new row has landed. Nothing is written, and the
    /// folded roster is only ever extended, never replaced. A handoff that
    /// carries the rows its edges stand on folds whole with this vault's
    /// rows instead, in memory ([`handoff::through_closure`], FIX 3797).
    ///
    /// The authority vault id and the roster; `None` when the fold is in
    /// conflict or the handoff does not carry it on: a row out of chain, one
    /// a key this fold retired signed (a fork), or any other refusal.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn roster_through_handoff(
        &self,
        handoff: &[Vec<u8>],
    ) -> Result<Option<(AuthorityVaultId, BTreeMap<AuthorityKey, FoldedDevice>)>> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        drop(txn);
        if fold.vault_root_is_conflicted() {
            return Ok(None);
        }
        let Some(vault_id) = fold.vault_id else {
            return Ok(None);
        };
        let handoff = match handoff::through_closure(self, vault_id, handoff)? {
            handoff::HandoffClosure::Folded(verdict) => return Ok(verdict),
            handoff::HandoffClosure::Edges(edges) => edges,
        };
        let mut roster = fold.roster.clone();
        let mut landed = false;
        for bytes in &handoff {
            let Ok(entry) = decode_authority_log_entry_body(bytes) else {
                return Ok(None);
            };
            let Ok(hash) = authority_entry_hash(&entry) else {
                return Ok(None);
            };
            if !landed && fold.valid_entries.contains(&hash) {
                continue;
            }
            let AuthorityOp::ReRoot { new_device } = &entry.op else {
                return Ok(None);
            };
            if !handoff_row_stands(&fold, &roster, vault_id, &entry, new_device) {
                return Ok(None);
            }
            for device in roster.values_mut() {
                device.revoked = true;
            }
            roster.insert(
                new_device.key.clone(),
                FoldedDevice {
                    key: new_device.key.clone(),
                    tier: new_device.tier,
                    roles: new_device.roles,
                    revoked: false,
                },
            );
            landed = true;
        }
        Ok(Some((vault_id, roster)))
    }
}

/// Whether `entry`, a ReRoot to `new_device`, stands on `roster` as the fold
/// judges a ReRoot (FIX 2053): well formed and well signed, in this vault,
/// signed by a live Owner key of `roster` that `fold` never retired, its
/// cosigners live there too, a sequence past every row its signer signed in
/// `fold`, and a successor no wider than its signer and new to the roster.
/// The rows between `fold`'s heads and the handoff do not ride with it, so
/// its signer's standing in `roster` is the ancestry it is judged on.
#[cfg(feature = "sync")]
fn handoff_row_stands(
    fold: &AuthorityFold,
    roster: &BTreeMap<AuthorityKey, FoldedDevice>,
    vault_id: AuthorityVaultId,
    entry: &AuthorityLogEntry,
    new_device: &DeviceAuthority,
) -> bool {
    if entry.validate_shape().is_err()
        || verify_entry_signatures(entry).is_err()
        || entry.vault_id != Some(vault_id)
    {
        return false;
    }
    let signer = entry.signer_key();
    let Some(old_root) = roster.get(signer).filter(|device| !device.revoked) else {
        return false;
    };
    if old_root.roles & ROLE_OWNER == 0
        || new_device.roles & !(old_root.roles | ROLE_CLOUD) != 0
        || fold.retired_keys.contains(signer)
        || roster.contains_key(&new_device.key)
        || fold
            .append_sequences
            .get(signer)
            .is_some_and(|prior| entry.seq <= *prior)
    {
        return false;
    }
    let live = |key: &AuthorityKey| {
        roster
            .get(key)
            .is_some_and(|device| !device.revoked && device.roles != 0)
    };
    let participants: BTreeSet<&AuthorityKey> = std::iter::once(&entry.signer)
        .chain(&entry.cosigns)
        .map(|signature| &signature.public_key)
        .collect();
    participants.iter().all(|&key| live(key))
}
