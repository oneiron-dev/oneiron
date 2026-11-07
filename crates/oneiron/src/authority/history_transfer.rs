//! Signed-history migration and independently authorized per-vault re-root doors.
use super::*;
use crate::batch::{BatchOp, apply_ops};
use crate::error::{Error, RecordError, Result};
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::{EntityId, TimeRange, Vault};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use super::adopted_evidence::AdoptedEvidence;

#[cfg(feature = "sync")]
mod handoff;
mod page;

pub(super) use page::{DecodedRow, PageVerdict, decode_page, page_root};

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

/// Whether an arriving row stands on a key a handoff retired in `fold`, as
/// [`retired_standing`] reads it, recording nothing (FIX 2536). The fold
/// before staging may lack a handoff's own ancestry, so an import it flags is
/// judged again on the merged history it stages, and refused, with its
/// evidence, only when that history still retires the key. An import it does
/// not flag lands as before.
fn flags_retired_standing(
    fold: &AuthorityFold,
    merged: &BTreeMap<AuthorityEntryHash, (Vec<u8>, AuthorityLogEntry)>,
    evidence: Option<&AdoptedEvidence>,
    arriving: &[AuthorityEntryHash],
) -> Result<bool> {
    for hash in arriving {
        let Some((_, entry)) = merged.get(hash) else {
            continue;
        };
        if fold.stands_on_retired_key(hash, entry, &mut |parent| match merged.get(parent) {
            Some((_, row)) => Ok(Some(row.clone())),
            None => evidence.map_or(Ok(None), |evidence| evidence.ancestor(parent)),
        })? {
            return Ok(true);
        }
    }
    Ok(false)
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
    Option<std::sync::Arc<VerifiedAuthorityCheckpoint>>,
    Option<std::sync::Arc<AdoptedEvidence>>,
)> {
    let Some((adopted, evidence)) = super::checkpoint_adopt::adopted_image_view_in_txn(store, txn)?
    else {
        return Ok((None, None));
    };
    Ok((Some(adopted), Some(evidence)))
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
            super::checkpoint_adopt::cached_adopted_authority_checkpoint_in_txn(&self.store, &txn)?
            && let Some(refusal) = unheld_prefix(adopted.as_ref(), &history)
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
        let prefix = adopted.as_deref().map(AdoptedPrefix::of);
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
        // open still refuses there. A row the fold before staging flags is
        // judged there too, on the merged history (FIX 2536).
        let judge_merged = match self.authority_fold_readonly_in_txn(&txn) {
            Ok(local) => flags_retired_standing(&local, &merged, evidence.as_deref(), &arriving)?,
            Err(error) if super::readonly_fold::is_history_incomplete(&error) => true,
            Err(error) => return Err(error),
        };
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
                row_version: None,
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
        if judge_merged {
            refuse_retired_standing(&self.store, &fold, &merged, evidence.as_deref(), &arriving)?;
        }
        if fold.vault_root_is_conflicted() {
            return Err(invalid_authority());
        }
        #[cfg(feature = "sync")]
        self.mark_pending_mirrors_in_txn(&mut txn, &ids.iter().copied().collect())?;
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
        self.apply_signed_re_root_with_joins(&[], entry)
    }

    /// [`Self::apply_signed_re_root`] for a move signed elsewhere over a
    /// main-log frontier wider than one entry names (FIX 11993): `joins` are
    /// the joins its signer signed first, in the host family, over the main
    /// log's heads, and the move names their tips. They land with the move
    /// in one write, and each must fold valid, or none does. The move and its
    /// joins must name every main-log head the write starts from. Nothing is
    /// re-signed and no parent is renamed; a move that no longer covers this
    /// vault's frontier is refused, for its signer to sign again. The rows
    /// are marked for the vault's loaded windows in the same write and
    /// announced once it commits, as an import's are.
    ///
    /// # Errors
    /// A move that is no ReRoot, a join that is no host-family main-log join
    /// by the move's own signer of the same vault or that the move does not
    /// rest on, a repeated join, a move that leaves a current main-log head
    /// uncovered, a transition the fold refuses, or a storage error.
    pub fn apply_signed_re_root_with_joins(
        &self,
        joins: &[AuthorityLogEntry],
        entry: &AuthorityLogEntry,
    ) -> Result<EntityId> {
        let mut txn = self.store.env.write_txn()?;
        let (id, rows) = self.apply_signed_re_root_in_txn(&mut txn, joins, entry)?;
        self.mark_authority_rows_in_txn(&mut txn, &rows)?;
        txn.commit()?;
        self.note_committed_authority_rows(rows);
        Ok(id)
    }

    /// Stages `joins` and the move `entry` in `txn` and refolds: the move's
    /// row and every row staged. Nothing is marked or announced here; the
    /// transaction owner does that around its commit.
    fn apply_signed_re_root_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        joins: &[AuthorityLogEntry],
        entry: &AuthorityLogEntry,
    ) -> Result<(EntityId, BTreeSet<EntityId>)> {
        if !matches!(entry.op, AuthorityOp::ReRoot { .. }) {
            return Err(invalid_authority());
        }
        let hash = authority_entry_hash(entry)?;
        let (join_hashes, under) = signed_re_root_joins(joins, entry)?;
        let now = crate::unix_seconds_now();
        let before = self.authority_fold_readonly_in_txn(txn)?;
        if before.vault_id.is_none() || entry.vault_id != before.vault_id {
            return Err(invalid_authority());
        }
        // A move covers every main-log head this write starts from (FIX
        // 11993 R1): a head has no resident child, so only the move or one
        // of its joins can name it. A row that landed after the move was
        // signed would otherwise fold invalid beside it; such a move is
        // signed again over the frontier as it now stands. Applying the
        // same move again is the one exception.
        if !before.valid_entries.contains(&hash)
            && !before.append_heads.iter().all(|head| under.contains(head))
        {
            return Err(Error::Record(RecordError::InvalidAuthorityLogBody(
                "re-root does not cover the current frontier; sign it again",
            )));
        }
        let at = TimeRange {
            start: now,
            end: now,
        };
        let staged: Vec<_> = joins
            .iter()
            .chain(std::iter::once(entry))
            .map(|row| (row.clone(), at, now))
            .collect();
        let ids = self.put_authority_log_entries_in_txn(txn, &staged)?;
        let after = self.authority_fold_readonly_in_txn(txn)?;
        if after.vault_id != before.vault_id
            || !after.valid_entries.contains(&hash)
            || !join_hashes
                .iter()
                .all(|join| after.valid_entries.contains(join))
        {
            return Err(Error::Record(RecordError::InvalidAuthorityLogBody(
                "re-root transition refused",
            )));
        }
        Ok((
            authority_log_entity_id_from_hash(&hash)?,
            ids.into_iter().collect(),
        ))
    }

    /// Marks authority `rows` this write stages for the vault's loaded
    /// windows, in the write (FIX 11993, as FIX 11821 does for an import), so
    /// a crash before the announcement still mirrors them.
    fn mark_authority_rows_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        rows: &BTreeSet<EntityId>,
    ) -> Result<()> {
        #[cfg(feature = "sync")]
        self.mark_pending_mirrors_in_txn(txn, rows)?;
        #[cfg(not(feature = "sync"))]
        let _ = (txn, rows);
        Ok(())
    }

    /// Announces committed authority `rows` to the live mirror (FIX 11993):
    /// a row written after its window loaded reaches it only that way.
    pub(super) fn note_committed_authority_rows(&self, rows: BTreeSet<EntityId>) {
        #[cfg(feature = "sync")]
        self.note_committed_rows(rows);
        #[cfg(not(feature = "sync"))]
        drop(rows);
    }

    /// Constructs and appends one root migration under the current root's
    /// signature, in one write transaction. The signer callback receives only
    /// domain-separated transcripts, each signed with `signer_key`, and runs
    /// while that transaction is open, so it must not write to this vault.
    ///
    /// A main-log frontier wider than one entry names is joined first (FIX
    /// 11867): the root signs the join through the callback, in the host
    /// family, whose rule (a live owner roster key) is the standing the move
    /// itself stands on, and the move names the join. An Ed25519 and a
    /// P-256 root join alike (FIX 11993). One join names every head in this
    /// call (FIX 8527), so no head count refuses and every head stays in the
    /// move's causal past, inside its fence. The join and the move are
    /// marked for the vault's loaded windows in the write and announced once
    /// it commits.
    pub fn re_root_authority<S>(
        &self,
        new_device: DeviceAuthority,
        signer_key: AuthorityKey,
        signer: S,
    ) -> Result<AuthorityLogEntry>
    where
        S: FnMut(&[u8]) -> Result<Vec<u8>>,
    {
        let signer = RefCell::new(signer);
        let sign = |transcript: &[u8]| (*signer.borrow_mut())(transcript);
        let joiner = FrontierSigner::Callback(&signer_key, &sign);
        let mut txn = self.store.env.write_txn()?;
        let (entry, rows) = self.re_root_authority_in_txn(
            &mut txn,
            new_device,
            (&signer_key, Some(joiner)),
            &sign,
        )?;
        txn.commit()?;
        self.note_committed_authority_rows(rows);
        Ok(entry)
    }

    /// The same move inside the caller's write transaction. `signer` runs
    /// while that transaction is open, so it must not open another. A
    /// frontier wider than one entry names is joined first by `joiner`, the
    /// key the move retires: the host signer, as its host-issued ops are
    /// (FIX 8498, Engine 09:31 (3)), or the root through the move's callback
    /// (FIX 11867, 11993); the move then names the join. With no `joiner`
    /// the move names the heads alone. The join and the move are
    /// marked for the vault's loaded windows in `txn`; the rows come back for
    /// the caller to announce once its own commit lands
    /// ([`Self::note_committed_authority_rows`]).
    pub(super) fn re_root_authority_in_txn<S>(
        &self,
        txn: &mut heed::RwTxn<'_>,
        new_device: DeviceAuthority,
        (signer_key, joiner): (&AuthorityKey, Option<FrontierSigner<'_>>),
        signer: S,
    ) -> Result<(AuthorityLogEntry, BTreeSet<EntityId>)>
    where
        S: FnOnce(&[u8]) -> Result<Vec<u8>>,
    {
        let mut rows = BTreeSet::new();
        if let Some(joiner) = joiner {
            let fold = self.authority_view_readonly_in_txn(txn)?;
            if let Some((_, joined)) = self.join_scoped_heads_with_rows_in_txn(
                txn,
                &fold,
                (&fold.append_heads, FrontierJoinScope::Main),
                joiner,
                MAX_PARENTS,
            )? {
                rows.extend(joined);
            }
        }
        let mut entry = self.unsigned_re_root_in_txn(txn, new_device, signer_key.clone())?;
        entry.signer.signature = signer(&authority_transcript(&entry)?)?;
        let (_, moved) = self.apply_signed_re_root_in_txn(txn, &[], &entry)?;
        rows.extend(moved);
        self.mark_authority_rows_in_txn(txn, &rows)?;
        Ok((entry, rows))
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
            super::checkpoint_adopt::cached_adopted_authority_checkpoint_in_txn(&self.store, txn)?;
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
    /// The move is [`Self::re_root_authority`]'s: `signer` signs the joins of a
    /// frontier wider than one entry names as well as the move (FIX 11867), so
    /// no head count refuses it.
    pub fn recover_cloud_account<S>(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        new_device: DeviceAuthority,
        signer_key: AuthorityKey,
        signer: S,
    ) -> Result<AuthorityLogEntry>
    where
        S: FnMut(&[u8]) -> Result<Vec<u8>>,
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

/// The hashes of `joins`, the joins a move signed elsewhere rests on (FIX
/// 11993): each a host-family join of the main log, of the move's vault, by
/// the move's own signer, named once, and under the move, a parent of it or
/// of another such join; and every hash the move or one of those joins
/// names. The fold judges each signature and standing.
fn signed_re_root_joins(
    joins: &[AuthorityLogEntry],
    entry: &AuthorityLogEntry,
) -> Result<(Vec<AuthorityEntryHash>, BTreeSet<AuthorityEntryHash>)> {
    let mut hashes = Vec::with_capacity(joins.len());
    for join in joins {
        if !matches!(
            join.op,
            AuthorityOp::FrontierJoin(FrontierJoin {
                family: FrontierJoinFamily::Host,
                scope: FrontierJoinScope::Main,
            })
        ) || join.vault_id != entry.vault_id
            || join.signer_key() != entry.signer_key()
        {
            return Err(invalid_authority());
        }
        hashes.push(authority_entry_hash(join)?);
    }
    let named: BTreeSet<AuthorityEntryHash> = hashes.iter().copied().collect();
    if named.len() != hashes.len() {
        return Err(invalid_authority());
    }
    let mut under: BTreeSet<AuthorityEntryHash> = entry.parent_hashes.iter().copied().collect();
    loop {
        let reached = under.len();
        for (join, hash) in joins.iter().zip(&hashes) {
            if under.contains(hash) {
                under.extend(join.parent_hashes.iter().copied());
            }
        }
        if under.len() == reached {
            break;
        }
    }
    if !hashes.iter().all(|hash| under.contains(hash)) {
        return Err(invalid_authority());
    }
    Ok((hashes, under))
}

/// One vault and its independently signed migration entry, with the joins
/// its signer signed first over a frontier wider than one entry names (FIX
/// 11993; empty when the frontier fits).
pub struct VaultRecoveryRequest<'a> {
    pub vault: &'a Vault,
    pub joins: Vec<AuthorityLogEntry>,
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
        .map(|request| {
            request
                .vault
                .apply_signed_re_root_with_joins(&request.joins, &request.entry)
        })
        .collect()
}

/// What a leave handoff proves of this vault's roster
/// ([`Vault::roster_through_handoff`], FIX 7919).
#[cfg(feature = "sync")]
pub(crate) enum HandoffRoster {
    /// The authority vault id and the roster whole evidence folds to.
    Proved(AuthorityVaultId, BTreeMap<AuthorityKey, FoldedDevice>),
    /// The evidence does not close: the authority vault id this vault
    /// folds, and the rows the handoff and this vault's rows still lack,
    /// ascending. No roster stands on it, so it proves nobody's standing.
    Pending(AuthorityVaultId, BTreeSet<AuthorityEntryHash>),
    /// The fold holds the root in conflict, or refuses the handoff.
    Refused,
}

#[cfg(feature = "sync")]
impl Vault {
    /// This vault's folded roster carried on, in memory, by `handoff`: the
    /// signed rows that hand the root on from where this vault's fold
    /// stands, and every row they stand on that this vault did not fold
    /// (FIX 2053, FIX 3797). They fold whole with this vault's rows by the
    /// fold that folds its own log, or past the checkpoint image this vault
    /// adopted as its own tail folds ([`handoff::through_closure`]). Nothing
    /// is written.
    ///
    /// Only evidence that closes proves a roster (FIX 7919). Where a row
    /// names a parent neither held, carried nor covered by that image, no
    /// chain cut out of the carried rows stands in for the fold, so no
    /// sibling fork or retirement they carry is dropped: the answer is
    /// pending and names the rows still lacking. Refused when this vault's
    /// fold holds the root in conflict, or the handoff does not carry it
    /// on: a row that does not decode, one of another vault, or a fold that
    /// refuses it.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn roster_through_handoff(&self, handoff: &[Vec<u8>]) -> Result<HandoffRoster> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        drop(txn);
        if fold.vault_root_is_conflicted() {
            return Ok(HandoffRoster::Refused);
        }
        let Some(vault_id) = fold.vault_id else {
            return Ok(HandoffRoster::Refused);
        };
        Ok(match handoff::through_closure(self, vault_id, handoff)? {
            handoff::HandoffClosure::Folded(Some((vault_id, roster))) => {
                HandoffRoster::Proved(vault_id, roster)
            }
            handoff::HandoffClosure::Folded(None) => HandoffRoster::Refused,
            handoff::HandoffClosure::Pending(missing) => HandoffRoster::Pending(vault_id, missing),
        })
    }
}
