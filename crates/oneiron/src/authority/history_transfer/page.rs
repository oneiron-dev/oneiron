//! One delivery page of a history this vault holds in part (OF-469): the
//! page door, its root check and its decoded rows.

use super::*;

/// [`history_root`] for a page added to a history held in part: one genesis
/// and one vault, as there, but only the rows not yet `resident` must find
/// their parents. The store door never needs a row's parents stored, so a
/// machine that syncs what it opened holds the authority rows its windows
/// carry, some above a gap a later page closes.
/// On a vault that adopted a checkpoint image, `adopted` adds its prefix
/// ([`AdoptedPrefix`]).
pub(in crate::authority) fn page_root(
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
    /// ([`crate::authority::history_repair`]), and the stage empties as they land.
    /// A row refused for retired standing writes nothing and is named.
    pub(in crate::authority) fn import_page_in(
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
                crate::authority::history_repair::staged_rows_in_txn(&self.store, &txn)?
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
        // open still refuses there. A row the fold before staging flags is
        // judged there too, on the merged history (FIX 2536).
        let judge_merged = match self.authority_fold_readonly_in_txn(&txn) {
            Ok(local) => flags_retired_standing(&local, &merged, evidence.as_deref(), &arriving)?,
            Err(error) if crate::authority::readonly_fold::is_history_incomplete(&error) => true,
            Err(error) => return Err(error),
        };
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
        let own_roots =
            crate::authority::log_structure::LocalRoots::read_in_txn(&self.store, &txn)?;
        for (hash, bytes, _) in
            crate::authority::import_order::import_order(stored, &resident, own_roots, decoded)
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
        if judge_merged
            && let Some(refused) =
                retired_standing(&self.store, &fold, &merged, evidence.as_deref(), &arriving)?
        {
            return Ok(PageVerdict::Retired(refused));
        }
        if fold.vault_root_is_conflicted() {
            return Err(invalid_authority());
        }
        if staged {
            crate::authority::history_repair::clear_stage_in_txn(&self.store, &mut txn)?;
        }
        #[cfg(feature = "sync")]
        self.mark_pending_mirrors_in_txn(&mut txn, &ids.iter().copied().collect())?;
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
pub(in crate::authority) enum PageVerdict {
    /// The page landed: the rows written.
    Landed(Vec<EntityId>),
    /// This arriving row stands on a key a handoff retired; nothing landed.
    Retired(AuthorityEntryHash),
}

/// One signed authority row as a page carries it: its hash, its original
/// bytes and the entry they decode to.
pub(in crate::authority) type DecodedRow = (AuthorityEntryHash, Vec<u8>, AuthorityLogEntry);

/// A page's rows, decoded and hashed, in the caller's order.
pub(in crate::authority) fn decode_page(blobs: &[Vec<u8>]) -> Result<Vec<DecodedRow>> {
    let mut decoded = Vec::with_capacity(blobs.len());
    for bytes in blobs {
        let entry = decode_authority_log_entry_body(bytes)?;
        decoded.push((authority_entry_hash(&entry)?, bytes.clone(), entry));
    }
    Ok(decoded)
}
