//! Tier-C physical-row checkpoints and one restore/wake/migrate path.
//!
//! Images encode raw database keys/values from ONE LMDB read transaction. They
//! never copy free pages, locks, index pages, telemetry or process leases. This
//! is distinct from the logical export's entity/claim transformation format.
mod authority_plane;
mod decisions;
mod rebuild;
mod restore_class;
mod tiers;
use crate::side_table::{self, Named, SideTable};
use crate::store::{DB_MANIFEST, ForkedCustodyDir, LiveCustody};
use crate::{EntityId, Error, Result, Vault, VaultConfig};
use heed::types::Bytes;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::{Path, PathBuf},
};
pub use tiers::{StorageTier, storage_tier};
type CanonicalRows = Vec<(Vec<u8>, Vec<u8>)>;

/// Presence-only probes for the canonical rebuild inputs behind the text and
/// phonetic indexes; the tables themselves are owned elsewhere (`text` search
/// and [`crate::batch::phonetic_apply`]), so only existence is checked here,
/// never the value shape.
const INDEX_SOURCE_TEXT: SideTable<EntityId, (), Named> =
    SideTable::new(&side_table::INDEX_SOURCE_TEXT);
const INDEX_SOURCE_PHONETIC: SideTable<EntityId, (), Named> =
    SideTable::new(&side_table::BATCH_PHONETIC_INDEX_SOURCE);
/// Log of checkpoint restore/wake/migrate events, one row per epoch. Key:
/// `u64be(sequence)`.
const RESTORE_EPOCH: SideTable<u64, RestoreEpoch, Named> =
    SideTable::new(&side_table::RESTORE_EPOCH);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointImage {
    version: u16,
    created_at: u64,
    databases: BTreeMap<String, CanonicalRows>,
}
/// Whose exterior key custody a restored vault holds (ARCH-0038
/// #erasure-completeness, "Key custody in a side restore").
#[derive(Clone, Copy)]
enum Custody<'a> {
    /// The restored vault takes its source's place and keeps its custody.
    Keep,
    /// As `Keep`, for the replacement of the vault at `home`: archived until
    /// a swap puts it there ([`Vault::swap_in_replacement`]).
    Replace(&'a Path),
    /// A copy served beside its source gets custody of its own. It never
    /// holds a key the source's live state, when given, says is destroyed or
    /// committed to be.
    Fork(Option<&'a LiveCustody>),
}
/// The custody a side restore forked, removed on drop unless kept: a restore
/// that fails or is refused after its fork leaves no copy of a live key.
struct ForkedCustody(Option<ForkedCustodyDir>);
impl ForkedCustody {
    fn keep(mut self) {
        self.0 = None;
    }
}
impl Drop for ForkedCustody {
    fn drop(&mut self) {
        if let Some(forked) = self.0.take() {
            forked.remove();
        }
    }
}
/// The vault a side restore copies. Each restore reads its live key-custody
/// state when it starts: where its custody is, and the key retirements it
/// has committed. The copy never holds a key that state says is destroyed or
/// committed to be, though the image predates the retirement. A source that
/// cannot be read refuses the restore; an archived vault is no source, its
/// custody being its replacement's.
pub struct SideRestoreSource<'a>(Source<'a>);
enum Source<'a> {
    /// A vault open in this process, read through its own handle.
    Open(&'a Vault),
    /// A vault read off its directory, as [`SideRestoreSource::read`] read
    /// it first.
    Disk { dir: PathBuf, first: LiveCustody },
}
impl SideRestoreSource<'static> {
    /// The vault at `vault_dir`, read without opening it, so a running
    /// server may hold it; a vault open in this process is
    /// [`Vault::side_restore_source`]. Refuses when no vault is there, when
    /// it cannot be read, or when it is archived. Each restore reads it again
    /// at its start, and refuses if the vault there is no longer the store
    /// read here, bound to the custody it bound here.
    pub fn read(vault_dir: &Path) -> Result<Self> {
        Ok(Self(Source::Disk {
            dir: vault_dir.to_path_buf(),
            first: crate::store::read_live_custody(vault_dir)?,
        }))
    }
}
impl SideRestoreSource<'_> {
    /// The source's live custody state, read now, at a restore's start.
    fn capture(&self) -> Result<LiveCustody> {
        match &self.0 {
            Source::Open(vault) => vault.store.live_custody(),
            Source::Disk { dir, first } => {
                let live = crate::store::read_live_custody(dir)?;
                if !first.same_vault(&live) {
                    return Err(Error::InvalidConfig(
                        "the vault read as this side restore's source has changed".into(),
                    ));
                }
                Ok(live)
            }
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RestoreReason {
    Restore,
    Wake,
    Migrate,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreEpoch {
    pub checkpoint_id: String,
    pub restored_at: u64,
    pub reason: RestoreReason,
}
/// Source checkpoint identity and newly rebuilt engine indexes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreReport {
    pub epoch: RestoreEpoch,
    pub rebuilt_entities: usize,
    pub rebuilt_text_documents: usize,
    pub pending_embeddings: usize,
}
fn codec_error() -> Error {
    Error::CorruptedIndex("canonical checkpoint image")
}
/// Reads and structurally checks one image; returns it with its checkpoint id.
fn read_image(path: &Path) -> Result<(CheckpointImage, String)> {
    let mut file = std::fs::File::open(path)?;
    let mut header = [0; 41];
    file.read_exact(&mut header)?;
    if &header[..9] != b"ONEIRONC1" {
        return Err(codec_error());
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let digest = blake3::hash(&bytes);
    if digest.as_bytes() != &header[9..] {
        return Err(codec_error());
    }
    let image: CheckpointImage = rmp_serde::from_slice(&bytes).map_err(|_| codec_error())?;
    if image.version != 1
        || image.databases.len() != DB_MANIFEST.len()
        || DB_MANIFEST
            .iter()
            .any(|e| !image.databases.contains_key(e.name))
    {
        return Err(codec_error());
    }
    for (name, rows) in &image.databases {
        if rows.windows(2).any(|w| w[0].0 >= w[1].0)
            || rows
                .iter()
                .any(|(k, _)| storage_tier(name, k) != StorageTier::Canonical)
        {
            return Err(codec_error());
        }
    }
    if image.databases["entities"].iter().any(|(_, value)| {
        crate::batch::EntityMetadataHeader::parse(value)
            .is_some_and(|h| h.entity_type == crate::registry::ENTITY_TYPE_DIAGNOSTIC)
    }) {
        return Err(codec_error());
    }
    Ok((image, digest.to_hex().to_string()))
}
impl Vault {
    /// Create-new output only. Checkpoint id hashes the entire canonical image.
    pub fn snapshot_checkpoint(&self, path: &Path, created_at: u64) -> Result<String> {
        self.snapshot_checkpoint_checked(path, created_at, None)
    }
    /// [`Vault::snapshot_checkpoint`] on an owner's request. The proof is
    /// rechecked in the snapshot's own read transaction, so an owner whose
    /// person, credential or ownership went away while the request waited
    /// writes no checkpoint.
    ///
    /// # Errors
    /// As [`Vault::snapshot_checkpoint`], and
    /// [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated)
    /// when `owner` no longer holds.
    pub fn snapshot_checkpoint_as(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        path: &Path,
        created_at: u64,
    ) -> Result<String> {
        self.snapshot_checkpoint_checked(path, created_at, Some(owner))
    }
    fn snapshot_checkpoint_checked(
        &self,
        path: &Path,
        created_at: u64,
        owner: Option<&crate::consent::AuthenticatedOwner>,
    ) -> Result<String> {
        let _custody = self.store.gate_custody_read_guard()?;
        let txn = self.store.env.read_txn()?;
        if let Some(owner) = owner {
            owner.revalidate_in_txn(self, &txn)?;
        }
        // Refuse a checkpoint that cannot read CURRENT exterior custody; it
        // cannot package key bytes to paper over a missing/shredded key.
        self.store.for_each_gate_decision_in_txn(&txn, |_| Ok(()))?;
        // Only claim/summary bodies have a canonical re-embedding path today.
        // Diagnostics are deliberately runtime-only. Other explicit vectors must
        // not silently disappear.
        for row in self.store.vectors.iter(&txn)? {
            let (id, _) = row?;
            let id =
                crate::EntityId::from_bytes(id.as_ref().try_into().map_err(|_| codec_error())?)?;
            let raw = crate::ports::EntityStoreRead::port_entity_raw(&self.store, &txn, &id)?;
            let reconstructable = match raw.as_deref() {
                Some(raw) => {
                    rebuild::has_embedding_source(raw)?
                        || crate::batch::EntityMetadataHeader::parse(raw).is_some_and(|header| {
                            header.entity_type == crate::registry::ENTITY_TYPE_DIAGNOSTIC
                        })
                }
                None => false,
            };
            if !reconstructable {
                return Err(Error::InvalidConfig(
                    "checkpoint vector lacks a canonical re-embedding source".into(),
                ));
            }
        }
        // A pre-witness index is not silently restored as an empty search surface.
        for row in self.store.text_forward.iter(&txn)? {
            let (id, _) = row?;
            let id = EntityId::from_bytes(id.as_ref().try_into().map_err(|_| codec_error())?)?;
            if !INDEX_SOURCE_TEXT.contains(&self.store, &txn, &id)? {
                return Err(Error::InvalidConfig(
                    "text index lacks canonical rebuild input".into(),
                ));
            }
        }
        for row in self.store.phonetic_forward.iter(&txn)? {
            let (id, _) = row?;
            let id = EntityId::from_bytes(id.as_ref().try_into().map_err(|_| codec_error())?)?;
            if !INDEX_SOURCE_PHONETIC.contains(&self.store, &txn, &id)? {
                return Err(Error::InvalidConfig(
                    "phonetic index lacks canonical rebuild input".into(),
                ));
            }
        }
        let mut excluded = std::collections::BTreeSet::<Vec<u8>>::new();
        for row in crate::ports::EntityStoreRead::port_entity_raw_records(&self.store, &txn)? {
            let (key, value) = row?;
            if crate::batch::EntityMetadataHeader::parse(&value)
                .is_some_and(|h| h.entity_type == crate::registry::ENTITY_TYPE_DIAGNOSTIC)
            {
                excluded.insert(key.as_bytes().to_vec());
            }
        }
        let mut databases = BTreeMap::new();
        for entry in DB_MANIFEST {
            let db = self
                .store
                .env
                .open_database::<Bytes, Bytes>(&txn, Some(entry.name))?
                .ok_or(codec_error())?;
            let mut rows = Vec::new();
            for row in db.iter(&txn)? {
                let (key, value) = row?;
                if storage_tier(entry.name, key) != StorageTier::Canonical {
                    continue;
                }
                let excluded_row = match entry.name {
                    "entities" | "short_ids_reverse" => excluded.contains(key),
                    "short_ids" => excluded.contains(value),
                    "edges_out" | "edges_in" => {
                        key.len() == 33
                            && (excluded.contains(&key[..16]) || excluded.contains(&key[17..]))
                    }
                    "vault_meta" => [
                        INDEX_SOURCE_TEXT.decl().prefix,
                        INDEX_SOURCE_PHONETIC.decl().prefix,
                    ]
                    .iter()
                    .any(|p| key.strip_prefix(*p).is_some_and(|id| excluded.contains(id))),
                    _ => false,
                };
                if excluded_row {
                    continue;
                }
                let value = if entry.name == "job_records" {
                    rebuild::unlease_attempt(key, value)?
                } else {
                    value.to_vec()
                };
                rows.push((key.to_vec(), value));
            }
            databases.insert(entry.name.into(), rows);
        }
        drop(txn);
        let image = CheckpointImage {
            version: 1,
            created_at,
            databases,
        };
        let bytes = rmp_serde::to_vec_named(&image).map_err(|_| codec_error())?;
        let digest = blake3::hash(&bytes);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        // A checkpoint contains canonical private data and device key material.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(b"ONEIRONC1")?;
        file.write_all(digest.as_bytes())?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(digest.to_hex().to_string())
    }
    /// Restore, wake and migrate use the same fail-closed path, with no tail replay.
    /// Model-dependent vectors enter the normal pending-embedding queue; no vector
    /// from another owner or old model can be served while that queue is rebuilt.
    /// The restored vault takes the image's vault's place and keeps its key
    /// custody; a copy served beside it is [`Vault::restore_checkpoint_beside`].
    pub fn restore_checkpoint(
        path: &Path,
        destination: &Path,
        config: VaultConfig,
        reason: RestoreReason,
        restored_at: u64,
    ) -> Result<(Self, RestoreReport)> {
        let (image, checkpoint_id) = read_image(path)?;
        let (vault, report, forked) = Self::restore_image(
            image,
            checkpoint_id,
            destination,
            config,
            reason,
            restored_at,
            Custody::Keep,
        )?;
        forked.keep();
        Ok((vault, report))
    }
    /// [`Vault::restore_checkpoint`] as a copy served beside its source vault.
    /// Key custody forks at restore time: the copy gets its own custody beside
    /// `destination`, holding only the keys still live in the source's, so an
    /// erase or age sweep in either vault never reaches the other's keys or
    /// receipts. A key retirement `source` has committed, its key not yet
    /// destroyed, counts as done. Refuses a checkpoint whose key custody is
    /// not `source`'s.
    pub fn restore_checkpoint_beside(
        path: &Path,
        destination: &Path,
        config: VaultConfig,
        source: &SideRestoreSource<'_>,
        restored_at: u64,
    ) -> Result<(Self, RestoreReport)> {
        let live = source.capture()?;
        let (image, checkpoint_id) = read_image(path)?;
        let (vault, report, forked) = Self::restore_image(
            image,
            checkpoint_id,
            destination,
            config,
            RestoreReason::Restore,
            restored_at,
            Custody::Fork(Some(&live)),
        )?;
        forked.keep();
        Ok((vault, report))
    }
    /// This vault as the source of a restore beside it
    /// ([`Vault::restore_checkpoint_beside`]). Refuses an archived vault.
    pub fn side_restore_source(&self) -> Result<SideRestoreSource<'_>> {
        self.store.refuse_archived()?;
        Ok(SideRestoreSource(Source::Open(self)))
    }
    /// Puts `replacement`, restored for this vault's place
    /// ([`Vault::restore_checkpoint_replacing`]), in it through `swap`, which
    /// exchanges the two directories at once, and archives this vault. The
    /// replacement keeps the key custody this vault binds to, so this vault
    /// is set aside as an archive: this handle, and every later open of it,
    /// reads, and refuses every write, erase and key retirement, until
    /// [`Vault::activate_archived`] gives it custody of its own.
    ///
    /// Whichever of the two sits at this vault's path is the live one, at
    /// every instant of the swap and after a crash anywhere in it; the other
    /// opens archived. `swap` must exchange the directories the two handles
    /// opened, not a symlink to one: a swap that returns without the
    /// replacement's directory at this vault's path is refused. A swap that
    /// fails changes nothing on disk, though this handle stays sealed. Reopen
    /// the replacement before it mints or retires a key.
    pub fn swap_in_replacement(
        &self,
        replacement: &Self,
        swap: impl FnOnce() -> std::io::Result<()>,
    ) -> Result<()> {
        self.store.swap_out(&replacement.store, swap)
    }
    /// An owner's activation of the archived vault at `path` as a side vault
    /// of `source`, the vault that replaced it. Its key custody forks as a
    /// side restore's does ([`Vault::restore_checkpoint_beside`]): a key
    /// `source` destroyed or has committed to destroy is not copied and the
    /// receipts under it are dropped, and from then on an erase or age sweep
    /// in either vault never reaches the other's keys. Every receipt it
    /// keeps is read under its own keys before the activation commits; when
    /// this returns `Ok` it is done, and the vault opens live. Refuses a vault
    /// that is not archived, and a `source` whose custody is not the one it
    /// binds; a refusal leaves it archived, as it was.
    pub fn activate_archived(
        path: &Path,
        config: VaultConfig,
        source: &SideRestoreSource<'_>,
    ) -> Result<()> {
        let live = source.capture()?;
        let archive = Self::open_owned(path, config)?;
        archive.store.activate_archived(&live)
    }
    /// Historical content restore beside a live vault: the image's content
    /// with `current`'s live authority, consent, policy, credential and
    /// erasure state, every row classed deny by default (`restore_class`).
    /// Refuses before creating `destination` when the image is another
    /// vault's, or when a family entangled with content (a grant, policy
    /// manifest, custody, machine identity, room role or membership, e-sign
    /// ceremony) moved since the checkpoint, rather than roll it back
    /// (ARCH-0038, RD-20); refuses and removes `destination` when the result
    /// would make someone an owner or member who is not one of `current` now,
    /// or when a decision the engine makes from restored rows would permit
    /// more than it does in `current` (`decisions`).
    ///
    /// Key custody forks as in [`Vault::restore_checkpoint_beside`]. A key
    /// retirement `current` has committed, its key not yet destroyed, counts
    /// as done: the copy never holds a key its source has committed to destroy.
    pub fn restore_checkpoint_keeping_authority(
        path: &Path,
        destination: &Path,
        config: VaultConfig,
        current: &Self,
        restored_at: u64,
    ) -> Result<(Self, RestoreReport)> {
        Self::restore_with_current_authority(
            path,
            destination,
            config,
            current,
            restored_at,
            Custody::Fork(None),
        )
    }
    /// [`Vault::restore_checkpoint_keeping_authority`] for a restore that
    /// replaces `current`: it keeps `current`'s key custody rather than
    /// forking it, and is archived until [`Vault::swap_in_replacement`] puts
    /// it in `current`'s place. Until then this handle writes its rows but
    /// mints and retires no key.
    pub fn restore_checkpoint_replacing(
        path: &Path,
        staging: &Path,
        config: VaultConfig,
        current: &Self,
        restored_at: u64,
    ) -> Result<(Self, RestoreReport)> {
        Self::restore_with_current_authority(
            path,
            staging,
            config,
            current,
            restored_at,
            Custody::Replace(current.store.env.path()),
        )
    }
    fn restore_with_current_authority(
        path: &Path,
        destination: &Path,
        config: VaultConfig,
        current: &Self,
        restored_at: u64,
        custody: Custody<'_>,
    ) -> Result<(Self, RestoreReport)> {
        // An archived vault's live state is not its custody's.
        current.store.refuse_archived()?;
        let (mut image, checkpoint_id) = read_image(path)?;
        // The carried rows hold `current`'s custody binding and retirements.
        authority_plane::carry_current_authority(&mut image.databases, current)?;
        let (vault, report, forked) = Self::restore_image(
            image,
            checkpoint_id,
            destination,
            config,
            RestoreReason::Restore,
            restored_at,
            custody,
        )?;
        if let Err(error) = authority_plane::refuse_new_members(current, &vault)
            .and_then(|()| decisions::refuse_loosened_decisions(current, &vault))
        {
            drop(vault);
            // This call created the destination; nothing else is in it. The
            // custody it forked goes with it as `forked` drops.
            let _ = std::fs::remove_dir_all(destination);
            return Err(error);
        }
        forked.keep();
        Ok((vault, report))
    }
    fn restore_image(
        image: CheckpointImage,
        checkpoint_id: String,
        destination: &Path,
        config: VaultConfig,
        reason: RestoreReason,
        restored_at: u64,
        custody: Custody<'_>,
    ) -> Result<(Self, RestoreReport, ForkedCustody)> {
        // A job row of another kind in the owner-retained key range would
        // hide from that kind's scans: refused before any destination exists.
        if image.databases["job_records"].iter().any(|(key, value)| {
            crate::attempt_queue::foreign_row_in_owner_retained_range(key, value)
        }) {
            return Err(codec_error());
        }
        // Authenticate every ORCB row against LIVE exterior custody before
        // creating a destination. A checkpoint never carries a key copy, and
        // a row whose key an erase destroyed since is dropped, not restored.
        let (fork, source, home) = match custody {
            Custody::Keep => (false, None, None),
            Custody::Replace(home) => (false, None, Some(home)),
            Custody::Fork(source) => (true, source, None),
        };
        let gate_custody =
            crate::store::preflight_checkpoint_rows(&image.databases["vault_meta"], source)?;
        if fork {
            crate::store::refuse_custody_beside(destination)?;
        }
        // Existing content is never replaced or partially restored over.
        std::fs::create_dir(destination)?;
        let mut forked = ForkedCustody(None);
        let vault = Self::open_owned(destination, config.clone())?;
        vault.with_write_txn(|txn| {
            for entry in DB_MANIFEST {
                let db = vault
                    .store
                    .env
                    .open_database::<Bytes, Bytes>(txn, Some(entry.name))?
                    .ok_or(codec_error())?;
                db.clear(txn)?;
                for (key, value) in &image.databases[entry.name] {
                    db.put(txn, key, value)?;
                }
            }
            if fork {
                forked.0 = vault.store.fork_gate_custody_in_txn(txn, &gate_custody)?;
            }
            if let Some(home) = home {
                vault.store.mark_live_only_at_in_txn(txn, home)?;
            }
            vault
                .store
                .drop_erased_gate_decisions_in_txn(txn, gate_custody.erased())?;
            // Open-time seed/backfill gates consult type indexes. Reconstruct this
            // mechanical projection before reopening; tokenizer/model work waits
            // until those compatibility gates have passed.
            for (key, raw) in &image.databases["entities"] {
                let id = crate::EntityId::from_bytes(
                    key.as_slice().try_into().map_err(|_| codec_error())?,
                )?;
                let h = crate::batch::EntityMetadataHeader::parse(raw).ok_or_else(codec_error)?;
                crate::batch::stage_entity_index_rows(
                    &vault.store,
                    txn,
                    &id,
                    h.entity_type,
                    crate::temporal::TimeRange {
                        start: h.occurred_start,
                        end: h.occurred_end,
                    },
                    h.learned_at,
                )?;
            }
            Ok(())
        })?;
        drop(vault);
        // Re-open through all ABI, model, analyzer and manifest gates before rebuilding.
        let vault = Self::open_owned(destination, config)?;
        if let Some(home) = home {
            vault.store.unseal_replacement(home)?;
        }
        // The image carries only a binding to current exterior custody, never
        // the keys. Verify EVERY claim-bound receipt against those live keys,
        // or a side copy's forked ones, before reporting a successful restore,
        // wake, or migration.
        {
            let txn = vault.store.env.read_txn()?;
            vault
                .store
                .for_each_gate_decision_in_txn(&txn, |_| Ok(()))?;
        }
        let (rebuilt_entities, rebuilt_text_documents, pending_embeddings) =
            rebuild::rebuild(&vault)?;
        rebuild::rebuild_auxiliary(&vault, image.created_at)?;
        let epoch = RestoreEpoch {
            checkpoint_id,
            restored_at,
            reason,
        };
        vault.with_write_txn(|txn| {
            let sequence = match RESTORE_EPOCH.iter_rev_from(&vault.store, txn, &[])?.next() {
                None => 0,
                Some(row) => {
                    let (sequence, _) = row?;
                    sequence.checked_add(1).ok_or(codec_error())?
                }
            };
            RESTORE_EPOCH.put(&vault.store, txn, &sequence, &epoch)?;
            Ok(())
        })?;
        let report = RestoreReport {
            epoch,
            rebuilt_entities,
            rebuilt_text_documents,
            pending_embeddings,
        };
        Ok((vault, report, forked))
    }
    pub fn restore_epochs(&self) -> Result<Vec<RestoreEpoch>> {
        let txn = self.store.env.read_txn()?;
        let mut epochs = Vec::new();
        for row in RESTORE_EPOCH.iter_from(&self.store, &txn, &[])? {
            let (_, epoch) = row?;
            epochs.push(epoch);
        }
        Ok(epochs)
    }
}
#[cfg(test)]
mod tests;
