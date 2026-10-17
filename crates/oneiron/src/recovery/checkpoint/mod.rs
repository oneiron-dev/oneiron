//! Tier-C physical-row checkpoints and one restore/wake/migrate path.
//!
//! Images encode raw database keys/values from ONE LMDB read transaction. They
//! never copy free pages, locks, index pages, telemetry or process leases. This
//! is distinct from the logical export's entity/claim transformation format.
//!
//! A result body kept as a file beside `data.mdb` (OF-597) is not in any row:
//! the image lists every one its rows name, and the snapshot seals each into
//! the same artifact after the image. A restore streams them back, each chunk
//! opened and checked, before the rows naming them land. Their line indexes
//! are rebuilt, never restored.
//!
//! Nothing leaves in the clear: the image and its bodies are one sealed
//! artifact under a key derived from the vault data key (`artifact`), opened
//! and checked whole before anything is decoded or made. Each one is
//! dual-signed by the install that took it and chained to the vault's last
//! (`commitment`); a restore refuses a signer its key does not trust.
mod artifact;
mod authority_plane;
mod commitment;
mod decisions;
mod host_holds;
mod rebuild;
mod restore_class;
mod tiers;
use crate::side_table::{self, Named, SideTable};
use crate::store::{DB_MANIFEST, ForkedCustodyDir, LiveCustody, MadeDestination};
use crate::{EntityId, Error, Result, Vault, VaultConfig};
pub use artifact::{ArtifactKind, ArtifactUnlocks, CheckpointKey};
pub use commitment::CheckpointSigner;
use heed::types::Bytes;
pub use host_holds::HostOrderHolds;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
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
    /// Each result body file the rows name: its BLAKE3 and length.
    bodies: Vec<([u8; 32], u64)>,
}

impl CheckpointImage {
    /// A direct restore may land on any install, so the image's machine
    /// identity, and the root it pins, stay with the install that minted it:
    /// the restored vault joins as a new machine and opens unpinned. So does a copy served beside a live vault,
    /// whose authority it keeps; only a restore that takes that vault's
    /// place carries its identity (`restore_class`).
    fn drop_machine_identity(&mut self) {
        if let Some(rows) = self.databases.get_mut("sync_state") {
            rows.retain(|(key, _)| !crate::identity::is_machine_identity_row(key));
        }
    }
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
    /// it first, and the directory on its path another user could change.
    Disk {
        dir: PathBuf,
        first: LiveCustody,
        #[cfg(unix)]
        shared: Option<crate::store::SharedPath>,
        /// The install's configured keystore; the platform's at its defaults
        /// when none was given ([`SideRestoreSource::with_keystore`]).
        keystore: Option<std::sync::Arc<dyn oneiron_keystore::DeviceKeystore>>,
    },
}
impl SideRestoreSource<'static> {
    /// The vault at `vault_dir`, read without opening it, so a running
    /// server may hold it; a vault open in this process is
    /// [`Vault::side_restore_source`]. Refuses when no vault is there, when
    /// it cannot be read, or when it is archived. Each restore reads it again
    /// at its start, and refuses if the vault there is no longer the store
    /// read here, bound to the custody it bound here.
    pub fn read(vault_dir: &Path) -> Result<Self> {
        let first = crate::store::read_live_custody(vault_dir)?;
        Ok(Self(Source::Disk {
            dir: vault_dir.to_path_buf(),
            first,
            #[cfg(unix)]
            shared: crate::store::shared_vault_root(vault_dir)?,
            keystore: None,
        }))
    }

    /// The source read off the disk, whose checkpoints open with `keystore`:
    /// the install's configured one.
    pub fn with_keystore(
        mut self,
        keystore: std::sync::Arc<dyn oneiron_keystore::DeviceKeystore>,
    ) -> Self {
        if let Source::Disk { keystore: slot, .. } = &mut self.0 {
            *slot = Some(keystore);
        }
        self
    }
}
impl SideRestoreSource<'_> {
    /// A directory on the path of a source read off the disk that another
    /// user could change, found when it was read. A restore from it goes
    /// ahead, since the vault opens and writes there as it is; a caller
    /// reports it with the fix. `None` for a vault open in this process.
    #[cfg(unix)]
    pub fn shared_path(&self) -> Option<&crate::store::SharedPath> {
        match &self.0 {
            Source::Disk { shared, .. } => shared.as_ref(),
            Source::Open(_) => None,
        }
    }
    /// The key the artifact at `checkpoint` opens with. A vault open in this
    /// process gives its own ([`Vault::checkpoint_key`]); one read off the
    /// disk is never opened, so this install's keystore unlocks the key from
    /// the device wrap the artifact carries
    /// ([`CheckpointKey::unlock_on_this_device`]).
    pub fn checkpoint_key(&self, checkpoint: &Path) -> Result<CheckpointKey> {
        match &self.0 {
            Source::Open(vault) => vault.checkpoint_key(),
            Source::Disk {
                keystore: Some(keystore),
                ..
            } => Ok(CheckpointKey::unlock(
                checkpoint,
                &crate::world_keys::VaultKeyUnlock::Device(keystore.as_ref()),
            )?
            .trusting_device(std::sync::Arc::clone(keystore))),
            Source::Disk { dir, .. } => CheckpointKey::unlock_on_this_device(checkpoint, dir),
        }
    }
    /// The source's live custody state, read now, at a restore's start.
    fn capture(&self) -> Result<LiveCustody> {
        match &self.0 {
            Source::Open(vault) => vault.store.live_custody(),
            Source::Disk { dir, first, .. } => {
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
/// Opens one sealed artifact with `key` and structurally checks its image;
/// returns the image, its checkpoint id and the bodies it carries.
fn read_image<'k>(
    path: &Path,
    key: &'k CheckpointKey,
) -> Result<(CheckpointImage, String, artifact::SealedBodies<'k>)> {
    let opened = artifact::open_artifact(path, key)?;
    let image: CheckpointImage = rmp_serde::from_slice(&opened.image).map_err(|_| codec_error())?;
    if image.version != 2
        || image.created_at != opened.created_at
        || image.bodies != opened.bodies.list()
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
    let id = blake3::Hash::from(opened.image_id).to_hex().to_string();
    Ok((image, id, opened.bodies))
}
impl Vault {
    /// Create-new output only: one sealed artifact under this vault's
    /// checkpoint key ([`Vault::checkpoint_key`]), unlocking the vault key with
    /// this device's wrap when this handle does not hold it. Checkpoint id
    /// hashes the entire canonical image.
    pub fn snapshot_checkpoint(&self, path: &Path, created_at: u64) -> Result<String> {
        self.snapshot_checkpoint_checked(path, created_at, None, ArtifactKind::Checkpoint)
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
        self.snapshot_checkpoint_checked(path, created_at, Some(owner), ArtifactKind::Checkpoint)
    }
    /// An owner's backup: [`Vault::snapshot_checkpoint`] sealed as a backup,
    /// and on `owner`'s request, when given, as
    /// [`Vault::snapshot_checkpoint_as`].
    pub fn snapshot_backup(
        &self,
        path: &Path,
        created_at: u64,
        owner: Option<&crate::consent::AuthenticatedOwner>,
    ) -> Result<String> {
        self.snapshot_checkpoint_checked(path, created_at, owner, ArtifactKind::Backup)
    }
    fn snapshot_checkpoint_checked(
        &self,
        path: &Path,
        created_at: u64,
        owner: Option<&crate::consent::AuthenticatedOwner>,
        kind: ArtifactKind,
    ) -> Result<String> {
        self.unlock_vault_key()?;
        let keys = self.checkpoint_signing_keys()?;
        let _custody = self.store.gate_custody_read_guard()?;
        let _bodies = self.pin_all_result_bodies();
        let txn = self.store.env.read_txn()?;
        if let Some(owner) = owner {
            owner.revalidate_in_txn(self, &txn)?;
        }
        // The vault key's wraps the artifact carries are the rows' own, and
        // so is the chain it extends.
        let (carried, key) = self.checkpoint_seal_in_txn(&txn)?;
        let link = commitment::Link {
            keys,
            head: self.checkpoint_chain_in_txn(&txn)?,
        };
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
        let mut bodies = Vec::new();
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
                if entry.name == "vault_meta"
                    && let Some(body) = crate::code_run::code_run_body_file_of_row(key, value)
                {
                    bodies.push(body);
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
            version: 2,
            created_at,
            databases,
            bodies,
        };
        let bytes = rmp_serde::to_vec_named(&image).map_err(|_| codec_error())?;
        // Body files are immutable once named, so the ones the snapshot's rows
        // name read the same after its transaction. Each is sealed into the
        // artifact after the image, and never lands anywhere in the clear.
        #[cfg(unix)]
        let body_dir = if image.bodies.is_empty() {
            None
        } else {
            Some(self.store.body_dir()?)
        };
        let open_body = |digest: &[u8; 32], len: u64| -> Result<std::fs::File> {
            #[cfg(unix)]
            if let Some(file) = match &body_dir {
                Some(dir) => dir.open_body(digest, len)?,
                None => None,
            } {
                return Ok(file);
            }
            #[cfg(not(unix))]
            let _ = (digest, len);
            Err(Error::CorruptedIndex("code-run result body file missing"))
        };
        let (id, head) = artifact::write_artifact(
            path,
            &key,
            kind,
            &carried,
            &link,
            created_at,
            &bytes,
            &image.bodies,
            open_body,
        )?;
        // A checkpoint the chain does not take is no checkpoint.
        if let Err(error) = self.advance_checkpoint_chain(link.head, head) {
            let _ = std::fs::remove_file(path);
            return Err(error);
        }
        Ok(blake3::Hash::from(id).to_hex().to_string())
    }
    /// Restore, wake and migrate use the same fail-closed path, with no tail replay.
    /// Model-dependent vectors enter the normal pending-embedding queue; no vector
    /// from another owner or old model can be served while that queue is rebuilt.
    /// The restored vault takes the image's vault's place and keeps its key
    /// custody; a copy served beside it is [`Vault::restore_checkpoint_beside`].
    ///
    /// Every restore is refused where another user could move a directory on
    /// the way to `destination` (or, replacing a vault, on the way to it): a
    /// directory not this user's or root's, or one a group or other may write
    /// without its sticky bit. Nothing is made there.
    ///
    /// Every restore opens the sealed artifact at `path` with `key` (the
    /// vault's [`Vault::checkpoint_key`], or one [`CheckpointKey::unlock`]
    /// unlocked from a wrap it carries) and checks it whole before it makes
    /// anything; another vault's, or one that does not open, is refused.
    pub fn restore_checkpoint(
        path: &Path,
        key: &CheckpointKey,
        destination: &Path,
        config: VaultConfig,
        reason: RestoreReason,
        restored_at: u64,
    ) -> Result<(Self, RestoreReport)> {
        let (mut image, checkpoint_id, bodies) = read_image(path, key)?;
        image.drop_machine_identity();
        let (made, forked, mut vault, report) = Self::restore_image(
            image,
            checkpoint_id,
            bodies,
            destination,
            config,
            reason,
            restored_at,
            Custody::Keep,
        )?;
        forked.keep();
        made.keep(&mut vault);
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
        key: &CheckpointKey,
        destination: &Path,
        config: VaultConfig,
        source: &SideRestoreSource<'_>,
        restored_at: u64,
    ) -> Result<(Self, RestoreReport)> {
        let live = source.capture()?;
        let (mut image, checkpoint_id, bodies) = read_image(path, key)?;
        image.drop_machine_identity();
        // The copy holds the source's records, so its host orders hold them too.
        host_holds::carry(&mut image.databases, live.host_holds())?;
        let (made, forked, mut vault, report) = Self::restore_image(
            image,
            checkpoint_id,
            bodies,
            destination,
            config,
            RestoreReason::Restore,
            restored_at,
            Custody::Fork(Some(&live)),
        )?;
        forked.keep();
        made.keep(&mut vault);
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
    /// opened, not a symlink to one. When `swap` fails, neither directory
    /// moved; this handle stays sealed, and should lifting this vault's mark
    /// fail too, the mark stays, which still opens it live where it is. When
    /// `swap` returns but the replacement's directory cannot be found at this
    /// vault's path, the swap is refused with both marks left as they were:
    /// the caller must not take either directory to be where it put it.
    /// Reopen the replacement before it mints or retires a key. A vault that
    /// admitted an agent request, or recovered its proof clock, after the
    /// replacement was made refuses it, and nothing moves: the replacement
    /// would not know those proofs; so does one that holds an agent id looser
    /// than this vault now does (H215).
    pub fn swap_in_replacement(
        &self,
        replacement: &Self,
        swap: impl FnOnce() -> std::io::Result<()>,
    ) -> Result<()> {
        self.store.swap_out(
            &replacement.store,
            |txn| {
                crate::authority::refuse_moved_proof_freshness(self, txn, replacement)?;
                crate::agent_def::refuse_loosened_agent_id_pins(
                    &self.store,
                    txn,
                    &replacement.store,
                )
            },
            swap,
        )
    }
    /// An owner's activation of the archived vault at `path` as a side vault
    /// of `source`, the vault that replaced it. Its key custody forks as a
    /// side restore's does ([`Vault::restore_checkpoint_beside`]): a key
    /// `source` destroyed or has committed to destroy is not copied and the
    /// receipts under it are dropped, and from then on an erase or age sweep
    /// in either vault never reaches the other's keys. Every receipt it
    /// keeps is read under its own keys before the activation commits; when
    /// this returns `Ok` it is done, and the vault opens live, joining as a
    /// new machine: its replacement is the machine it was. Refuses a vault
    /// that is not archived, a `source` whose custody is not the one it
    /// binds, and, before opening anything, a missing `path` or one where
    /// another user could move a directory on it; a refusal leaves it
    /// archived, as it was.
    pub fn activate_archived(
        path: &Path,
        config: VaultConfig,
        source: &SideRestoreSource<'_>,
    ) -> Result<()> {
        // The archive is admitted like the source before anything opens it
        // by name; a missing one is refused, not made.
        crate::store::admit_existing_vault_root(path)?;
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
    /// The copy joins as a new machine; `current` stays the machine it is.
    pub fn restore_checkpoint_keeping_authority(
        path: &Path,
        key: &CheckpointKey,
        destination: &Path,
        config: VaultConfig,
        current: &Self,
        restored_at: u64,
    ) -> Result<(Self, RestoreReport)> {
        Self::restore_with_current_authority(
            path,
            key,
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
        key: &CheckpointKey,
        staging: &Path,
        config: VaultConfig,
        current: &Self,
        restored_at: u64,
    ) -> Result<(Self, RestoreReport)> {
        Self::restore_with_current_authority(
            path,
            key,
            staging,
            config,
            current,
            restored_at,
            Custody::Replace(current.store.env.path()),
        )
    }
    fn restore_with_current_authority(
        path: &Path,
        key: &CheckpointKey,
        destination: &Path,
        config: VaultConfig,
        current: &Self,
        restored_at: u64,
        custody: Custody<'_>,
    ) -> Result<(Self, RestoreReport)> {
        // An archived vault's live state is not its custody's.
        current.store.refuse_archived()?;
        let (mut image, checkpoint_id, bodies) = read_image(path, key)?;
        // The carried rows hold `current`'s custody binding and retirements.
        authority_plane::carry_current_authority(&mut image.databases, current)?;
        // And its host orders, which no image carries.
        host_holds::carry_current(&mut image.databases, current)?;
        // Two live vaults never answer as one machine (wp-keys I7).
        if let Custody::Fork(_) = custody {
            image.drop_machine_identity();
        }
        let (made, forked, mut vault, report) = Self::restore_image(
            image,
            checkpoint_id,
            bodies,
            destination,
            config,
            RestoreReason::Restore,
            restored_at,
            custody,
        )?;
        #[cfg(test)]
        panic_if_armed();
        // Refused here, or unwound, the bindings above drop in reverse: the
        // copy closes, the custody it forked goes, and then the directory
        // made for it, still under the copy's lease (review r3, Sol F4).
        authority_plane::refuse_new_members(current, &vault)
            .and_then(|()| decisions::refuse_loosened_decisions(current, &vault))?;
        forked.keep();
        made.keep(&mut vault);
        Ok((vault, report))
    }
    /// Restores `image` into `destination`. The made directory, the forked
    /// custody and the copy come back in that order, so a caller's bindings,
    /// dropped in reverse, close the copy before the others go.
    #[allow(clippy::too_many_arguments)]
    fn restore_image(
        image: CheckpointImage,
        checkpoint_id: String,
        bodies: artifact::SealedBodies<'_>,
        destination: &Path,
        config: VaultConfig,
        reason: RestoreReason,
        restored_at: u64,
        custody: Custody<'_>,
    ) -> Result<(MadeDestination, ForkedCustody, Self, RestoreReport)> {
        // A job row of another kind in the owner-retained key range would
        // hide from that kind's scans: refused before any destination exists.
        if image.databases["job_records"].iter().any(|(key, value)| {
            crate::attempt_queue::foreign_row_in_owner_retained_range(key, value)
        }) {
            return Err(codec_error());
        }
        // A signed authority row that fails its key-free checks (an owner
        // root or a world-key record among them), and a FACET carrying PERSON
        // identity, are refused here as at every other write door, before any
        // destination exists.
        for (_, blob) in &image.databases["entities"] {
            validate_checkpoint_entity_row(blob)?;
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
        // The pin pass below reads every agent id pin the restore brings
        // back: one no pin decodes from is refused here, before a
        // destination exists (H215).
        crate::agent_def::refuse_unreadable_agent_id_pins(&image.databases["vault_meta"])?;
        // Existing content is never replaced or partially restored over. A
        // refusal from here on drops the copy, then the directory made for
        // it: only a committed restore keeps them (C8). The config is checked
        // first, as an owned open checks it before it touches the disk.
        Self::check_open_config(&config)?;
        let made = MadeDestination::make(destination, home)?;
        let mut forked = ForkedCustody(None);
        let vault = Self::open_under_lease(destination, config.clone(), made.lease()?)?;
        #[cfg(test)]
        fail_at(RestoreStep::FirstOpen)?;
        made.holds(&vault.store)?;
        // The bodies land, read back through their sealed chunks and each
        // checked against its digest, before any row naming them does.
        #[cfg(unix)]
        if !image.bodies.is_empty() {
            let mut bodies = bodies;
            let target = vault.store.body_dir()?;
            for (index, (digest, len)) in image.bodies.iter().enumerate() {
                target.import(digest, *len, &mut bodies.body(index))?;
            }
        }
        #[cfg(not(unix))]
        drop(bodies);
        vault.with_write_txn_grouped(|txn| {
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
            // The rows came back without a put: every entity kind is judged
            // against the image's own registry, now readable in this
            // transaction. A refusal discards the copy before it commits.
            vault
                .store
                .validate_checkpoint_entity_kinds_in_txn(&*txn, &image.databases["entities"])?;
            if fork {
                forked.0 = vault.store.fork_gate_custody_in_txn(txn, &gate_custody)?;
            }
            if let Some(home) = home {
                vault.store.mark_live_only_at_in_txn(txn, home)?;
            }
            vault
                .store
                .drop_erased_gate_decisions_in_txn(txn, gate_custody.erased())?;
            // A written-here mark carried from the live vault binds only a
            // carrier the restored rows hold, byte for byte.
            crate::identity_topology::drop_unheld_author_marks_in_txn(&vault.store, txn)?;
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
            // Rows came back without a put: each definition pins its id as a
            // put of it would have (H215).
            crate::agent_def::pin_stored_rows_in_txn(&vault.store, txn)?;
            #[cfg(test)]
            fail_at(RestoreStep::ImageWrite)?;
            Ok(())
        })?;
        drop(vault);
        // Re-open through all ABI, model, analyzer and manifest gates before rebuilding.
        let vault = Self::open_under_lease(destination, config, made.lease()?)?;
        #[cfg(test)]
        fail_at(RestoreStep::SecondOpen)?;
        made.holds(&vault.store)?;
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
            #[cfg(test)]
            fail_at(RestoreStep::ReceiptCheck)?;
        }
        let (rebuilt_entities, rebuilt_text_documents, pending_embeddings) =
            rebuild::rebuild(&vault)?;
        rebuild::rebuild_auxiliary(&vault, image.created_at)?;
        let epoch = RestoreEpoch {
            checkpoint_id,
            restored_at,
            reason,
        };
        vault.with_write_txn_grouped(|txn| {
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
        Ok((made, forked, vault, report))
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
mod test_hooks;
#[cfg(test)]
use test_hooks::{RestoreStep, fail_at, panic_if_armed};

#[cfg(test)]
mod tests;

/// Refuses a row with no header, which the index rebuild refuses anyway; a
/// body the local identity refusal turns away; or an AUTHORITY_LOG row whose
/// body the shared authority validator refuses, an empty one included: no
/// authority row is a bodiless shell.
fn validate_checkpoint_entity_row(blob: &[u8]) -> Result<()> {
    let header = crate::batch::EntityMetadataHeader::parse(blob).ok_or_else(codec_error)?;
    let body = &blob[crate::batch::ENTITY_METADATA_HEADER_LEN..];
    crate::batch::validate_local_identity_body(header.entity_type, body)?;
    if header.entity_type == crate::registry::ENTITY_TYPE_AUTHORITY_LOG
        && crate::authority::validate_authority_log_entry_body_bytes(body).is_err()
    {
        return Err(codec_error());
    }
    Ok(())
}
