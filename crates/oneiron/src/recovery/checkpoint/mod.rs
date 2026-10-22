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
//! are rebuilt, never restored. A sealed vault's file goes as its envelope,
//! its key row with the rows (`carried_bodies`, FIX 5348).
//!
//! Nothing leaves in the clear: the image and its bodies are one sealed
//! artifact under a key derived from the vault data key (`artifact`), opened
//! and checked whole before anything is decoded or made. Each one is
//! dual-signed by the install that took it and chained to the vault's last
//! (`commitment`); a restore refuses a signer its key does not trust.
mod admission;
mod artifact;
mod authority_plane;
mod body_bind;
mod carried_bodies;
mod commitment;
mod custody_head;
mod decisions;
mod host_holds;
mod image;
mod landing;
mod pad_custody;
mod payload;
mod rebuild;
mod response_rows;
mod restore_class;
mod side_pads;
mod snapshot;
mod tiers;
mod watermark;
mod write_budget;
mod write_estimate;
use crate::side_table::{self, Named, SideTable};
pub use crate::store::custody_protocol;
use crate::store::{ForkedCustodyDir, LiveCustody};
use crate::{EntityId, Error, Result, Vault, VaultConfig};
pub use admission::{
    AddedRecipient, AdmittedRestore, AnchorDisposition, CustodyAdmissionFacts, CustodyPositionFact,
    CustodyRouteFact, EscrowRole, FreshRecipient, RecipientAdmissionFacts,
    RecipientRetirementDisposition, ReleasedRecipient, RestoreAdmission, RestoreAdmissionError,
    RestoreAdmissionReason, RestoreCommitFacts, RestoreDestinationState, RestorePhase, RestorePlan,
    RetiredBy, RetiredRecipient, SourceExpectation, VerifiedSource,
};
pub(crate) use admission::{Rejected, because};
pub use artifact::{ArtifactKind, ArtifactUnlocks, CheckpointKey};
pub use commitment::CheckpointSigner;
pub use custody_head::*;
pub use host_holds::{BackupHolds, HostOrderHolds};
use image::{CheckpointImage, read_image, read_image_required};
pub use pad_custody::PadRestoreNote;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};
pub use tiers::{StorageTier, storage_tier};
pub use watermark::{
    BACKUP_WATERMARK_MARKER_SUFFIX, BackupArtifactEvidence, BackupMarker, BackupSnapshotReceipt,
    BackupWatermark, backup_marker, inspect_backup, last_backed_up, verify_with_pins,
};
pub use write_budget::{AtWriteFloor, RecoveryWriteBudget};
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
/// Whose exterior key custody a restored vault holds (ARCH-0038
/// #erasure-completeness, "Key custody in a side restore").
#[derive(Clone, Copy)]
enum Custody<'a> {
    /// The restored vault takes its source's place and keeps its custody.
    Keep,
    /// As `Keep`, for the replacement of the vault at `home`: archived until
    /// a swap puts it there ([`Vault::swap_in_replacement`]). It re-elects
    /// its MACRO home over the host's own candidacy the vault it replaces
    /// kept, when it kept one, before it is returned (FIX 5661 C2b).
    Replace(&'a Path, Option<&'a [crate::DreamerHomeNodeCandidate]>),
    /// A copy served beside its source gets custody of its own. It never
    /// holds a key the source's live state, when given, says is destroyed or
    /// committed to be; with it, the source's live pad rows (`side_pads`).
    Fork(Option<(&'a LiveCustody, &'a side_pads::SidePads)>),
    /// As `Keep`, for a restore whose custody is not on this host and finds
    /// no head for it (or carries only the legacy untyped marker), on every
    /// entry point: its claim-bound rows whose keys stayed there are dropped
    /// and named, binding and intents with them (CUSTODY_NO_HEAD_GATE_ROWS).
    NewHost,
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
        /// A sealed vault's page seal, which every read of it opens with.
        page_seal: Option<crate::world_keys::VaultPageSeal>,
    },
}
impl SideRestoreSource<'static> {
    /// The vault at `vault_dir`, read without opening it, so a running
    /// server may hold it; a vault open in this process is
    /// [`Vault::side_restore_source`]. A sealed vault (OF-570 maximum tier)
    /// reads with `page_seal`, its seal unlocked from its mirror, here and at
    /// each restore's start. Refuses when no vault is there, when it cannot
    /// be read, or when it is archived. Each restore reads it again at its
    /// start, and refuses if the vault there is no longer the store read
    /// here, bound to the custody it bound here.
    pub fn read(
        vault_dir: &Path,
        page_seal: Option<crate::world_keys::VaultPageSeal>,
    ) -> Result<Self> {
        let first = crate::store::read_live_custody(vault_dir, page_seal.as_ref())?;
        Ok(Self(Source::Disk {
            dir: vault_dir.to_path_buf(),
            first,
            #[cfg(unix)]
            shared: crate::store::shared_vault_root(vault_dir)?,
            keystore: None,
            page_seal,
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
    /// The source's page seal while its pages are sealed (OF-570 maximum
    /// tier): a copy restored beside it takes a fresh incarnation of it, and
    /// so keeps the source's tier. `None` for a plain source.
    pub fn page_seal(&self) -> Option<&crate::world_keys::VaultPageSeal> {
        match &self.0 {
            Source::Open(vault) => vault
                .vault_pages_sealed()
                .then_some(vault.config.page_seal.as_ref())
                .flatten(),
            Source::Disk { page_seal, .. } => page_seal.as_ref(),
        }
    }
    /// The source's live custody state, read now, at a restore's start.
    fn capture(&self) -> Result<LiveCustody> {
        match &self.0 {
            Source::Open(vault) => vault.store.live_custody(),
            Source::Disk {
                dir,
                first,
                page_seal,
                ..
            } => {
                let live = crate::store::read_live_custody(dir, page_seal.as_ref())?;
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
    /// An owner's activation of an archived vault as a side vault
    /// ([`Vault::activate_archived`]): it lands no checkpoint, so its epoch
    /// names none.
    Activate,
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
    /// Claim-bound gate decisions a new-host restore dropped because their
    /// keys stayed on the old host, by decision id (hex): the image named
    /// no custody head (CALLS CUSTODY_NO_HEAD_GATE_ROWS).
    pub dropped_gate_decisions: Vec<String>,
    /// What the restore says about the custody head it used: rollback is
    /// not proven when no anchor was configured (CALLS
    /// CUSTODY_ANCHOR_UNSET_RESTORE).
    pub custody_note: Option<String>,
    /// What the restore costs the vault's publisher training (FIX 5892): set
    /// when the vault had a training link key and the restore brought none,
    /// so a fresh one is made at its next training write.
    pub training_note: Option<String>,
    /// The tables a home move carries that this restore took from the image
    /// because the live vault's rows did not read (FIX 5661 C2b).
    pub home_table_notes: Vec<HomeTableNote>,
    /// The world key pads its image names that it did not land at rest
    /// (KS-5, FIX 5686 part 2): erased since the image, or withheld by
    /// their world's sealed copies setting.
    pub pad_notes: Vec<PadRestoreNote>,
}
/// What a restore over a live vault says about a table a home move carries
/// (FIX 5661 C2b).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HomeTableNote {
    /// The live vault's rows of `table` did not read or decode, so the table
    /// kept its own restore class and its rows came from the image.
    Unreadable { table: String },
}
impl std::fmt::Display for HomeTableNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable { table } => {
                write!(f, "home table {table} unreadable: restored from image")
            }
        }
    }
}
fn codec_error() -> Error {
    Error::CorruptedIndex("canonical checkpoint image")
}
impl Vault {
    /// Create-new output only: one sealed artifact under this vault's
    /// checkpoint key ([`Vault::checkpoint_key`]), unlocking the vault key with
    /// this device's wrap when this handle does not hold it. Checkpoint id
    /// hashes the entire canonical image.
    pub fn snapshot_checkpoint(&self, path: &Path, created_at: u64) -> Result<String> {
        self.snapshot_checkpoint_checked(
            path,
            created_at,
            None,
            ArtifactKind::Checkpoint,
            None,
            &write_budget::Unfloored,
        )
        .map(|receipt| receipt.image_digest)
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
        self.snapshot_checkpoint_checked(
            path,
            created_at,
            Some(owner),
            ArtifactKind::Checkpoint,
            None,
            &write_budget::Unfloored,
        )
        .map(|receipt| receipt.image_digest)
    }
    /// An owner's backup: [`Vault::snapshot_checkpoint`] sealed as a backup,
    /// and on `owner`'s request, when given, as
    /// [`Vault::snapshot_checkpoint_as`]. `registry` is the registry's id for
    /// the vault where the host knows one (a managed vault's name): the
    /// artifact binds the vault id to it, or says it knew none (FIX 5826).
    /// Neither is refused. The receipt names the image, what the backup
    /// covered for [`Vault::backup_watermark`], and the artifact's evidence.
    pub fn snapshot_backup(
        &self,
        path: &Path,
        created_at: u64,
        owner: Option<&crate::consent::AuthenticatedOwner>,
        registry: Option<&str>,
    ) -> Result<BackupSnapshotReceipt> {
        self.snapshot_backup_within(path, created_at, owner, registry, &write_budget::Unfloored)
    }
    /// [`Vault::snapshot_backup`] on a disk whose host keeps a free-space
    /// floor under its uploads (FIX 5479): the artifact's room is claimed on
    /// `budget` before its first byte, at the most its streams can seal to,
    /// and set to what is left at each frame. A claim the floor refuses
    /// stops the backup with [`AtWriteFloor`], its partial file removed.
    pub fn snapshot_backup_within(
        &self,
        path: &Path,
        created_at: u64,
        owner: Option<&crate::consent::AuthenticatedOwner>,
        registry: Option<&str>,
        budget: &dyn RecoveryWriteBudget,
    ) -> Result<BackupSnapshotReceipt> {
        self.snapshot_checkpoint_checked(
            path,
            created_at,
            owner,
            ArtifactKind::Backup,
            registry,
            budget,
        )
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
        Self::restore_checkpoint_finishing(
            path,
            key,
            destination,
            config,
            reason,
            restored_at,
            |_| Ok(()),
        )
    }
    /// [`Vault::restore_checkpoint`], with `finish` run on the restored vault
    /// once its rows are in and it reopened, before it is kept: how a host
    /// wraps a restored sealed vault's key to itself before the vault is
    /// published. A refusal from `finish` removes the vault, and the
    /// page-seal mirror its open wrote, as any refusal does.
    pub fn restore_checkpoint_finishing(
        path: &Path,
        key: &CheckpointKey,
        destination: &Path,
        config: VaultConfig,
        reason: RestoreReason,
        restored_at: u64,
        finish: impl FnOnce(&Self) -> Result<()>,
    ) -> Result<(Self, RestoreReport)> {
        Self::restore_keeping_custody(
            path,
            key,
            destination,
            config,
            (reason, restored_at),
            None,
            finish,
        )
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
        Self::restore_checkpoint_beside_within(
            path,
            key,
            destination,
            config,
            source,
            restored_at,
            &write_budget::Unfloored,
        )
    }
    /// [`Vault::restore_checkpoint_beside`] on a disk whose host keeps a
    /// free-space floor under its uploads, as a rehearsal's copy is made
    /// (FIX 5479): the copy's bodies and rows are claimed on `budget` before
    /// it is made or opened, the rest set before each body and before the
    /// rows land, and each write it derives after them is admitted at the
    /// floor. A claim the floor refuses stops the restore with
    /// [`AtWriteFloor`], and the copy is removed as any refusal removes it.
    pub fn restore_checkpoint_beside_within(
        path: &Path,
        key: &CheckpointKey,
        destination: &Path,
        config: VaultConfig,
        source: &SideRestoreSource<'_>,
        restored_at: u64,
        budget: &dyn RecoveryWriteBudget,
    ) -> Result<(Self, RestoreReport)> {
        let live = source.capture()?;
        let (mut image, checkpoint_id, bodies) = read_image(path, key)?;
        image.drop_machine_identity();
        // The copy holds the source's records, so its host orders hold them too.
        host_holds::carry(&mut image.databases, live.host_holds())?;
        // A pad its forked custody lacks or cannot read comes from the
        // source's live row (KS-5).
        let pads = source.live_pads(&image);
        let (made, forked, mut vault, report) = Self::restore_image(
            image,
            checkpoint_id,
            bodies,
            destination,
            config,
            RestoreReason::Restore,
            restored_at,
            Custody::Fork(Some((&live, &pads))),
            &BTreeSet::new(),
            budget,
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
        // The archive the swap parks keeps every body instance its rows
        // name, until its custodian releases it (FIX 6022).
        self.store.hold_parked_archive_bodies()?;
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
    ///
    /// Every body the archive keeps is read back under its forked custody
    /// first, once what `source` retired took its rows as an erase took
    /// them (FIX 6020). The report says what a restore's says, from the
    /// vault reopened live (FIX 6033): when it was activated, the decisions
    /// dropped because their keys stayed on another host, the custody note
    /// its publication status gives, and the training note when its training
    /// link key did not come with it. It names no checkpoint and rebuilt
    /// nothing.
    pub fn activate_archived(
        path: &Path,
        config: VaultConfig,
        source: &SideRestoreSource<'_>,
    ) -> Result<RestoreReport> {
        // The archive is admitted like the source before anything opens it
        // by name; a missing one is refused, not made.
        crate::store::admit_existing_vault_root(path)?;
        let live = source.capture()?;
        let archive = Self::open_owned(path, config.clone())?;
        let (dropped_gate_decisions, erased_pads) = archive.store.activate_archived(&live)?;
        let restored_at = archive.now_recorded_at();
        drop(archive);
        // Reopened, it reads what it holds under its own custody.
        let vault = Self::open_owned(path, config)?;
        Ok(RestoreReport {
            epoch: RestoreEpoch {
                checkpoint_id: String::new(),
                restored_at,
                reason: RestoreReason::Activate,
            },
            rebuilt_entities: 0,
            rebuilt_text_documents: 0,
            pending_embeddings: 0,
            dropped_gate_decisions,
            custody_note: vault.activation_custody_note(),
            training_note: vault.training_link_restore_notice(),
            home_table_notes: Vec::new(),
            pad_notes: erased_pads.iter().map(PadRestoreNote::erased).collect(),
        })
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
        // The host's own home candidacy stays on this host: the replacement
        // re-elects over it, never over the image's.
        let candidacy = rebuild::host_candidacy(current);
        Self::restore_with_current_authority(
            path,
            key,
            staging,
            config,
            current,
            restored_at,
            Custody::Replace(current.store.env.path(), candidacy.as_deref()),
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
        // Every id `current` has hard-erased, those after the checkpoint
        // too: the restored rows must not name those actors (FIX 3655).
        let erased = crate::deletion::hard_erased_ids_in(current)?;
        let installed = current.installed_pack_sources()?;
        let (mut image, checkpoint_id, bodies) = read_image(path, key)?;
        // The carried rows hold `current`'s custody binding and retirements.
        let home_table_notes =
            authority_plane::carry_current_authority(&mut image.databases, current)?;
        // A Live family's response row came with it, and its binding: the
        // image's copy is passed over (KS-2B2).
        response_rows::supersede_live(&mut image, current)?;
        // And its host orders, which no image carries.
        host_holds::carry_current(&mut image.databases, current)?;
        // Two live vaults never answer as one machine (wp-keys I7).
        if let Custody::Fork(_) = custody {
            image.drop_machine_identity();
        }
        let (made, forked, mut vault, mut report) = Self::restore_image(
            image,
            checkpoint_id,
            bodies,
            destination,
            config,
            RestoreReason::Restore,
            restored_at,
            custody,
            &erased,
            &write_budget::Unfloored,
        )?;
        // A home table whose live rows did not read came from the image.
        report.home_table_notes = home_table_notes;
        // A live install the image does not hold halts its routes (FIX 6034).
        vault.halt_departed_pack_routes(&installed, restored_at)?;
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

/// The sequence of the latest restore, wake or migrate epoch `txn` reads, none before
/// the first: a reader's position that must not outlive a restore is bound to it
/// (FIX 1585).
pub(crate) fn latest_restore_epoch_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<u64>> {
    match RESTORE_EPOCH.iter_rev_from(&vault.store, txn, &[])?.next() {
        Some(row) => Ok(Some(row?.0)),
        None => Ok(None),
    }
}
#[cfg(test)]
mod test_hooks;
#[cfg(test)]
use test_hooks::panic_if_armed;

#[cfg(test)]
mod tests;
