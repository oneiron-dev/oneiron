//! The backup watermark: where a vault stood when a backup was taken, and
//! where it stands now, so a host backs up only what changed (LC backup
//! shipper rows, Engine 10-20; agreed with L14).
//!
//! A watermark is the store's backup incarnation, its last content commit's
//! LMDB transaction id, and its custody log's writer epoch and sequence. Any
//! content commit and any custody move changes it: a change is never missed,
//! and a commit that changes nothing a restore needs still reads as a change
//! (CALLS BACKUP_CHANGED_ANY_COMMIT), save the classed writes that say so: a
//! host's telemetry, and the backup's own incarnation and chain advance
//! (FIX 6730, `store::backup_change`). The selection is also part of the mark:
//! an automatic copy never certifies a whole-vault request. Hosts use equality
//! for the same selection or [`BackupWatermark::covers`] when a whole-vault
//! artifact may also satisfy an automatic backup duty.
//!
//! The incarnation is 16 random bytes kept in a Runtime-tier row
//! ([`side_table::BACKUP_INCARNATION`]): minted at a store's first backup,
//! carried by no image, so a restored or recreated store, whose transaction
//! ids start again, never compares equal to an older one. Until it is minted
//! [`Vault::backup_watermark`] is a typed error, which reads as changed.
//!
//! A backup's receipt says what it covered, read in its own snapshot: the
//! last content commit its read transaction sees and the custody position
//! under the same guard. Its own chain advance changes no content, so it
//! leaves that mark where it was; content another write commits in between
//! still reads as a change.
//!
//! The host records what its newest backup covered in a marker file beside
//! it, `.<label>.backup-watermark.json`, once the artifact's rename and
//! directory sync are done ([`BackupSnapshotReceipt::persist_marker`]); no
//! LMDB write, so recording it changes nothing. A marker that failed to land
//! leaves the one before, and a missing or bad one reads as changed
//! ([`last_backed_up`]); every reader takes it through one strict read
//! (`marker`, FIX 6777).

mod marker;

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oneiron_crypto::backup::CheckpointSigner;
pub use oneiron_crypto::backup::{inspect_backup, verify_with_pins};
use oneiron_vault_contract::backup_handoff::write_private_file;
use serde::{Deserialize, Serialize};

use crate::side_table::{self, Named, SideTable};
use crate::store::{BackupWriteClass, Callback, Rows};
use crate::{Error, Result, Vault};

/// The store's backup incarnation. Key: ().
const INCARNATION: SideTable<(), [u8; 16], Named> = SideTable::new(&side_table::BACKUP_INCARNATION);

/// The evidence of one written backup artifact: the shared inspector's type
/// (`oneiron_crypto::backup`), built by the writer from what it wrote.
pub type BackupArtifactEvidence = oneiron_crypto::backup::BackupEvidence;

/// Which rows a backup snapshot was asked to select.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupSelection {
    /// The existing whole-vault canonical snapshot, including private worlds.
    WholeVault,
    /// An automatic copy selected by the worlds' sealed-copy settings.
    Automatic,
}

/// Where a vault stood for whether it changed since a backup. Two compare
/// equal only when their selections match, no content was committed and custody
/// did not move between them, within one store incarnation. Fixed-size; its fields
/// are read-only.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupWatermark {
    #[serde(with = "hex16")]
    incarnation: [u8; 16],
    db_txn: u64,
    custody_epoch: u64,
    custody_seq: u64,
    selection: BackupSelection,
}

impl BackupWatermark {
    /// The store's backup incarnation.
    pub fn incarnation(&self) -> [u8; 16] {
        self.incarnation
    }

    /// The LMDB transaction id of the last content commit it covers.
    pub fn db_txn(&self) -> u64 {
        self.db_txn
    }

    /// The custody log's writer epoch it covers; 0 where the vault keeps no
    /// custody log.
    pub fn custody_epoch(&self) -> u64 {
        self.custody_epoch
    }

    /// The custody log's sequence it covers; 0 where the vault keeps no
    /// custody log.
    pub fn custody_seq(&self) -> u64 {
        self.custody_seq
    }

    /// The selection whose snapshot this mark describes.
    pub fn selection(&self) -> BackupSelection {
        self.selection
    }

    /// Whether this snapshot covers the requested selection at exactly the same
    /// content and custody position. A whole-vault snapshot also covers an
    /// automatic selection, never the other way around.
    pub fn covers(&self, requested: &Self) -> bool {
        self.incarnation == requested.incarnation
            && self.db_txn == requested.db_txn
            && self.custody_epoch == requested.custody_epoch
            && self.custody_seq == requested.custody_seq
            && (self.selection == requested.selection
                || matches!(
                    (self.selection, requested.selection),
                    (BackupSelection::WholeVault, BackupSelection::Automatic)
                ))
    }
}

impl fmt::Debug for BackupWatermark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackupWatermark")
            .field(
                "incarnation",
                &format_args!("{}", hex16::encode(&self.incarnation)),
            )
            .field("db_txn", &self.db_txn)
            .field("custody_epoch", &self.custody_epoch)
            .field("custody_seq", &self.custody_seq)
            .field("selection", &self.selection)
            .finish()
    }
}

/// What one backup snapshot wrote and covered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupSnapshotReceipt {
    /// BLAKE3 of the image, hex: the checkpoint id.
    pub image_digest: String,
    /// The content and custody position the snapshot read for its selection,
    /// its own chain advance excluded. An automatic selection is not a
    /// whole-vault coverage promise.
    pub covered: BackupWatermark,
    /// The written artifact's evidence.
    pub evidence: BackupArtifactEvidence,
    /// The artifact's checkpoint fact (FIX 7326), signed with the keys that
    /// signed its commitment, for its host to publish beside it: `None` for
    /// a checkpoint, which publishes none, or where signing it failed, which
    /// was logged and leaves the backup without one.
    pub checkpoint_fact: Option<oneiron_crypto::backup::SignedCheckpointFact>,
    /// What the artifact carries of the vault's host-order legal holds
    /// (FIX 6598): none for a self-hosted vault; for a hosted one, the
    /// sealed member's recipient and BLAKE3, or why it carries none, for its
    /// host to alert on.
    pub host_holds: super::HostHoldsAvailability,
    /// The pad rows the image carries with their pad, which current custody
    /// did not hold the same when it was taken (KS-5, FIX 7313): each pad
    /// rides these bytes past its custody entry's retirement. Zero once
    /// every pad was prepared into custody and the image names it by
    /// reference alone.
    pub pads_carried: usize,
    /// The families whose rows the image keeps under its vault-wide seal,
    /// with how many rows each (KS-7, CALLS PAYLOAD_UNCLASSIFIED): not
    /// compartmented, so an erase can't reach them in this checkpoint. Empty
    /// for an image taken with no payload section.
    pub not_compartmented: BTreeMap<String, u64>,
    /// Each gap in the checkpoint payload registry the capture rode past
    /// (KS7-6), one line each naming the family by its name, database and
    /// prefix, or the database or entity kind, and what became of its rows.
    /// Empty when the registry is whole.
    pub payload_registry_gaps: Vec<String>,
}

/// The suffix of the marker beside a label's newest backup:
/// `.<label>.backup-watermark.json`.
pub const BACKUP_WATERMARK_MARKER_SUFFIX: &str = ".backup-watermark.json";
const MARKER_SCHEMA_VERSION: u32 = 2;

/// What a label's newest backup covered, as its host recorded it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatermarkMarker {
    schema_version: u32,
    /// The backup's file name in its directory.
    file: String,
    covered: BackupWatermark,
    /// The image's BLAKE3, hex.
    image_digest: String,
    /// The artifact's commitment digest, hex.
    commitment_digest: String,
    /// BLAKE3 of the artifact's every byte, hex.
    outer_blake3: String,
    size: u64,
}

fn marker_name(label: &str) -> String {
    format!(".{label}{BACKUP_WATERMARK_MARKER_SUFFIX}")
}

impl BackupSnapshotReceipt {
    /// Records what this backup covered beside it: `file`, landed in `dir`
    /// under `label`, its marker written to a private temporary sibling,
    /// synced, renamed over the label's marker and `dir` synced. Call it once
    /// the artifact's own rename and directory sync are done. A marker that
    /// fails leaves the one before it, which only reads as changed.
    pub fn persist_marker(&self, dir: &Path, label: &str, file: &str) -> Result<()> {
        let marker = WatermarkMarker {
            schema_version: MARKER_SCHEMA_VERSION,
            file: file.to_owned(),
            covered: self.covered,
            image_digest: self.image_digest.clone(),
            commitment_digest: oneiron_vault_contract::hex(&self.evidence.commitment_digest),
            outer_blake3: oneiron_vault_contract::hex(&self.evidence.outer_blake3),
            size: self.evidence.size,
        };
        let bytes = serde_json::to_vec_pretty(&marker)
            .map_err(|_| Error::CorruptedIndex("backup watermark marker"))?;
        write_private_file(dir, &marker_name(label), &bytes)?;
        Ok(())
    }
}

/// What the newest backup of `label` in `dir` covered, from its marker:
/// `None`, read as changed, when the marker is missing, is not a private file
/// of this user, does not parse, does not name a backup of `label` by its
/// current file name, or names one that is no longer there as it recorded it
/// (its size and the commitment its head and tail carry, FIX 6777).
pub fn last_backed_up(dir: &Path, label: &str) -> Option<BackupWatermark> {
    marker::read_bound_marker(dir, label).map(|marker| marker.covered)
}

/// A label's backup marker read whole (L14 B2, agreed with L04): the backup
/// it names, what that backup covered, its artifact's commitment digest and
/// when the marker landed, which is when the backup was recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupMarker {
    file: String,
    covered: BackupWatermark,
    commitment_digest: String,
    outer_blake3: String,
    size: u64,
    landed_ms: u64,
}

impl BackupMarker {
    /// The backup's file name in its directory.
    pub fn file(&self) -> &str {
        &self.file
    }

    /// What the backup covered.
    pub fn covered(&self) -> BackupWatermark {
        self.covered
    }

    /// The backup artifact's commitment digest, as the marker records it in
    /// hex.
    pub fn commitment_digest(&self) -> &str {
        &self.commitment_digest
    }

    /// When the marker landed, in Unix milliseconds by the wall clock.
    pub fn landed_ms(&self) -> u64 {
        self.landed_ms
    }

    /// Whether the file in `dir` it names is still the backup it recorded:
    /// a regular file, never read through a symlink, whose evidence the
    /// shared inspector reads as the marker's commitment digest, BLAKE3 and
    /// size. It reads the whole file. Anything short of that is `false`,
    /// which reads as changed.
    pub fn held(&self, dir: &Path) -> bool {
        open_backup(&dir.join(&self.file))
            .is_some_and(|(file, metadata)| self.reads_as_recorded(&file, &metadata))
    }

    /// [`Self::held`], kept as a verdict that a later check asks in place of
    /// a second whole read (HELD-WHOLE-READ-OFF-PRE-IDLE): `None` when the
    /// file is not held, when its identity moved while it was read, and
    /// where the platform gives no file identity (only unix does) or no
    /// boot clock (time since boot, the time suspended included). The
    /// verdict is for this marker, so for the outer digest the read found
    /// every byte to match. Only this samples the file's identity, so
    /// [`Self::held`] makes the same calls it always made.
    pub fn verify(&self, dir: &Path) -> Option<HeldVerdict> {
        let started_boot = boot_clock()?;
        let started_ms = wall_clock_ms()?;
        let (file, metadata) = open_backup(&dir.join(&self.file))?;
        let identity = FileIdentity::of(&metadata)?;
        if !self.reads_as_recorded(&file, &metadata) {
            return None;
        }
        let after = file
            .metadata()
            .ok()
            .and_then(|metadata| FileIdentity::of(&metadata));
        (after == Some(identity)).then(|| HeldVerdict {
            marker: self.clone(),
            identity,
            started_boot,
            started_ms,
        })
    }

    /// Whether the open `file`, with its `metadata`, reads whole as the
    /// backup this marker recorded: a regular file of its size whose
    /// evidence is its commitment digest, BLAKE3 and size.
    fn reads_as_recorded(&self, file: &std::fs::File, metadata: &std::fs::Metadata) -> bool {
        metadata.is_file()
            && metadata.len() == self.size
            && inspect_backup(std::io::BufReader::new(file)).is_ok_and(|evidence| {
                evidence.size == self.size
                    && oneiron_vault_contract::hex(&evidence.commitment_digest)
                        == self.commitment_digest
                    && oneiron_vault_contract::hex(&evidence.outer_blake3) == self.outer_blake3
            })
    }
}

/// A whole read's finding that the file a marker names was, as read, the
/// backup it recorded (HELD-WHOLE-READ-OFF-PRE-IDLE): the marker it was read
/// for, the file's identity, the same at open and after the read, and when
/// the read began by the boot clock, which counts time suspended, and by the
/// wall clock. Only [`BackupMarker::verify`] makes one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldVerdict {
    marker: BackupMarker,
    identity: FileIdentity,
    started_boot: Duration,
    started_ms: u64,
}

impl HeldVerdict {
    /// The backup's file name in its directory.
    pub fn file(&self) -> &str {
        &self.marker.file
    }

    /// The backup artifact's commitment digest, in hex: the backup's id.
    pub fn commitment_digest(&self) -> &str {
        &self.marker.commitment_digest
    }

    /// BLAKE3 of the artifact's every byte, in hex: the outer digest the read
    /// found.
    pub fn outer_blake3(&self) -> &str {
        &self.marker.outer_blake3
    }

    /// When the read began, in Unix milliseconds by the wall clock.
    pub fn verified_at_ms(&self) -> u64 {
        self.started_ms
    }

    /// Whether it answers for `marker`'s backup in `dir` with no read of its
    /// bytes: it was made for that same marker, the file opens as it did, a
    /// regular file never reached through a symlink, with the identity the
    /// read saw, and then, once the file has answered, its read began less
    /// than `within` ago by the boot clock, so a suspend counts, and by the
    /// wall clock (a clock behind the read's start answers nothing). The age
    /// is read after the open and its stat, so a slow file system never
    /// carries a verdict past `within`. A change that keeps the file's
    /// identity is not seen here. Once `within` has passed since the read
    /// began, by either clock, it answers nothing, and a reuse reads the file
    /// whole.
    pub fn answers(&self, marker: &BackupMarker, dir: &Path, within: Duration) -> bool {
        self.marker == *marker
            && open_backup(&dir.join(&marker.file)).is_some_and(|(_, metadata)| {
                metadata.is_file() && FileIdentity::of(&metadata) == Some(self.identity)
            })
            && self.younger_than(within)
    }

    /// Whether its read began less than `within` ago by the boot clock and
    /// by the wall clock; `false` where either does not read or reads before
    /// the read's start.
    fn younger_than(&self, within: Duration) -> bool {
        let within_ms = u64::try_from(within.as_millis()).unwrap_or(u64::MAX);
        boot_clock()
            .and_then(|now| now.checked_sub(self.started_boot))
            .is_some_and(|age| age < within)
            && wall_clock_ms()
                .and_then(|now| now.checked_sub(self.started_ms))
                .is_some_and(|age| age < within_ms)
    }
}

/// A file's identity as a verdict keeps it: device, inode, size, and
/// modification and status-change times to the nanosecond.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(unix), allow(dead_code))]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl FileIdentity {
    #[cfg(unix)]
    fn of(metadata: &std::fs::Metadata) -> Option<Self> {
        use std::os::unix::fs::MetadataExt;
        Some(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }

    #[cfg(not(unix))]
    fn of(_: &std::fs::Metadata) -> Option<Self> {
        None
    }
}

/// Opens the backup at `path` for reading, never through a symlink and
/// never waiting on a FIFO, with its metadata from the open file.
fn open_backup(path: &Path) -> Option<(std::fs::File, std::fs::Metadata)> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(
        &mut options,
        libc::O_NOFOLLOW | libc::O_NONBLOCK,
    );
    let file = options.open(path).ok()?;
    let metadata = file.metadata().ok()?;
    Some((file, metadata))
}

/// Now in Unix milliseconds by the wall clock; `None` before the epoch.
fn wall_clock_ms() -> Option<u64> {
    let since = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    Some(u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
}

/// Time since boot, the time suspended included: `CLOCK_BOOTTIME` on Linux
/// and Android, and `CLOCK_MONOTONIC` on Apple systems, which counts sleep.
/// [`std::time::Instant`] leaves a suspend out on both, so a verdict aged by
/// it alone would outlive its window across a suspend once the wall clock
/// was set back. `None` on every other platform, where no verdict is made.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn boot_clock() -> Option<Duration> {
    use rustix::time::{ClockId, clock_gettime};
    Duration::try_from(clock_gettime(ClockId::Boottime)).ok()
}

#[cfg(target_vendor = "apple")]
fn boot_clock() -> Option<Duration> {
    use rustix::time::{ClockId, clock_gettime};
    Duration::try_from(clock_gettime(ClockId::Monotonic)).ok()
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn boot_clock() -> Option<Duration> {
    None
}

/// [`last_backed_up`] whole: the backup the marker names and when it landed
/// as well as what it covered. `None` as there, and when the marker's time
/// does not read.
pub fn backup_marker(dir: &Path, label: &str) -> Option<BackupMarker> {
    backup_marker_with_pins(dir, label, None)
}

/// [`backup_marker`], and when `pins` are given, `None` too for a backup
/// whose commitment none of them signed (FIX 10712). It checks the signer of
/// the backup's tail; [`BackupMarker::held`] stays the strong check.
pub fn backup_marker_with_pins(
    dir: &Path,
    label: &str,
    pins: Option<&[CheckpointSigner]>,
) -> Option<BackupMarker> {
    let marker = marker::read_bound_marker_with_pins(dir, label, pins)?;
    let landed = std::fs::symlink_metadata(dir.join(marker_name(label)))
        .and_then(|metadata| std::fs::Metadata::modified(&metadata))
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    Some(BackupMarker {
        file: marker.file,
        covered: marker.covered,
        commitment_digest: marker.commitment_digest,
        outer_blake3: marker.outer_blake3,
        size: marker.size,
        landed_ms: u64::try_from(landed.as_millis()).unwrap_or(u64::MAX),
    })
}

/// What a snapshot read under its custody guard, before its own write.
pub(super) struct SnapshotMark {
    incarnation: [u8; 16],
    snapshot_txn: u64,
    custody_epoch: u64,
    custody_seq: u64,
}

impl SnapshotMark {
    /// The mark of the snapshot `txn`, read under the custody guard the
    /// snapshot holds.
    pub(super) fn read(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Self> {
        let incarnation = INCARNATION
            .get(&vault.store, txn, &())?
            .ok_or_else(unminted)?;
        let (custody_epoch, custody_seq) = vault.store.custody_log_mark()?;
        Ok(Self {
            incarnation,
            snapshot_txn: crate::store::backup_content_txn_in_txn(&vault.store, txn)?,
            custody_epoch,
            custody_seq,
        })
    }

    /// What the backup covered: the content its snapshot saw. Its own chain
    /// advance, backup metadata, leaves that mark as it was (FIX 6730).
    pub(super) fn covered(&self, selection: BackupSelection) -> BackupWatermark {
        BackupWatermark {
            incarnation: self.incarnation,
            db_txn: self.snapshot_txn,
            custody_epoch: self.custody_epoch,
            custody_seq: self.custody_seq,
            selection,
        }
    }
}

fn unminted() -> Error {
    Error::InvalidConfig(
        "this vault has no backup watermark until its first backup: read it as changed".into(),
    )
}

impl Vault {
    /// Where this vault stands now, for whether it changed since a backup's
    /// [`BackupSnapshotReceipt::covered`]: its backup incarnation, last
    /// content commit's transaction id and custody log position, read under the
    /// custody guard. Cheap and independent of the vault's size: no write,
    /// no walk. A store with no incarnation yet (none backed up, or a
    /// restored one) or one that does not read is an error, never unchanged.
    pub fn backup_watermark(&self) -> Result<BackupWatermark> {
        self.backup_watermark_for(BackupSelection::WholeVault)
    }

    /// Where this vault stands for its automatic backup selection. This mark
    /// cannot certify a whole-vault backup, even when the selection omits nothing.
    pub fn automatic_backup_watermark(&self) -> Result<BackupWatermark> {
        self.backup_watermark_for(BackupSelection::Automatic)
    }

    fn backup_watermark_for(&self, selection: BackupSelection) -> Result<BackupWatermark> {
        let _custody = self.store.gate_custody_read_guard()?;
        let txn = self.store.env.read_txn()?;
        Ok(SnapshotMark::read(self, &txn)?.covered(selection))
    }

    /// Mints this store's backup incarnation when it has none, in a write of
    /// its own, before a snapshot reads it.
    pub(super) fn mint_backup_incarnation(&self) -> Result<()> {
        if INCARNATION
            .get(&self.store, &self.store.env.read_txn()?, &())?
            .is_some()
        {
            return Ok(());
        }
        let mut fresh = [0u8; 16];
        crate::world_keys::os_fill(&mut fresh)?;
        let class = BackupWriteClass::BackupMetadata;
        self.store
            .group_write_classed(Callback::Opaque, class, |txn| {
                let held = match INCARNATION.get(&self.store, txn, &()) {
                    Ok(held) => held,
                    Err(error) => return Rows::Discard(Err(error)),
                };
                if held.is_some() {
                    return Rows::Discard(Ok(()));
                }
                match INCARNATION.put(&self.store, txn, &(), &fresh) {
                    Ok(()) => Rows::Commit(()),
                    Err(error) => Rows::Discard(Err(error)),
                }
            })
    }
}

/// The incarnation as 32 hex digits in a host's journal.
mod hex16 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn encode(bytes: &[u8; 16]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    pub(super) fn serialize<S: Serializer>(
        bytes: &[u8; 16],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 16], D::Error> {
        let text = String::deserialize(deserializer)?;
        let malformed = || serde::de::Error::custom("an incarnation is 32 hex digits");
        if text.len() != 32 || !text.is_ascii() {
            return Err(malformed());
        }
        let mut out = [0u8; 16];
        for (byte, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
            let pair = std::str::from_utf8(pair).map_err(|_| malformed())?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| malformed())?;
        }
        Ok(out)
    }
}
