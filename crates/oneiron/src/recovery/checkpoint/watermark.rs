//! The backup watermark: where a vault stood when a backup was taken, and
//! where it stands now, so a host backs up only what changed (LC backup
//! shipper rows, Engine 10-20; agreed with L14).
//!
//! A watermark is the store's backup incarnation, its last committed LMDB
//! transaction id, and its custody log's writer epoch and sequence. Any LMDB
//! commit and any custody move changes it: a change is never missed, and a
//! commit that changes nothing a restore needs still reads as a change
//! (CALLS BACKUP_CHANGED_ANY_COMMIT). Hosts compare two for equality only.
//!
//! The incarnation is 16 random bytes kept in a Runtime-tier row
//! ([`side_table::BACKUP_INCARNATION`]): minted at a store's first backup,
//! carried by no image, so a restored or recreated store, whose transaction
//! ids start again, never compares equal to an older one. Until it is minted
//! [`Vault::backup_watermark`] is a typed error, which reads as changed.
//!
//! A backup's receipt says what it covered, read in its own snapshot: the
//! snapshot's read transaction and the custody position under the same
//! guard. The backup's own chain advance, a write of its own carrying
//! nothing else, is excluded by the baseline rule: covered is that write's id
//! when it directly follows the snapshot, else the snapshot's.
//!
//! The host records what its newest backup covered in a marker file beside
//! it, `.<label>.backup-watermark.json`, once the artifact's rename and
//! directory sync are done ([`BackupSnapshotReceipt::persist_marker`]); no
//! LMDB write, so recording it changes nothing. A marker that failed to land
//! leaves the one before, and a missing or bad one reads as changed
//! ([`last_backed_up`]).

use std::fmt;
use std::path::Path;

pub use oneiron_crypto::backup::{inspect_backup, verify_with_pins};
use oneiron_vault_contract::backup_handoff::{PrivateFile, read_private_file, write_private_file};
use serde::{Deserialize, Serialize};

use crate::side_table::{self, Named, SideTable};
use crate::store::{Callback, Rows};
use crate::{Error, Result, Vault};

/// The store's backup incarnation. Key: ().
const INCARNATION: SideTable<(), [u8; 16], Named> = SideTable::new(&side_table::BACKUP_INCARNATION);

/// The evidence of one written backup artifact: the shared inspector's type
/// (`oneiron_crypto::backup`), built by the writer from what it wrote.
pub type BackupArtifactEvidence = oneiron_crypto::backup::BackupEvidence;

/// Where a vault stood for whether it changed since a backup. Two compare
/// equal only when nothing was committed and custody did not move between
/// them, within one store incarnation. Fixed-size; its fields are read-only.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupWatermark {
    #[serde(with = "hex16")]
    incarnation: [u8; 16],
    db_txn: u64,
    custody_epoch: u64,
    custody_seq: u64,
}

impl BackupWatermark {
    /// The store's backup incarnation.
    pub fn incarnation(&self) -> [u8; 16] {
        self.incarnation
    }

    /// The last committed LMDB transaction id it covers.
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
            .finish()
    }
}

/// What one backup snapshot wrote and covered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupSnapshotReceipt {
    /// BLAKE3 of the image, hex: the checkpoint id.
    pub image_digest: String,
    /// The vault as the snapshot read it, its own chain advance excluded.
    pub covered: BackupWatermark,
    /// The written artifact's evidence.
    pub evidence: BackupArtifactEvidence,
}

/// The suffix of the marker beside a label's newest backup:
/// `.<label>.backup-watermark.json`.
pub const BACKUP_WATERMARK_MARKER_SUFFIX: &str = ".backup-watermark.json";
const MARKER_SCHEMA_VERSION: u32 = 1;

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
/// of this user, does not parse, or names a backup no longer there.
pub fn last_backed_up(dir: &Path, label: &str) -> Option<BackupWatermark> {
    let Ok(PrivateFile::Bytes(bytes)) = read_private_file(&dir.join(marker_name(label))) else {
        return None;
    };
    let marker: WatermarkMarker = serde_json::from_slice(&bytes).ok()?;
    let plain = !marker.file.is_empty()
        && !marker.file.starts_with('.')
        && !marker.file.contains(['/', '\\', '\0']);
    (marker.schema_version == MARKER_SCHEMA_VERSION && plain && dir.join(&marker.file).is_file())
        .then_some(marker.covered)
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
            snapshot_txn: txn.id() as u64,
            custody_epoch,
            custody_seq,
        })
    }

    /// What the backup covered, its own chain advance committed as `own`:
    /// that write when it directly follows the snapshot, else the snapshot.
    pub(super) fn covered(&self, own: u64) -> BackupWatermark {
        let db_txn = if Some(own) == self.snapshot_txn.checked_add(1) {
            own
        } else {
            self.snapshot_txn
        };
        BackupWatermark {
            incarnation: self.incarnation,
            db_txn,
            custody_epoch: self.custody_epoch,
            custody_seq: self.custody_seq,
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
    /// committed transaction id and custody log position, read under the
    /// custody guard. Cheap and independent of the vault's size: no write,
    /// no walk. A store with no incarnation yet (none backed up, or a
    /// restored one) or one that does not read is an error, never unchanged.
    pub fn backup_watermark(&self) -> Result<BackupWatermark> {
        let _custody = self.store.gate_custody_read_guard()?;
        let txn = self.store.env.read_txn()?;
        let mark = SnapshotMark::read(self, &txn)?;
        Ok(BackupWatermark {
            incarnation: mark.incarnation,
            db_txn: mark.snapshot_txn,
            custody_epoch: mark.custody_epoch,
            custody_seq: mark.custody_seq,
        })
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
        self.store.group_write_as(Callback::Opaque, None, |txn| {
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
