//! The residence home's side of the residence target (KS-4A2, FIX 5685).
//!
//! A machine of the owner's ships its custody to its residence home: the
//! frames first, then its sealed head in parts into a stage, then a commit.
//! The home keeps it beside its own vault in `.<vault>.custody-residence/`,
//! outside its image and outside its own key custody, in the folder layout
//! (`oneiron-custody/<namespace hex>.<vault hex>/{head, log/f<seq>}`), so no
//! home image or backup ever holds a frozen head. The commit checks the
//! staged bytes against the head object id and position the machine named,
//! refuses to replace a newer position (another writer moved it, or a newer
//! commit: one commit of a lineage at a time, FIX 6394), switches the head
//! in one rename, removes every superseded head, temporary and stale stage
//! (a newer upload's stage stays, and no frame or part lands while the
//! commit holds the lineage, FIX 6415), lists the directory again, and
//! persists its ack under
//! `acks/<namespace hex>.<vault hex>` before it replies. A commit retried
//! after a lost reply answers the ack it already gave. Nothing here reads a
//! key: heads and frames are sealed bytes the home cannot open.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;

use super::anchor::extends;
use super::files::{open_dir, read_whole, replace_file};
use super::folder::{FolderTarget, STAGE_PREFIX, held_position, ship_frame, switch_head};
use super::head::head_position;
use super::log::CustodyPosition;
use super::platform;
use super::protocol::{
    ACK_VERSION, AckOperation, AckPosition, AckRecord, DeletionEvidence, DrainAck, DrainTicket,
    EvidenceKind, Lineage, ResidenceCommit, TargetSpec, hex, operation_id,
};

const HOME: &str = "custody-residence";
const ACKS: &str = "acks";

fn refused(reason: &str) -> Error {
    Error::InvalidConfig(format!(
        "the residence home refused the custody upload: {reason}"
    ))
}

fn lineage_name(lineage: Lineage) -> String {
    format!(
        "{}.{}",
        hex(lineage.namespace.as_bytes()),
        hex(lineage.vault.as_bytes())
    )
}

impl Store {
    /// `.<vault>.custody-residence/` beside this vault, made owner-only.
    fn residence_home(&self) -> Result<PathBuf> {
        let root = self.core.key_custody.home();
        let mut name = OsString::from(".");
        name.push(
            root.file_name()
                .ok_or_else(|| refused("the home has no vault name"))?,
        );
        name.push(".");
        name.push(HOME);
        let dir = root.with_file_name(name);
        open_dir(&dir, true, None)?;
        Ok(dir)
    }

    /// Holds the lock of `lineage` in the home `root` for the life of the
    /// returned file: one commit of the lineage at a time (FIX 6394), and no
    /// frame or stage part lands while a commit sweeps the lineage (FIX
    /// 6415).
    fn lineage_lock(root: &Path, lineage: Lineage) -> Result<File> {
        let acks = root.join(ACKS);
        open_dir(&acks, true, None)?;
        platform::lock_at(&acks.join(format!("{}.lock", lineage_name(lineage))))
    }

    /// The position of the head this home holds of `lineage`, read from its
    /// public structure only.
    pub(crate) fn residence_custody_held(
        &self,
        lineage: Lineage,
    ) -> Result<Option<CustodyPosition>> {
        Ok(held_position(
            &FolderTarget::at(self.residence_home()?).dir(lineage),
        ))
    }

    /// Ships one log frame of `lineage` here.
    pub(crate) fn residence_custody_frame(
        &self,
        lineage: Lineage,
        seq: u64,
        frame: &[u8],
    ) -> Result<()> {
        let root = self.residence_home()?;
        let _lock = Self::lineage_lock(&root, lineage)?;
        let dir = FolderTarget::at(root).open_lineage(lineage)?;
        ship_frame(&dir, seq, frame)
    }

    /// Appends one part of the head the operation `operation` stages, at
    /// `offset`. A part sent again after a lost reply is taken when its bytes
    /// are already there. Returns the stage's length.
    pub(crate) fn residence_custody_stage(
        &self,
        lineage: Lineage,
        operation: [u8; 32],
        offset: u64,
        part: &[u8],
    ) -> Result<u64> {
        let root = self.residence_home()?;
        let _lock = Self::lineage_lock(&root, lineage)?;
        let dir = FolderTarget::at(root).open_lineage(lineage)?;
        let path = dir.join(format!("{STAGE_PREFIX}{}", hex(&operation)));
        let mut options = OpenOptions::new();
        options.read(true).append(true).create(true);
        let mut stage = super::platform::secure(&mut options).open(&path)?;
        let length = stage.metadata()?.len();
        let part_len =
            u64::try_from(part.len()).map_err(|_| refused("a part too long to count"))?;
        let end = offset
            .checked_add(part_len)
            .ok_or_else(|| refused("a part past the end of any stage"))?;
        if offset == length {
            stage.write_all(part)?;
            stage.sync_all()?;
            return Ok(end);
        }
        if end <= length {
            let mut held = vec![0; part.len()];
            stage.seek(SeekFrom::Start(offset))?;
            stage.read_exact(&mut held)?;
            if held == part {
                return Ok(length);
            }
        }
        Err(refused("a part at another offset than the stage's end"))
    }

    /// Commits the staged head of `commit`: checked, switched, superseded
    /// heads and stages removed, listed again, and the ack persisted before
    /// it is returned. `home` is this home's machine id: the ack names the
    /// target `residence:<home hex>` and attests as `home`.
    pub(crate) fn residence_custody_commit(
        &self,
        commit: &ResidenceCommit,
        home: EntityId,
    ) -> Result<AckRecord> {
        let attester = home.to_hex();
        let target = TargetSpec::residence(home).id().as_str().to_owned();
        let lineage = Lineage::of(&commit.position);
        let root = self.residence_home()?;
        // One commit of the lineage at a time, from the ack check through the
        // head switch and the ack it persists: an older commit never renames
        // its head over a newer one (FIX 6394).
        let _lock = Self::lineage_lock(&root, lineage)?;
        let acks = root.join(ACKS);
        let ack_name = lineage_name(lineage);
        let operation = hex(&commit.operation_id);
        if let Some(bytes) = read_whole(&acks.join(&ack_name))? {
            let given: AckRecord =
                rmp_serde::from_slice(&bytes).map_err(|_| refused("its ack does not decode"))?;
            if given.operation_id == operation && given.target_id == target {
                return Ok(given);
            }
        }
        let dir = FolderTarget::at(root).open_lineage(lineage)?;
        let staged = dir.join(format!("{STAGE_PREFIX}{operation}"));
        let head =
            read_whole(&staged)?.ok_or_else(|| refused("nothing is staged for this operation"))?;
        let head_object_id = *blake3::hash(&head).as_bytes();
        if head_object_id != commit.head_object_id
            || head_position(&head)? != commit.position
            || operation_id(&commit.position, &head_object_id) != commit.operation_id
        {
            return Err(refused("the staged head is not the one the commit names"));
        }
        let held = held_position(&dir);
        if held.is_some_and(|held| !extends(&held, &commit.position)) {
            return Err(refused("a newer custody head is already here"));
        }
        let evidence = switch_head(&dir, &head, held.is_some(), EvidenceKind::ResidenceSweep)?;
        let ack = AckRecord {
            version: ACK_VERSION,
            target_id: target,
            set_revision: commit.set_revision,
            position: AckPosition::of(&commit.position),
            head_object_id: hex(&head_object_id),
            operation: AckOperation::PublishAndDeleteSuperseded,
            operation_id: operation,
            evidence,
            attester,
            acked_at: crate::unix_seconds_now(),
        };
        let encoded =
            rmp_serde::to_vec_named(&ack).map_err(|_| refused("its ack does not encode"))?;
        replace_file(&acks, &ack_name, &encoded)?;
        Ok(ack)
    }

    /// Drains the lineage `ticket` names for the owner's drain (FIX 5843):
    /// its head, every stage and every temporary go, synced, and a fresh
    /// listing counts the heads left. The keyless log stays. Returns this
    /// member's sweep ack as `residence:<home hex>`. A lineage with nothing
    /// stored drains to the same ack.
    pub(crate) fn residence_custody_drain(
        &self,
        ticket: &DrainTicket,
        home: EntityId,
    ) -> Result<DrainAck> {
        let lineage = Lineage::of(&ticket.position);
        let root = self.residence_home()?;
        // The commit's own lineage lock: no frame or part lands while the
        // drain sweeps (FIX 6415).
        let _lock = Self::lineage_lock(&root, lineage)?;
        let dir = FolderTarget::at(root).dir(lineage);
        let mut removed = 0_u64;
        if dir.is_dir() {
            // Every stage and temporary, as the folder drain sweeps them.
            for entry in std::fs::read_dir(&dir)? {
                let entry = entry?;
                let name = entry.file_name();
                let Some(text) = name.to_str() else {
                    continue;
                };
                let stage = text.starts_with(STAGE_PREFIX);
                if !stage && !(text.starts_with(".t") && text.ends_with(".pending")) {
                    continue;
                }
                match std::fs::remove_file(entry.path()) {
                    Ok(()) => removed = removed.saturating_add(1),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(err) => return Err(err.into()),
                }
            }
            platform::sync_dir(&dir)?;
            match std::fs::remove_file(dir.join("head")) {
                Ok(()) => removed = removed.saturating_add(1),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
            platform::sync_dir(&dir)?;
        }
        let mut names: Vec<std::ffi::OsString> = match std::fs::read_dir(&dir) {
            Ok(entries) => entries
                .map(|entry| entry.map(|entry| entry.file_name()))
                .collect::<std::io::Result<_>>()?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(err) => return Err(err.into()),
        };
        names.sort();
        let mut inventory = blake3::Hasher::new();
        let mut heads = 0_u64;
        for name in &names {
            let text = name.to_string_lossy();
            if text == "head" || text.starts_with(STAGE_PREFIX) || text.starts_with(".t") {
                heads = heads.saturating_add(1);
            }
            inventory.update(&(text.len() as u64).to_be_bytes());
            inventory.update(text.as_bytes());
        }
        ticket.ack(
            &TargetSpec::residence(home),
            DeletionEvidence {
                kind: EvidenceKind::ResidenceSweep,
                superseded_removed: removed,
                remaining_heads: heads,
                inventory_digest: hex(inventory.finalize().as_bytes()),
            },
        )
    }
}
