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
//! in one rename, removes every superseded head, temporary and stale stage,
//! lists the directory again, and persists its ack under
//! `acks/<namespace hex>.<vault hex>` before it replies. A commit retried
//! after a lost reply answers the ack it already gave. Nothing here reads a
//! key: heads and frames are sealed bytes the home cannot open.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

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
    ACK_VERSION, AckOperation, AckPosition, AckRecord, EvidenceKind, Lineage, ResidenceCommit,
    TargetSpec, hex, operation_id,
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
        let dir = FolderTarget::at(self.residence_home()?).open_lineage(lineage)?;
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
        let dir = FolderTarget::at(self.residence_home()?).open_lineage(lineage)?;
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
        let acks = root.join(ACKS);
        open_dir(&acks, true, None)?;
        let ack_name = lineage_name(lineage);
        // One commit of the lineage at a time, from the ack check through the
        // head switch and the ack it persists: an older commit never renames
        // its head over a newer one (FIX 6394).
        let _lock = platform::lock_at(&acks.join(format!("{ack_name}.lock")))?;
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
}
