//! The folder target (KS-4A1; acknowledgements KS-4A2, FIX 5685):
//! `<folder>/oneiron-custody/<namespace hex>.<vault hex>/` holding `head`
//! and `log/f<seq hex16>`, every directory owner-only. The residence home
//! keeps a device's custody in the same layout beside its own vault
//! (`sync::residence::custody`), so both delete and prove the same way.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

use super::anchor::extends;
use super::files::{open_dir, read_whole, replace_file, write_once};
use super::head::head_position;
use super::log::{CustodyPosition, FrameHeader, frame_name, log_corrupt};
use super::protocol::{
    CustodyBatch, CustodySource, CustodyTarget, DeletionEvidence, EvidenceKind, Lineage,
    PendingCode, TargetPending, TargetPublication, TargetSpec, hex,
};

const FOLDER: &str = "oneiron-custody";
const HEAD: &str = "head";
const LOG: &str = "log";
/// A staged head a residence upload is still writing, by its operation.
pub(super) const STAGE_PREFIX: &str = ".stage.";

/// Who attests a folder's ack: this install, which did the deletions.
pub(super) const THIS_INSTALL: &str = "this-install";

/// A folder target.
pub(crate) struct FolderTarget {
    folder: PathBuf,
    spec: TargetSpec,
    /// The floor its files claim their room on first: a backup's landing
    /// disk's (FIX 5858). `None` claims nothing.
    room: Option<Box<dyn crate::recovery::checkpoint::RecoveryWriteBudget>>,
}

impl FolderTarget {
    pub(crate) fn at(folder: PathBuf) -> Self {
        Self {
            spec: TargetSpec::folder(folder.clone()),
            folder,
            room: None,
        }
    }

    /// This target, its frames and head claimed on `room` before a byte of
    /// them is written: a claim the floor refuses leaves it pending by
    /// name, retried by the next pass, and refuses nothing else.
    pub(crate) fn claiming(
        mut self,
        room: Box<dyn crate::recovery::checkpoint::RecoveryWriteBudget>,
    ) -> Self {
        self.room = Some(room);
        self
    }

    /// The lineage's directory under this folder.
    pub(super) fn dir(&self, lineage: Lineage) -> PathBuf {
        self.folder.join(FOLDER).join(format!(
            "{}.{}",
            hex(lineage.namespace.as_bytes()),
            hex(lineage.vault.as_bytes())
        ))
    }

    /// Makes the lineage's directories, owner-only, and returns the
    /// lineage's.
    pub(super) fn open_lineage(&self, lineage: Lineage) -> Result<PathBuf> {
        let dir = self.dir(lineage);
        open_dir(&self.folder.join(FOLDER), true, None)?;
        open_dir(&dir, true, None)?;
        open_dir(&dir.join(LOG), true, None)?;
        Ok(dir)
    }
}

impl CustodySource for FolderTarget {
    fn head(&self, lineage: Lineage) -> Result<Option<Vec<u8>>> {
        read_whole(&self.dir(lineage).join(HEAD))
    }

    fn frame(&self, lineage: Lineage, seq: u64) -> Result<Option<Vec<u8>>> {
        read_whole(&self.dir(lineage).join(LOG).join(frame_name(seq)))
    }
}

impl CustodyTarget for FolderTarget {
    fn spec(&self) -> TargetSpec {
        self.spec.clone()
    }

    fn publish(&self, batch: &CustodyBatch) -> Result<TargetPublication> {
        let lineage = batch.lineage();
        let position = batch.position();
        let dir = match self.open_lineage(lineage) {
            Ok(dir) => dir,
            Err(error) => return Ok(unreachable(&error)),
        };
        let held = held_position(&dir);
        if held.is_some_and(|held| !extends(&held, &position)) {
            return Ok(moved());
        }
        let after = held
            .filter(|held| held.epoch == position.epoch)
            .map_or(0, |held| held.seq);
        let frames = batch.frames_after(after)?;
        if let Some(room) = &self.room {
            let bytes = frames
                .iter()
                .map(|(_, frame)| frame.len() as u64)
                .fold(batch.head().len() as u64, u64::saturating_add);
            if !room.hold(bytes) {
                return Ok(TargetPublication::Pending(TargetPending {
                    code: PendingCode::Denied,
                    detail: "the custody folder's disk is at the write floor its host keeps; the \
                             next pass retries"
                        .into(),
                }));
            }
        }
        for (seq, frame) in frames {
            ship_frame(&dir, seq, &frame)?;
        }
        let evidence = switch_head(
            &dir,
            batch.head(),
            held.is_some(),
            EvidenceKind::FilesystemSweep,
        )?;
        Ok(TargetPublication::Acked(batch.ack(
            self.spec.id(),
            evidence,
            THIS_INSTALL,
        )))
    }
}

/// A folder the pass cannot open: unmounted, removed, or not writable.
fn unreachable(error: &Error) -> TargetPublication {
    let code = match error {
        Error::Io(io) if io.kind() == std::io::ErrorKind::PermissionDenied => PendingCode::Locked,
        Error::Io(io) if io.kind() == std::io::ErrorKind::ReadOnlyFilesystem => PendingCode::Locked,
        _ => PendingCode::Offline,
    };
    TargetPublication::Pending(TargetPending {
        code,
        detail: "the custody folder is not reachable".into(),
    })
}

pub(super) fn moved() -> TargetPublication {
    TargetPublication::Pending(TargetPending {
        code: PendingCode::Moved,
        detail: "the target holds a newer custody head: another writer moved it".into(),
    })
}

/// The position of the head the lineage directory `dir` holds,
/// unauthenticated; `None` with none, or one that does not parse.
pub(super) fn held_position(dir: &Path) -> Option<CustodyPosition> {
    read_whole(&dir.join(HEAD))
        .ok()
        .flatten()
        .and_then(|head| head_position(&head).ok())
}

/// Ships one frame into the lineage directory `dir`. A frame already there
/// must be this one: the log is append-only. A frame of another lineage, or
/// at another number than its own, is refused.
pub(super) fn ship_frame(dir: &Path, seq: u64, frame: &[u8]) -> Result<()> {
    let (header, _): (FrameHeader, _) = FrameHeader::parse(frame)?;
    if header.seq != seq
        || !lineage_dir_names(dir, header.vault.as_bytes(), header.namespace.as_bytes())
    {
        return Err(log_corrupt());
    }
    let log = dir.join(LOG);
    let name = frame_name(seq);
    if !write_once(&log, &name, frame)? && read_whole(&log.join(&name))?.as_deref() != Some(frame) {
        return Err(log_corrupt());
    }
    Ok(())
}

/// Whether `dir` is the lineage directory of `vault` in `namespace`.
fn lineage_dir_names(dir: &Path, vault: &[u8; 32], namespace: &[u8; 16]) -> bool {
    dir.file_name().and_then(|name| name.to_str())
        == Some(format!("{}.{}", hex(namespace), hex(vault)).as_str())
}

/// Makes `head` the latest of the lineage directory `dir` in one rename,
/// then removes every superseded head, temporary and stale stage there and
/// in its log, syncs both, and lists the directory again: anything but the
/// head and the log left over is a refusal, never an ack. `replaced` says a
/// head was there before, which the rename superseded.
pub(super) fn switch_head(
    dir: &Path,
    head: &[u8],
    replaced: bool,
    kind: EvidenceKind,
) -> Result<DeletionEvidence> {
    replace_file(dir, HEAD, head)?;
    let removed = sweep(dir)? + sweep(&dir.join(LOG))?;
    let mut left = fs::read_dir(dir)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    left.sort();
    if left.iter().any(|name| name != HEAD && name != LOG) {
        return Err(Error::InvalidConfig(
            "a superseded custody head is still on the target".into(),
        ));
    }
    let mut inventory = blake3::Hasher::new();
    for name in &left {
        inventory.update(name.as_encoded_bytes());
        inventory.update(&[0]);
    }
    inventory.update(blake3::hash(head).as_bytes());
    Ok(DeletionEvidence {
        kind,
        superseded_removed: removed.saturating_add(u64::from(replaced)),
        remaining_heads: 1,
        inventory_digest: hex(inventory.finalize().as_bytes()),
    })
}

/// Removes every temporary an interrupted write left in `dir`, a head's
/// among them, and every stale staged head, and syncs it. Returns how many
/// it removed.
fn sweep(dir: &Path) -> Result<u64> {
    let mut removed = 0_u64;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_str().is_some_and(|name| {
            (name.starts_with(".t") && name.ends_with(".pending")) || name.starts_with(STAGE_PREFIX)
        }) {
            match fs::remove_file(entry.path()) {
                Ok(()) => removed = removed.saturating_add(1),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
        }
    }
    super::platform::sync_dir(dir)?;
    Ok(removed)
}
