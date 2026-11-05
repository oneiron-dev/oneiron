//! Core half of `origin::smart_http::hooks`: its store-layer items live in `oneiron_store::origin::smart_http::hooks` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::origin::smart_http::hooks::*;

use super::bounds::ScanBounds;
use super::paths::{
    DOOR_BLOB_TOO_LARGE, DOOR_DISK_FLOOR, DOOR_PRE_RECEIVE_HOOK_NAME, DOOR_WORK_HEARTBEAT_POLLS,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use std::fs;
use std::path::{Path, PathBuf};

/// One per-request directory that `core.hooksPath` points at.
///
/// It is created by the origin, holds exactly one vetted `pre-receive` script,
/// and is removed when the request ends. A repository can neither add to it nor
/// redirect away from it.
#[derive(Debug)]
pub struct DoorHooksDir {
    path: PathBuf,
}

impl DoorHooksDir {
    /// Materializes a fresh door-owned directory under `root`.
    pub fn materialize(root: &Path) -> Result<Self> {
        Self::materialize_with(root, ScanBounds::default())
    }

    /// Materializes the directory with the hook keeping `scan`'s bounds.
    pub(super) fn materialize_with(root: &Path, scan: ScanBounds) -> Result<Self> {
        Self::materialize_listing(root, scan, false)
    }

    /// [`Self::materialize_with`], the hook also listing each move's
    /// changed paths when `list_paths` (a checkout push, G1-PUSH).
    pub(super) fn materialize_listing(
        root: &Path,
        scan: ScanBounds,
        list_paths: bool,
    ) -> Result<Self> {
        let path = root.join(EntityId::now().to_hex());
        fs::create_dir_all(&path)?;
        let hook = path.join(DOOR_PRE_RECEIVE_HOOK_NAME);
        let script = DOOR_PRE_RECEIVE_HOOK
            .replace("@DOOR_SCAN_BLOB_BYTES@", &scan.blob_bytes().to_string())
            .replace(
                "@DOOR_SCAN_DISK_FLOOR_BYTES@",
                &scan.disk_floor_bytes().to_string(),
            )
            .replace("@DOOR_BLOB_TOO_LARGE@", DOOR_BLOB_TOO_LARGE)
            .replace("@DOOR_DISK_FLOOR@", DOOR_DISK_FLOOR)
            .replace(
                "@DOOR_WORK_HEARTBEAT_POLLS@",
                &DOOR_WORK_HEARTBEAT_POLLS.to_string(),
            )
            .replace(
                "@DOOR_LIST_CHANGED_PATHS@",
                if list_paths { "1" } else { "0" },
            );
        fs::write(&hook, script.as_bytes())?;
        set_executable(&hook)?;
        Ok(Self {
            path: path.canonicalize()?,
        })
    }

    /// The directory every serve invocation pins in argv.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn request_path(&self) -> PathBuf {
        self.path.join("pre-receive.request")
    }

    /// The length-framed blob stream the hook emits, moved into place before
    /// the request file it announces.
    pub(super) fn blobs_path(&self) -> PathBuf {
        self.path.join("pre-receive.blobs")
    }

    /// The framed history stream: the blobs the new tips reach that the tip
    /// diffs did not frame. Moved into place before the blob stream.
    pub(super) fn history_path(&self) -> PathBuf {
        self.path.join("pre-receive.history")
    }

    /// The changed-path stream of a checkout push, moved into place before
    /// the history stream.
    pub(super) fn paths_path(&self) -> PathBuf {
        self.path.join("pre-receive.paths")
    }

    pub(super) fn verdict_path(&self) -> PathBuf {
        self.path.join("pre-receive.verdict")
    }

    /// Publishes the verdict the blocked hook is waiting on. The write is
    /// rename-atomic, so the hook can never read half an answer.
    pub(super) fn publish_verdict(&self, verdict: &str) -> Result<()> {
        let staged = self.path.join("pre-receive.verdict.part");
        fs::write(&staged, verdict.as_bytes())?;
        fs::rename(&staged, self.verdict_path())?;
        Ok(())
    }
}

impl Drop for DoorHooksDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
