//! Codebase snapshot doors: ingest a pinned folder and read or project its snapshot.
//! `Memory::code_snapshot_ingest_as` is its call surface.
//! `memory::codebase_doors::types` defines the records these take and return.

use std::path::Path;

use sha2::{Digest, Sha256};

use super::*;
use crate::codebase::{
    CodebaseFileEntry, CodebaseSnapshot, RepoIngestConfig, RepoRef, snapshot_asset_entity_id,
    validate_project_id,
};
use crate::origin::secret_projection::reveal::RepoReadDoor;
use crate::temporal::TimeRange;

/// The CALL behind the import whitelist: this import claims no editable
/// policy, so the engine config it builds holds none. An empty list is no
/// write grant, and no caller list is accepted and then ignored.
const NO_EDITABLE_WHITELIST: [&str; 0] = [];

impl Memory<'_> {
    /// `vault.code.snapshots.ingest`: one committed tree imported through the
    /// unchanged engine importer, which reads the commit tree (never the dirty
    /// checkout), applies custody in its final writer and extracts Rust
    /// symbols. No repository is registered and no receipt is minted.
    pub fn code_snapshot_ingest_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeSnapshotIngestRequest,
    ) -> MemoryResult<CodeSnapshotView> {
        self.codebase_owner(owner)?;
        validate_project_id(&input.project_id)?;
        let folder = served_host_folder(&input.pointer.local_folder)?;
        let commit = pinned_commit(folder, &input.pointer.commit)?;
        let config = RepoIngestConfig::new(folder, NO_EDITABLE_WHITELIST)?;
        let (occurred, learned_at) = self.codebase_import_time();
        let imported = self.vault.ingest_local_repo_at_commit(
            input.project_id,
            &config,
            &commit,
            occurred,
            learned_at,
        )?;
        self.produced_from([imported.code_artifact_id]);
        Ok(snapshot_view(imported.code_artifact_id, &imported.snapshot))
    }

    /// `vault.code.snapshots.get`: the manifest of exactly the pinned
    /// snapshot. `None` when the artifact is absent or withheld.
    pub fn code_snapshot_get_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeSnapshotRequest,
    ) -> MemoryResult<Option<CodeSnapshotView>> {
        self.codebase_owner(owner)?;
        Ok(self
            .codebase_pinned(input.repo, &input.snapshot)?
            .map(|mount| snapshot_view(mount.code_artifact_id(), mount.snapshot())))
    }

    /// `vault.code.snapshots.read`: one file of the pinned snapshot, read
    /// from its stored blob through the mount, which withholds custody-lifted
    /// paths. The blob is admitted through this credential before any byte is
    /// projected. `None` when the file is absent, withheld or unreadable here;
    /// no read falls back to the folder on disk.
    pub fn code_snapshot_read_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeSnapshotReadRequest,
    ) -> MemoryResult<Option<CodeSnapshotPinnedFile>> {
        self.codebase_owner(owner)?;
        let Some(mount) = self.codebase_pinned(input.repo, &input.snapshot)? else {
            return Ok(None);
        };
        let Some(bytes) = mount.read_file(&input.path)? else {
            return Ok(None);
        };
        let Some(entry) = mount
            .snapshot()
            .files
            .iter()
            .find(|entry| entry.path == input.path)
        else {
            return Ok(None);
        };
        if !self.codebase_readable(snapshot_asset_entity_id(&entry.content_hash)?)? {
            return Ok(None);
        }
        let (content, text_sha256) = pinned_text(bytes)?;
        Ok(Some(CodeSnapshotPinnedFile {
            repo: input.repo,
            snapshot: input.snapshot,
            file: snapshot_file(entry),
            content,
            text_sha256,
        }))
    }

    /// [`Self::code_snapshot_get_as`] for a caller the host knows is a tool
    /// or a run (FIX 7608, ASK 1): the same owner proof and manifest, each
    /// marked file naming the copy a masked reader reads.
    pub fn code_snapshot_get_projected_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeSnapshotRequest,
    ) -> MemoryResult<Option<CodeSnapshotView>> {
        self.codebase_owner(owner)?;
        let Some(mount) = self.codebase_pinned(input.repo, &input.snapshot)? else {
            return Ok(None);
        };
        let mut views = mount.projected_file_views(|_| true)?;
        let mut view = snapshot_view(mount.code_artifact_id(), mount.snapshot());
        for file in &mut view.files {
            file.projection = views.remove(&file.path);
        }
        Ok(Some(view))
    }

    /// [`Self::code_snapshot_read_as`] for a caller the host knows is a tool
    /// or a run (FIX 7608, ASK 1): the same owner proof, mount, withheld
    /// paths and ASSET admission; a marked file reads as its projection,
    /// found before its stored bytes are read.
    pub fn code_snapshot_read_projected_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeSnapshotReadRequest,
    ) -> MemoryResult<Option<CodeSnapshotPinnedFile>> {
        self.codebase_owner(owner)?;
        let Some(mount) = self.codebase_pinned(input.repo, &input.snapshot)? else {
            return Ok(None);
        };
        // A read that says why asks only after the ASSET is admitted (FIX
        // 8960); one with none reads as before.
        let early = match input.why {
            None => match mount.read_file_projected(&input.path)? {
                Some(read) => Some(read),
                None => return Ok(None),
            },
            Some(_) => None,
        };
        let Some(entry) = mount
            .snapshot()
            .files
            .iter()
            .find(|entry| entry.path == input.path)
        else {
            return Ok(None);
        };
        let asset = snapshot_asset_entity_id(&entry.content_hash)?;
        if !self.codebase_readable(asset)? {
            return Ok(None);
        }
        let (read, byte_route) = match early {
            Some(read) => (read, None),
            None => {
                let changed =
                    || crate::Error::ConcurrentWrite("the snapshot read's admission changed");
                let artifact = mount.code_artifact_id();
                let readmit = || -> crate::error::Result<()> {
                    self.codebase_owner(owner).map_err(|_| changed())?;
                    let pinned = self
                        .codebase_pinned(input.repo, &input.snapshot)
                        .map_err(|_| changed())?;
                    if pinned.is_none_or(|pinned| pinned.code_artifact_id() != artifact)
                        || !self.codebase_readable(asset).map_err(|_| changed())?
                    {
                        return Err(changed());
                    }
                    Ok(())
                };
                let Some(read) = self.snapshot_file_read_with_why(
                    &mount,
                    input.repo,
                    &input.path,
                    input.why.as_deref(),
                    RepoReadDoor::Text,
                    readmit,
                )?
                else {
                    return Ok(None);
                };
                (read.projection, read.byte_route)
            }
        };
        let mut file = snapshot_file(entry);
        file.projection = read.view();
        // CALL 4: granted bytes that are not text keep the masked reply,
        // which names the byte route.
        if let (Some(route), Some(view)) = (byte_route, file.projection.as_mut()) {
            route.clone_into(&mut view.way_out);
        }
        let (content, text_sha256) = pinned_text(read.into_bytes())?;
        Ok(Some(CodeSnapshotPinnedFile {
            repo: input.repo,
            snapshot: input.snapshot,
            file,
            content,
            text_sha256,
        }))
    }

    /// The CALL behind import timing: the vault clock stamps both when the
    /// import occurred and when it was learned. No caller clock is read.
    fn codebase_import_time(&self) -> (TimeRange, u64) {
        let at = self.vault.store.clock.now_recorded_at();
        (TimeRange { start: at, end: at }, at)
    }
}

/// The CALL behind `pointer.local_folder`: an absolute path on the serving
/// engine's host, not the client's. The adapter reads no client file, clones
/// nothing and grants nothing by the path; the existing importer opens it.
/// A folder may hold `#`: the pointer grammar ends the path at its last one.
fn served_host_folder(local_folder: &str) -> MemoryResult<&str> {
    if !Path::new(local_folder).is_absolute() {
        return Err(MemoryError::bad_request_with(
            "pointer.local_folder must be an absolute folder on the serving host",
            &["Name the folder as the engine host sees it, not as the client does."],
        ));
    }
    Ok(local_folder)
}

/// The CALL behind the import commit: the explicit full commit, 40 hex
/// characters, normalized by the existing pointer grammar. No HEAD, branch or
/// tag name resolves here.
fn pinned_commit(folder: &str, commit: &str) -> MemoryResult<String> {
    match RepoRef::parse(&format!("local:{folder}#{commit}"))? {
        RepoRef::LocalFolder {
            path,
            commit: normalized,
        } if path == folder => Ok(normalized),
        _ => Err(MemoryError::bad_request(
            "pointer must name one local folder and its full commit",
        )),
    }
}

/// The CALL behind the pinned text: strict UTF-8 over the exact stored bytes,
/// and `text_sha256` over those same bytes. A file that is not UTF-8 refuses;
/// no byte is replaced, and no blob, chunk or fingerprint hash stands in.
fn pinned_text(bytes: Vec<u8>) -> MemoryResult<(String, String)> {
    let text_sha256 = bytes_to_hex_lower(&Sha256::digest(&bytes));
    let content = String::from_utf8(bytes)
        .map_err(|_| MemoryError::bad_request("the pinned file is not UTF-8 text"))?;
    Ok((content, text_sha256))
}

fn snapshot_view(repo: EntityId, snapshot: &CodebaseSnapshot) -> CodeSnapshotView {
    CodeSnapshotView {
        repo,
        repo_ref: snapshot.repo_ref.canonical(),
        project_id: snapshot.project_id.clone(),
        commit: snapshot.commit_hash.clone(),
        snapshot: bytes_to_hex_lower(&snapshot.fork_hash),
        scope_key: bytes_to_hex_lower(&snapshot.scope_key),
        files: snapshot.files.iter().map(snapshot_file).collect(),
    }
}

fn snapshot_file(entry: &CodebaseFileEntry) -> CodeSnapshotFile {
    CodeSnapshotFile {
        path: entry.path.clone(),
        content_hash_blake3: bytes_to_hex_lower(&entry.content_hash),
        size_bytes: entry.size_bytes,
        mode: entry.mode,
        projection: None,
    }
}
