//! Owner capture of current folder bytes through the native snapshot writer.

use std::convert::Infallible;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use super::super::ingest::{
    RepoIngestBlob, RepoIngestResult, scan_codebase_snapshot_metadata, validate_project_id,
};
use super::super::repo_ref::RepoRef;
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{CodeError, Error, GateError, Result};
use crate::host_memory::{MachineMemory, MemoryLease};
use crate::repo_mutation::CaptureEntry;
use crate::temporal::TimeRange;

impl Vault {
    pub(crate) fn capture_local_folder_as_owner(
        &self,
        project_id: String,
        folder: &Path,
        timing: (TimeRange, u64),
        owner: &AuthenticatedOwner,
        actor: EntityId,
    ) -> Result<RepoIngestResult> {
        if owner.revalidate(self)? != actor {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "capture owner differs from the authenticated actor",
            )));
        }
        validate_project_id(&project_id)?;
        let root = folder.canonicalize()?;
        let path = root
            .to_str()
            .ok_or(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                "capture folder must be UTF-8",
            )))?;
        let repo_ref = RepoRef::LocalCapture {
            path: path.to_owned(),
        };
        // Validate the pointer before walking or allocating any file body.
        RepoRef::parse(&repo_ref.canonical())?;
        let mut capture = CapturedFiles {
            blobs: Vec::new(),
            memory: MachineMemory::process().empty_lease(),
        };
        crate::repo_mutation::visit_code_capture_files(self, &root, |relative, entry| {
            let (data, mode) = match entry {
                CaptureEntry::File(file) => {
                    let metadata = file.metadata()?;
                    let data = read_file(file, metadata.len(), &mut capture.memory)?;
                    (data, file_mode(&metadata))
                }
                link @ CaptureEntry::Symlink { expected, .. } => (
                    read_symlink(&link, expected, &mut capture.memory)?,
                    0o120_000,
                ),
            };
            capture.blobs.push(RepoIngestBlob {
                path: relative,
                content_hash: *blake3::hash(&data).as_bytes(),
                size_bytes: data.len() as u64,
                data,
                mode,
            });
            Ok(())
        })?;
        capture.blobs.sort_by(|a, b| a.path.cmp(&b.path));
        let snapshot = Self::build_ingest_snapshot(project_id, &repo_ref, None, &capture.blobs)?;
        scan_codebase_snapshot_metadata(&snapshot)?;
        let contents = |path: &str| {
            capture
                .blobs
                .binary_search_by_key(&path, |blob| blob.path.as_str())
                .ok()
                .map(|index| capture.blobs[index].data.clone())
        };
        let result = self.commit_ingest_snapshot(
            &snapshot,
            &capture.blobs,
            timing.0,
            timing.1,
            Some(path.trim_end_matches('/')),
            &contents,
            |txn| {
                if owner.revalidate_in_txn(self, txn)? != actor {
                    return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                        "capture owner differs from the authenticated actor",
                    )));
                }
                Ok(Ok::<(), Infallible>(()))
            },
        )?;
        match result {
            Ok(result) => Ok(result),
            Err(never) => match never {},
        }
    }
}

/// Bodies drop before the admission that kept room for them through the writer.
struct CapturedFiles {
    blobs: Vec<RepoIngestBlob>,
    memory: MemoryLease,
}

/// Never wait behind another request while retaining buffers it may need.
fn grow_memory(memory: &mut MemoryLease, more: u64) -> Result<()> {
    memory
        .grow(more, std::time::Instant::now(), &|| false)
        .map_err(|refusal| {
            Error::Code(CodeError::CodebaseCaptureMemoryRefused {
                detail: format!("{refusal:?}"),
            })
        })
}

/// Reads a growing file without allocating its next buffer before admission.
fn read_file(mut file: File, expected: u64, memory: &mut MemoryLease) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let initial =
        usize::try_from(expected).map_err(|_| Error::ArithmeticOverflow("capture file length"))?;
    grow_buffer(&mut bytes, initial, memory)?;
    let mut filled = 0;
    loop {
        if filled == bytes.len() {
            let mut next = [0];
            match file.read(&mut next) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
            let more = bytes.len().max(1);
            grow_buffer(&mut bytes, more, memory)?;
            bytes[filled] = next[0];
            filled += 1;
            continue;
        }
        match file.read(&mut bytes[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    bytes.truncate(filled);
    Ok(bytes)
}

fn read_symlink(
    entry: &CaptureEntry<'_>,
    expected: u64,
    memory: &mut MemoryLease,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let initial = usize::try_from(expected)
        .map_err(|_| Error::ArithmeticOverflow("capture symlink length"))?
        .max(1);
    grow_buffer(&mut bytes, initial, memory)?;
    loop {
        let read = entry.read_link(&mut bytes)?;
        if read < bytes.len() {
            bytes.truncate(read);
            std::str::from_utf8(&bytes).map_err(|_| {
                Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                    "capture symlink target must be UTF-8",
                ))
            })?;
            return Ok(bytes);
        }
        let more = bytes.len().max(1);
        grow_buffer(&mut bytes, more, memory)?;
    }
}

fn grow_buffer(bytes: &mut Vec<u8>, more: usize, memory: &mut MemoryLease) -> Result<()> {
    let old = bytes.capacity();
    grow_memory(memory, more as u64)?;
    bytes.try_reserve_exact(more).map_err(|_| {
        Error::Code(CodeError::CodebaseCaptureMemoryRefused {
            detail: "allocation failed".to_owned(),
        })
    })?;
    memory.materialized(more as u64, bytes.capacity().saturating_sub(old) as u64);
    bytes.resize(bytes.capacity(), 0);
    Ok(())
}

fn file_mode(metadata: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 != 0 {
            return 0o100_755;
        }
    }
    #[cfg(not(unix))]
    let _ = metadata;
    super::super::DEFAULT_CODE_FILE_MODE
}
