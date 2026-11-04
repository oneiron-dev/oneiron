//! Codebase snapshot conversion and codebase-scoped query filters.

use napi::bindgen_prelude::*;
use oneiron::{
    CODEBASE_FORK_HASH_LEN, CODEBASE_SCOPE_KEY_LEN, CodebaseFileEntry, CodebaseSnapshot, RepoRef,
};

use oneiron::host_memory::{MachineMemory, MemoryLease};

use super::boundary::{
    BoundaryResult, parse_content_hash, parse_file_size, parse_fixed_hash, to_napi_err,
};
use super::types::{NapiCodebaseFileEntry, NapiCodebaseSnapshot};

/// FIX74 native-ingress slice: the caller-owned admission guard for one
/// `put_codebase_snapshot`. It wraps the process `MemoryLease` and admits
/// only direct native DTO, core `Vec`, path and callback bytes. It starts
/// empty and admits nothing until the first actual reserve.
pub(super) struct CodebaseMemory {
    lease: MemoryLease,
}

impl CodebaseMemory {
    pub(super) fn new() -> Self {
        Self {
            lease: MachineMemory::process().empty_lease(),
        }
    }

    pub(super) fn reserve(&mut self, bytes: u64) -> BoundaryResult<()> {
        if bytes == 0 {
            return Ok(());
        }
        self.lease
            .grow_pending_untimed(bytes, &|| false)
            .map_err(|refusal| format!("native codebase ingress refused: {refusal:?}"))
    }

    pub(super) fn vector<T>(&mut self, len: usize) -> BoundaryResult<Vec<T>> {
        let want = (len as u64)
            .checked_mul(std::mem::size_of::<T>() as u64)
            .ok_or_else(|| format!("native codebase ingress vector too long: {len}"))?;
        self.reserve(want)?;
        let vec = Vec::<T>::with_capacity(len);
        let actual = (vec.capacity() as u64)
            .checked_mul(std::mem::size_of::<T>() as u64)
            .ok_or_else(|| format!("native codebase ingress vector too long: {len}"))?;
        self.allocated(want, actual);
        Ok(vec)
    }

    pub(super) fn allocated(&mut self, reserved: u64, actual: u64) {
        self.lease.materialized(reserved, actual);
    }

    pub(super) fn release(&mut self, bytes: u64) {
        self.lease.shrink(bytes);
    }
}

struct ContentEntry {
    path: String,
    body: Vec<u8>,
    position: usize,
}

/// Owned bodies captured before core conversion, sorted by path and original
/// position. The last present body at a path wins, as in the original map.
pub(super) struct CodebaseContents {
    entries: Vec<ContentEntry>,
}

impl CodebaseContents {
    pub(super) fn from_files(
        files: &[NapiCodebaseFileEntry],
        memory: &mut CodebaseMemory,
    ) -> BoundaryResult<Self> {
        let count = files.iter().filter(|entry| entry.content.is_some()).count();
        let mut entries = memory.vector::<ContentEntry>(count)?;
        for (position, entry) in files.iter().enumerate() {
            if let Some(body) = &entry.content {
                let want = (entry.path.len() as u64)
                    .checked_add(body.len() as u64)
                    .ok_or_else(|| "native codebase ingress content too long".to_owned())?;
                memory.reserve(want)?;
                let path = entry.path.clone();
                let body = body.to_vec();
                memory.allocated(want, path.capacity() as u64 + body.capacity() as u64);
                entries.push(ContentEntry {
                    path,
                    body,
                    position,
                });
            }
        }
        entries.sort_unstable_by(|a, b| {
            a.path
                .cmp(&b.path)
                .then_with(|| a.position.cmp(&b.position))
        });
        Ok(Self { entries })
    }

    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(super) fn get(&self, path: &str) -> Option<Vec<u8>> {
        let start = self
            .entries
            .partition_point(|entry| entry.path.as_str() < path);
        let mut found: Option<&ContentEntry> = None;
        for entry in &self.entries[start..] {
            if entry.path.as_str() != path {
                break;
            }
            found = Some(entry);
        }
        found.map(|entry| entry.body.clone())
    }

    pub(super) fn max_scratch_len(&self) -> u64 {
        let mut max: u64 = 0;
        let mut index = 0;
        while index < self.entries.len() {
            let mut end = index + 1;
            while end < self.entries.len() && self.entries[end].path == self.entries[index].path {
                end += 1;
            }
            let last_len = self.entries[end - 1].body.len() as u64;
            if last_len > max {
                max = last_len;
            }
            index = end;
        }
        max
    }
}

pub(super) fn core_codebase_snapshot(
    input: NapiCodebaseSnapshot,
    memory: &mut CodebaseMemory,
) -> BoundaryResult<CodebaseSnapshot> {
    let NapiCodebaseSnapshot {
        project_id,
        repo_ref: repo_ref_string,
        commit_hash,
        fork_hash,
        scope_key,
        files,
    } = input;
    let repo_ref = RepoRef::parse(&repo_ref_string).map_err(|e| e.to_string())?;
    let mut core_files = memory.vector::<CodebaseFileEntry>(files.len())?;
    let napi_cap_bytes = (files.capacity() as u64)
        .checked_mul(std::mem::size_of::<NapiCodebaseFileEntry>() as u64)
        .ok_or_else(|| "native codebase ingress manifest too long".to_owned())?;
    for entry in files {
        core_files.push(CodebaseFileEntry::new(
            entry.path,
            parse_content_hash(&entry.content_hash)?,
            parse_file_size(entry.size_bytes)?,
        ));
    }
    memory.release(napi_cap_bytes);
    let fork_hash = fork_hash
        .as_ref()
        .map(|buf| parse_fixed_hash::<CODEBASE_FORK_HASH_LEN>(buf, "fork_hash"))
        .transpose()?;
    let scope_key = scope_key
        .as_ref()
        .map(|buf| parse_fixed_hash::<CODEBASE_SCOPE_KEY_LEN>(buf, "scope_key"))
        .transpose()?;
    let snapshot = CodebaseSnapshot::new(project_id, repo_ref, commit_hash, core_files)
        .map_err(|e| e.to_string())?;
    if let Some(fork_hash) = fork_hash
        && snapshot.fork_hash != fork_hash
    {
        return Err("fork_hash must match the file manifest".to_owned());
    }
    if let Some(scope_key) = scope_key
        && snapshot.scope_key != scope_key
    {
        return Err("scope_key must match project_id and repo_ref".to_owned());
    }
    Ok(snapshot)
}

pub(super) fn napi_codebase_snapshot(
    snapshot: CodebaseSnapshot,
) -> BoundaryResult<NapiCodebaseSnapshot> {
    let files = snapshot
        .files
        .into_iter()
        .map(|entry| {
            let size_bytes = i64::try_from(entry.size_bytes).map_err(|_| {
                format!(
                    "size_bytes must fit in signed 64-bit integer, got {}",
                    entry.size_bytes
                )
            })?;
            Ok(NapiCodebaseFileEntry {
                path: entry.path,
                content_hash: Buffer::from(entry.content_hash.as_slice()),
                size_bytes,
                // Reads return the manifest only; bodies live in ASSET entities.
                content: None,
            })
        })
        .collect::<BoundaryResult<Vec<_>>>()?;
    Ok(NapiCodebaseSnapshot {
        project_id: snapshot.project_id,
        repo_ref: snapshot.repo_ref.canonical(),
        commit_hash: snapshot.commit_hash,
        fork_hash: Some(Buffer::from(snapshot.fork_hash.as_slice())),
        scope_key: Some(Buffer::from(snapshot.scope_key.as_slice())),
        files,
    })
}

/// The codebase filters a scoped search or pack names, parsed once, so a
/// run can apply them again on base without a second parse.
pub(super) struct CodebaseScope {
    repo_ref: Option<RepoRef>,
    project_id: Option<String>,
}

impl CodebaseScope {
    pub(super) fn parse(
        repo_ref: Option<String>,
        project_id: Option<String>,
    ) -> napi::Result<Self> {
        let repo_ref = repo_ref
            .map(|repo_ref| RepoRef::parse(&repo_ref))
            .transpose()
            .map_err(to_napi_err)?;
        Ok(Self {
            repo_ref,
            project_id,
        })
    }

    /// `builder`, filtered to this scope.
    pub(super) fn query<'a>(
        &self,
        mut builder: oneiron::PipelineBuilder<'a>,
    ) -> oneiron::PipelineBuilder<'a> {
        if let Some(repo_ref) = &self.repo_ref {
            builder = builder.filter_repo_ref(repo_ref.clone());
        }
        if let Some(project_id) = &self.project_id {
            builder = builder.filter_project_id(project_id.as_str());
        }
        builder
    }

    /// `builder`, filtered to this scope.
    pub(super) fn pack<'a>(
        &self,
        mut builder: oneiron::ContextPackBuilder<'a>,
    ) -> oneiron::ContextPackBuilder<'a> {
        if let Some(repo_ref) = &self.repo_ref {
            builder = builder.filter_repo_ref(repo_ref.clone());
        }
        if let Some(project_id) = &self.project_id {
            builder = builder.filter_project_id(project_id.as_str());
        }
        builder
    }
}
