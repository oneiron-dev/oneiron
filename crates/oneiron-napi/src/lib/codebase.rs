//! Codebase snapshot conversion and codebase-scoped query filters.

use napi::bindgen_prelude::*;
use oneiron::{
    CODEBASE_FORK_HASH_LEN, CODEBASE_SCOPE_KEY_LEN, CodebaseFileEntry, CodebaseSnapshot, RepoRef,
};

use super::boundary::{
    BoundaryResult, parse_content_hash, parse_file_size, parse_fixed_hash, to_napi_err,
    validate_codebase_file_count,
};
use super::types::{NapiCodebaseFileEntry, NapiCodebaseSnapshot};

pub(super) fn core_codebase_snapshot(
    input: NapiCodebaseSnapshot,
) -> BoundaryResult<CodebaseSnapshot> {
    validate_codebase_file_count(input.files.len())?;
    let repo_ref = RepoRef::parse(&input.repo_ref).map_err(|e| e.to_string())?;
    let files = input
        .files
        .into_iter()
        .map(|entry| {
            Ok(CodebaseFileEntry::new(
                entry.path,
                parse_content_hash(&entry.content_hash)?,
                parse_file_size(entry.size_bytes)?,
            ))
        })
        .collect::<BoundaryResult<Vec<_>>>()?;
    let fork_hash = input
        .fork_hash
        .as_ref()
        .map(|buf| parse_fixed_hash::<CODEBASE_FORK_HASH_LEN>(buf, "fork_hash"))
        .transpose()?;
    let scope_key = input
        .scope_key
        .as_ref()
        .map(|buf| parse_fixed_hash::<CODEBASE_SCOPE_KEY_LEN>(buf, "scope_key"))
        .transpose()?;
    let snapshot = CodebaseSnapshot::new(input.project_id, repo_ref, input.commit_hash, files)
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

pub(super) fn apply_codebase_filters<'a>(
    mut builder: oneiron::PipelineBuilder<'a>,
    repo_ref: Option<String>,
    project_id: Option<String>,
) -> napi::Result<oneiron::PipelineBuilder<'a>> {
    if let Some(repo_ref) = repo_ref {
        builder = builder.filter_repo_ref(RepoRef::parse(&repo_ref).map_err(to_napi_err)?);
    }
    if let Some(project_id) = project_id {
        builder = builder.filter_project_id(project_id);
    }
    Ok(builder)
}

pub(super) fn apply_codebase_context_filters<'a>(
    mut builder: oneiron::ContextPackBuilder<'a>,
    repo_ref: Option<String>,
    project_id: Option<String>,
) -> napi::Result<oneiron::ContextPackBuilder<'a>> {
    if let Some(repo_ref) = repo_ref {
        builder = builder.filter_repo_ref(RepoRef::parse(&repo_ref).map_err(to_napi_err)?);
    }
    if let Some(project_id) = project_id {
        builder = builder.filter_project_id(project_id);
    }
    Ok(builder)
}
