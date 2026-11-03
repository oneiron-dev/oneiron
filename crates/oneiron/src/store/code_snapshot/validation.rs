//! Project identifiers and normalized paths in code snapshot manifests.

use super::snapshot::{
    CODEBASE_FILE_PATH_MAX_BYTES, CODEBASE_PROJECT_ID_MAX_BYTES, validate_bounded_text,
};
use crate::error::{CodeError, Error, Result};

pub(crate) fn validate_project_id(project_id: &str) -> Result<()> {
    validate_bounded_text(
        project_id,
        CODEBASE_PROJECT_ID_MAX_BYTES,
        "project_id must be non-empty and at most 256 bytes",
    )?;
    if project_id.trim() != project_id {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "project_id must not have leading or trailing whitespace",
        )));
    }
    Ok(())
}

pub(crate) fn validate_manifest_path(path: &str) -> Result<()> {
    validate_bounded_text(
        path,
        CODEBASE_FILE_PATH_MAX_BYTES,
        "file path must be non-empty and at most 4096 bytes",
    )?;
    if path.starts_with('/') || path.contains('\\') {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "file path must be repository-relative",
        )));
    }
    if path
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "file path must be normalized and cannot contain . or .. segments",
        )));
    }
    Ok(())
}
