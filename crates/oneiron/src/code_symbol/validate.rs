//! Manifest, chunk, symbol and commit-hash validation plus the secret scan.

use crate::batch::secret_scan;
use crate::codebase::{CODEBASE_COMMIT_HASH_HEX_LEN, CODEBASE_FILE_PATH_MAX_BYTES, RepoRef};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};

use super::types::{
    CODE_SYMBOL_KIND_MAX_BYTES, CODE_SYMBOL_MANIFEST_MAX_CHUNKS, CODE_SYMBOL_MANIFEST_MAX_SYMBOLS,
    CODE_SYMBOL_NAME_MAX_BYTES, CODE_SYMBOL_SOURCE_SESSION_MAX_BYTES, CodeChunk,
    CodeSymbolGraphEdge, CodeSymbolManifest, CodeSymbolRevision,
};

pub(super) fn validate_code_symbol_manifest(manifest: &CodeSymbolManifest) -> Result<()> {
    let canonical_repo_ref = manifest.repo_ref.canonical();
    if RepoRef::parse(&canonical_repo_ref)
        .map_err(|_| Error::InvalidCodeSymbolManifestBody("repo_ref must be a valid v1 repo_ref"))?
        != manifest.repo_ref
    {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "repo_ref must be a canonical v1 repo_ref",
        ));
    }
    if let Some(commit_hash) = &manifest.commit_hash {
        validate_normalized_commit_hash(commit_hash)?;
    }
    if let Some(repo_commit) = manifest.repo_ref.commit_hash()
        && manifest.commit_hash.as_deref() != Some(repo_commit)
    {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "GitHub repo_ref commit must match manifest commit_hash",
        ));
    }
    if manifest.chunks.len() > CODE_SYMBOL_MANIFEST_MAX_CHUNKS {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "chunk manifest exceeds 100000 entries",
        ));
    }
    if manifest.symbols.len() > CODE_SYMBOL_MANIFEST_MAX_SYMBOLS {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "symbol manifest exceeds 100000 entries",
        ));
    }

    let mut previous_chunk: Option<&CodeChunk> = None;
    for chunk in &manifest.chunks {
        validate_chunk(chunk)?;
        if let Some(previous) = previous_chunk
            && compare_chunks(previous, chunk) != std::cmp::Ordering::Less
        {
            return Err(Error::InvalidCodeSymbolManifestBody(
                "chunks must be sorted and unique",
            ));
        }
        previous_chunk = Some(chunk);
    }

    let mut previous_symbol: Option<&CodeSymbolRevision> = None;
    for symbol in &manifest.symbols {
        validate_symbol_shape(symbol)?;
        validate_symbol_indexes(symbol, &manifest.chunks)?;
        if let Some(previous) = previous_symbol
            && compare_symbols(previous, symbol) != std::cmp::Ordering::Less
        {
            return Err(Error::InvalidCodeSymbolManifestBody(
                "symbol revisions must be sorted and unique",
            ));
        }
        previous_symbol = Some(symbol);
    }
    Ok(())
}

pub(super) fn scan_code_symbol_manifest_metadata(manifest: &CodeSymbolManifest) -> Result<()> {
    let repo_ref = manifest.repo_ref.canonical();
    secret_scan::scan_metadata_field(&repo_ref)?;
    if let Some(commit_hash) = &manifest.commit_hash {
        secret_scan::scan_metadata_field(commit_hash)?;
    }
    for chunk in &manifest.chunks {
        secret_scan::scan_metadata_field(&chunk.path)?;
    }
    for symbol in &manifest.symbols {
        secret_scan::scan_metadata_field(&symbol.path)?;
        secret_scan::scan_metadata_field(&symbol.name)?;
        secret_scan::scan_metadata_field(&symbol.kind)?;
        if let Some(source_session) = &symbol.source_session {
            secret_scan::scan_metadata_field(source_session)?;
        }
    }
    Ok(())
}

pub(super) fn validate_chunk(chunk: &CodeChunk) -> Result<()> {
    validate_manifest_path(&chunk.path)?;
    if chunk.start_line == 0 || chunk.end_line == 0 || chunk.start_line > chunk.end_line {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "chunk line range must be 1-based and ordered",
        ));
    }
    Ok(())
}

pub(super) fn validate_symbol_shape(symbol: &CodeSymbolRevision) -> Result<()> {
    validate_manifest_path(&symbol.path)?;
    validate_text(&symbol.name, CODE_SYMBOL_NAME_MAX_BYTES, "symbol name")?;
    validate_text(&symbol.kind, CODE_SYMBOL_KIND_MAX_BYTES, "symbol kind")?;
    if let Some(session) = &symbol.source_session {
        validate_text(
            session,
            CODE_SYMBOL_SOURCE_SESSION_MAX_BYTES,
            "source_session",
        )?;
    }
    Ok(())
}

pub(super) fn validate_symbol_indexes(
    symbol: &CodeSymbolRevision,
    chunks: &[CodeChunk],
) -> Result<()> {
    if symbol.chunk_indexes.is_empty() {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "symbol revision must reference at least one chunk",
        ));
    }
    let mut previous: Option<u32> = None;
    for raw_index in &symbol.chunk_indexes {
        let index = usize::try_from(*raw_index)
            .ok()
            .filter(|index| *index < chunks.len())
            .ok_or(Error::InvalidCodeSymbolManifestBody(
                "symbol revision chunk index is out of bounds",
            ))?;
        if chunks[index].path != symbol.path {
            return Err(Error::InvalidCodeSymbolManifestBody(
                "symbol revision chunk path must match symbol path",
            ));
        }
        if let Some(previous) = previous
            && previous >= *raw_index
        {
            return Err(Error::InvalidCodeSymbolManifestBody(
                "symbol revision chunk indexes must be sorted and unique",
            ));
        }
        previous = Some(*raw_index);
    }
    Ok(())
}

pub(super) fn validate_manifest_path(path: &str) -> Result<()> {
    validate_text(path, CODEBASE_FILE_PATH_MAX_BYTES, "file path")?;
    if path.starts_with('/') || path.contains('\\') {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "file path must be repository-relative",
        ));
    }
    if path
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "file path must be normalized and cannot contain . or .. segments",
        ));
    }
    Ok(())
}

pub(super) fn validate_text(text: &str, max_bytes: usize, field: &'static str) -> Result<()> {
    if text.is_empty() || text.len() > max_bytes {
        return Err(Error::InvalidCodeSymbolManifestBody(field));
    }
    if text.trim() != text {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "text fields must not have leading or trailing whitespace",
        ));
    }
    if text.chars().any(char::is_control) {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "text fields must not contain control characters",
        ));
    }
    Ok(())
}

pub(super) fn normalize_commit_hash(input: impl AsRef<str>) -> Result<String> {
    let input = input.as_ref();
    if input.len() != CODEBASE_COMMIT_HASH_HEX_LEN || !input.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "commit hash must be 40 hexadecimal characters",
        ));
    }
    Ok(input.to_ascii_lowercase())
}

pub(super) fn validate_normalized_commit_hash(input: &str) -> Result<()> {
    if normalize_commit_hash(input)? != input {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "commit hash must use lowercase hexadecimal",
        ));
    }
    Ok(())
}

pub(super) fn validate_code_symbol_graph_edge(edge: &CodeSymbolGraphEdge) -> Result<()> {
    if edge.source == edge.target {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "code symbol graph edge cannot be a self-edge",
        ));
    }
    if !edge.weight.is_finite() || !(0.0..=1.0).contains(&edge.weight) || edge.weight == 0.0 {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "code symbol graph edge weight must be finite and in (0, 1]",
        ));
    }
    match edge.kind {
        EdgeKind::Mentions | EdgeKind::Attached => Ok(()),
        _ => Err(Error::InvalidCodeSymbolManifestBody(
            "code symbol graph edge kind must be Mentions or Attached",
        )),
    }
}

pub(super) fn compare_code_symbol_graph_edges(
    left: &CodeSymbolGraphEdge,
    right: &CodeSymbolGraphEdge,
) -> std::cmp::Ordering {
    left.source
        .cmp(&right.source)
        .then_with(|| (left.kind as u8).cmp(&(right.kind as u8)))
        .then_with(|| left.target.cmp(&right.target))
        .then_with(|| left.weight.to_bits().cmp(&right.weight.to_bits()))
}

pub(super) fn compare_chunks(a: &CodeChunk, b: &CodeChunk) -> std::cmp::Ordering {
    a.path
        .cmp(&b.path)
        .then_with(|| a.start_line.cmp(&b.start_line))
        .then_with(|| a.end_line.cmp(&b.end_line))
        .then_with(|| a.content_hash.cmp(&b.content_hash))
}

pub(super) fn compare_symbols(
    a: &CodeSymbolRevision,
    b: &CodeSymbolRevision,
) -> std::cmp::Ordering {
    a.path
        .cmp(&b.path)
        .then_with(|| a.name.cmp(&b.name))
        .then_with(|| a.fingerprint.cmp(&b.fingerprint))
}

pub(super) fn sort_chunks_with_index_remap(
    chunks: Vec<CodeChunk>,
) -> Result<(Vec<CodeChunk>, Vec<u32>)> {
    let mut indexed = chunks.into_iter().enumerate().collect::<Vec<_>>();
    indexed.sort_by(|(_, left), (_, right)| compare_chunks(left, right));
    let mut remapped = vec![0_u32; indexed.len()];
    let mut sorted = Vec::with_capacity(indexed.len());
    for (new_index, (old_index, chunk)) in indexed.into_iter().enumerate() {
        remapped[old_index] = u32::try_from(new_index).map_err(|_| {
            Error::InvalidCodeSymbolManifestBody("chunk manifest exceeds u32 indexes")
        })?;
        sorted.push(chunk);
    }
    Ok((sorted, remapped))
}
