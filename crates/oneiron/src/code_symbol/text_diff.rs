//! Language-agnostic chunking of a text diff into code chunks and embedding inputs.

use std::ops::Range;

use crate::codebase::RepoRef;
use crate::error::{Error, Result};

use super::rust_source::{is_tree_sitter_rust_source, rust_code_embedding_inputs};
use super::types::{CodeChunk, CodeEmbeddingInput, CodeEmbeddingVector, CodeSymbolRevision};
use super::validate::{validate_manifest_path, validate_symbol_indexes};
use crate::error::CodeError;

pub fn derive_code_chunks_from_text_diff(
    path: &str,
    old_text: &str,
    new_text: &str,
) -> Result<Vec<CodeChunk>> {
    super::semantic_diff::semantic_code_diff(path, old_text, new_text)?
        .into_iter()
        .filter_map(|change| change.after)
        .map(|version| {
            CodeChunk::from_text(path, version.start_line, version.end_line, &version.text)
        })
        .collect()
}

pub fn derive_code_embedding_inputs_from_text_diff(
    repo_ref: &RepoRef,
    path: &str,
    old_text: &str,
    new_text: &str,
) -> Result<Vec<CodeEmbeddingInput>> {
    validate_manifest_path(path)?;
    if old_text == new_text || !is_tree_sitter_rust_source(path) {
        return Ok(Vec::new());
    }
    let changed_ranges: Vec<_> =
        super::semantic_diff::semantic_code_diff(path, old_text, new_text)?
            .into_iter()
            .filter_map(|change| change.after)
            .map(|version| (version.start_line as usize - 1)..(version.end_line as usize))
            .collect();
    rust_code_embedding_inputs(repo_ref, path, new_text, &changed_ranges)
}

pub fn embed_code_chunks(
    inputs: &[CodeEmbeddingInput],
    embedder: impl FnOnce(&[CodeEmbeddingInput]) -> Result<Vec<Vec<f32>>>,
) -> Result<Vec<CodeEmbeddingVector>> {
    let vectors = embedder(inputs)?;
    if vectors.len() != inputs.len() {
        return Err(Error::InvariantViolation(
            "code embedder returned mismatched vector count",
        ));
    }
    Ok(inputs
        .iter()
        .zip(vectors)
        .map(|(input, vector)| CodeEmbeddingVector::new(input.entity_id, vector))
        .collect())
}

pub(super) fn subtract_line_range(ranges: &mut Vec<Range<usize>>, covered: Range<usize>) {
    let mut remaining = Vec::with_capacity(ranges.len());
    for range in ranges.drain(..) {
        if covered.end <= range.start || covered.start >= range.end {
            remaining.push(range);
            continue;
        }
        if range.start < covered.start {
            remaining.push(range.start..covered.start);
        }
        if covered.end < range.end {
            remaining.push(covered.end..range.end);
        }
    }
    *ranges = remaining;
}

pub(super) fn symbol_line_range(
    symbol: &CodeSymbolRevision,
    chunks: &[CodeChunk],
) -> Result<(u32, u32)> {
    validate_symbol_indexes(symbol, chunks)?;
    let mut start_line = u32::MAX;
    let mut end_line = 0_u32;
    for index in &symbol.chunk_indexes {
        let index = usize::try_from(*index).map_err(|_| {
            Error::Code(CodeError::InvalidCodeSymbolManifestBody(
                "symbol chunk index exceeds usize",
            ))
        })?;
        let chunk =
            chunks
                .get(index)
                .ok_or(Error::Code(CodeError::InvalidCodeSymbolManifestBody(
                    "symbol chunk index is out of bounds",
                )))?;
        start_line = start_line.min(chunk.start_line);
        end_line = end_line.max(chunk.end_line);
    }
    Ok((start_line, end_line))
}
