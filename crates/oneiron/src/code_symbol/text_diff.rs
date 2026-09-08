//! Language-agnostic chunking of a text diff into code chunks and embedding inputs.

use std::ops::Range;

use crate::codebase::RepoRef;
use crate::error::{Error, Result};

use super::rust_source::{
    derive_rust_code_chunks_from_text_diff, is_tree_sitter_rust_source, rust_code_embedding_inputs,
};
use super::types::{CodeChunk, CodeEmbeddingInput, CodeEmbeddingVector, CodeSymbolRevision};
use super::validate::{validate_manifest_path, validate_symbol_indexes};

pub fn derive_code_chunks_from_text_diff(
    path: &str,
    old_text: &str,
    new_text: &str,
) -> Result<Vec<CodeChunk>> {
    validate_manifest_path(path)?;
    if old_text == new_text {
        return Ok(Vec::new());
    }

    if is_tree_sitter_rust_source(path) {
        return derive_rust_code_chunks_from_text_diff(path, old_text, new_text);
    }

    derive_line_diff_code_chunks(path, old_text, new_text)
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
    let changed_ranges = changed_line_ranges(old_text, new_text);
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

fn derive_line_diff_code_chunks(
    path: &str,
    old_text: &str,
    new_text: &str,
) -> Result<Vec<CodeChunk>> {
    let old_lines: Vec<&str> = old_text.lines().collect();
    let new_lines: Vec<&str> = new_text.lines().collect();
    if old_lines.len() == new_lines.len() {
        return changed_equal_length_chunks(path, &old_lines, &new_lines, new_text);
    }

    let mut prefix = 0;
    let min_len = old_lines.len().min(new_lines.len());
    while prefix < min_len && old_lines[prefix] == new_lines[prefix] {
        prefix += 1;
    }

    let mut suffix = 0;
    while suffix < old_lines.len().saturating_sub(prefix)
        && suffix < new_lines.len().saturating_sub(prefix)
        && old_lines[old_lines.len() - 1 - suffix] == new_lines[new_lines.len() - 1 - suffix]
    {
        suffix += 1;
    }

    let new_end = new_lines.len().saturating_sub(suffix);
    Ok(vec![chunk_for_line_range(
        path, &new_lines, prefix, new_end, new_text,
    )?])
}

pub(super) fn changed_line_ranges(old_text: &str, new_text: &str) -> Vec<Range<usize>> {
    if old_text == new_text {
        return Vec::new();
    }

    let old_lines: Vec<&str> = old_text.lines().collect();
    let new_lines: Vec<&str> = new_text.lines().collect();
    if old_lines.len() == new_lines.len() {
        let mut ranges = Vec::new();
        let mut index = 0;
        while index < new_lines.len() {
            if old_lines[index] == new_lines[index] {
                index += 1;
                continue;
            }
            let start = index;
            index += 1;
            while index < new_lines.len() && old_lines[index] != new_lines[index] {
                index += 1;
            }
            ranges.push(start..index);
        }
        return ranges;
    }

    let mut prefix = 0;
    let min_len = old_lines.len().min(new_lines.len());
    while prefix < min_len && old_lines[prefix] == new_lines[prefix] {
        prefix += 1;
    }

    let mut suffix = 0;
    while suffix < old_lines.len().saturating_sub(prefix)
        && suffix < new_lines.len().saturating_sub(prefix)
        && old_lines[old_lines.len() - 1 - suffix] == new_lines[new_lines.len() - 1 - suffix]
    {
        suffix += 1;
    }

    let new_end = new_lines.len().saturating_sub(suffix);
    let mut ranges = Vec::with_capacity(1);
    if prefix == new_end {
        ranges.push(prefix..prefix.saturating_add(1));
    } else {
        ranges.push(prefix..new_end);
    }
    ranges
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

pub(super) fn source_end_line(source: &str) -> Result<u32> {
    u32::try_from(source.lines().count().max(1))
        .map_err(|_| Error::InvalidCodeSymbolManifestBody("line number exceeds u32"))
}

fn changed_equal_length_chunks(
    path: &str,
    old_lines: &[&str],
    new_lines: &[&str],
    new_text: &str,
) -> Result<Vec<CodeChunk>> {
    let mut chunks = Vec::new();
    let mut index = 0;
    while index < new_lines.len() {
        if old_lines[index] == new_lines[index] {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < new_lines.len() && old_lines[index] != new_lines[index] {
            index += 1;
        }
        chunks.push(chunk_for_line_range(
            path, new_lines, start, index, new_text,
        )?);
    }
    Ok(chunks)
}

pub(super) fn chunk_for_line_range(
    path: &str,
    lines: &[&str],
    start: usize,
    end: usize,
    source_text: &str,
) -> Result<CodeChunk> {
    let line_number = u32::try_from(start + 1)
        .map_err(|_| Error::InvalidCodeSymbolManifestBody("line number exceeds u32"))?;
    if start == end {
        return CodeChunk::from_text(path, line_number, line_number, "");
    }
    let end_line = u32::try_from(end)
        .map_err(|_| Error::InvalidCodeSymbolManifestBody("line number exceeds u32"))?;
    let mut text = lines[start..end].join("\n");
    if end == lines.len() && source_text.ends_with('\n') {
        text.push('\n');
    }
    CodeChunk::from_text(path, line_number, end_line, &text)
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
            Error::InvalidCodeSymbolManifestBody("symbol chunk index exceeds usize")
        })?;
        let chunk = chunks
            .get(index)
            .ok_or(Error::InvalidCodeSymbolManifestBody(
                "symbol chunk index is out of bounds",
            ))?;
        start_line = start_line.min(chunk.start_line);
        end_line = end_line.max(chunk.end_line);
    }
    Ok((start_line, end_line))
}
