//! Chunk, symbol, manifest, graph and embedding value types with their limits.

use crate::codebase::RepoRef;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::codec::sha256_bytes;
use super::validate::{
    compare_code_symbol_graph_edges, compare_symbols, normalize_commit_hash,
    sort_chunks_with_index_remap, validate_code_symbol_graph_edge, validate_code_symbol_manifest,
};

pub const CODE_SYMBOL_TEXT_HASH_LEN: usize = 32;

pub const CODE_SYMBOL_FINGERPRINT_LEN: usize = 32;

pub const CODE_SYMBOL_NAME_MAX_BYTES: usize = 1024;

pub const CODE_SYMBOL_KIND_MAX_BYTES: usize = 128;

pub const CODE_SYMBOL_SOURCE_SESSION_MAX_BYTES: usize = 512;

pub const CODE_SYMBOL_MANIFEST_MAX_CHUNKS: usize = 100_000;

pub const CODE_SYMBOL_MANIFEST_MAX_SYMBOLS: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeChunk {
    pub path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub content_hash: [u8; CODE_SYMBOL_TEXT_HASH_LEN],
}

impl CodeChunk {
    #[must_use]
    pub fn new(
        path: impl Into<String>,
        start_line: u32,
        end_line: u32,
        content_hash: [u8; CODE_SYMBOL_TEXT_HASH_LEN],
    ) -> Self {
        Self {
            path: path.into(),
            start_line,
            end_line,
            content_hash,
        }
    }

    pub fn from_text(
        path: impl Into<String>,
        start_line: u32,
        end_line: u32,
        text: &str,
    ) -> Result<Self> {
        Ok(Self::new(
            path,
            start_line,
            end_line,
            sha256_bytes(text.as_bytes()),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeEmbeddingInput {
    pub entity_id: EntityId,
    pub path: String,
    pub name: String,
    pub kind: String,
    pub start_line: u32,
    pub end_line: u32,
    pub content_hash: [u8; CODE_SYMBOL_TEXT_HASH_LEN],
    pub text: String,
}

impl CodeEmbeddingInput {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        entity_id: EntityId,
        path: impl Into<String>,
        name: impl Into<String>,
        kind: impl Into<String>,
        start_line: u32,
        end_line: u32,
        content_hash: [u8; CODE_SYMBOL_TEXT_HASH_LEN],
        text: impl Into<String>,
    ) -> Self {
        Self {
            entity_id,
            path: path.into(),
            name: name.into(),
            kind: kind.into(),
            start_line,
            end_line,
            content_hash,
            text: text.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct CodeEmbeddingVector {
    pub entity_id: EntityId,
    pub vector: Vec<f32>,
}

impl CodeEmbeddingVector {
    #[must_use]
    pub fn new(entity_id: EntityId, vector: impl Into<Vec<f32>>) -> Self {
        Self {
            entity_id,
            vector: vector.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeSymbolRevision {
    pub path: String,
    pub name: String,
    pub kind: String,
    pub fingerprint: [u8; CODE_SYMBOL_FINGERPRINT_LEN],
    pub chunk_indexes: Vec<u32>,
    pub provenance_claim_id: Option<EntityId>,
    pub source_session: Option<String>,
}

impl CodeSymbolRevision {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        path: impl Into<String>,
        name: impl Into<String>,
        kind: impl Into<String>,
        fingerprint: [u8; CODE_SYMBOL_FINGERPRINT_LEN],
        chunk_indexes: Vec<u32>,
        provenance_claim_id: Option<EntityId>,
        source_session: Option<String>,
    ) -> Self {
        Self {
            path: path.into(),
            name: name.into(),
            kind: kind.into(),
            fingerprint,
            chunk_indexes,
            provenance_claim_id,
            source_session,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeSymbolManifest {
    pub repo_ref: RepoRef,
    pub commit_hash: Option<String>,
    pub chunks: Vec<CodeChunk>,
    pub symbols: Vec<CodeSymbolRevision>,
}

impl CodeSymbolManifest {
    pub fn new(
        repo_ref: RepoRef,
        commit_hash: Option<String>,
        chunks: Vec<CodeChunk>,
        mut symbols: Vec<CodeSymbolRevision>,
    ) -> Result<Self> {
        let (chunks, remapped_indexes) = sort_chunks_with_index_remap(chunks)?;
        symbols.sort_by(compare_symbols);
        for symbol in &mut symbols {
            for index in &mut symbol.chunk_indexes {
                let old_index = usize::try_from(*index).map_err(|_| {
                    Error::InvalidCodeSymbolManifestBody(
                        "symbol revision chunk index exceeds usize",
                    )
                })?;
                *index = *remapped_indexes.get(old_index).ok_or(
                    Error::InvalidCodeSymbolManifestBody(
                        "symbol revision chunk index is out of bounds",
                    ),
                )?;
            }
            symbol.chunk_indexes.sort_unstable();
            symbol.chunk_indexes.dedup();
        }
        let manifest = Self {
            repo_ref,
            commit_hash: commit_hash.map(normalize_commit_hash).transpose()?,
            chunks,
            symbols,
        };
        validate_code_symbol_manifest(&manifest)?;
        Ok(manifest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeSymbolBlame {
    pub code_artifact_id: EntityId,
    pub provenance_claim_id: Option<EntityId>,
    pub source_session: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeSymbolSource<'a> {
    pub path: &'a str,
    pub text: &'a str,
}

impl<'a> CodeSymbolSource<'a> {
    #[must_use]
    pub const fn new(path: &'a str, text: &'a str) -> Self {
        Self { path, text }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct CodeSymbolGraphEdge {
    pub source: EntityId,
    pub kind: EdgeKind,
    pub target: EntityId,
    pub weight: f32,
}

impl CodeSymbolGraphEdge {
    #[must_use]
    pub const fn new(source: EntityId, kind: EdgeKind, target: EntityId, weight: f32) -> Self {
        Self {
            source,
            kind,
            target,
            weight,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct CodeSymbolGraph {
    pub manifest: CodeSymbolManifest,
    pub edges: Vec<CodeSymbolGraphEdge>,
}

impl CodeSymbolGraph {
    pub fn new(manifest: CodeSymbolManifest, mut edges: Vec<CodeSymbolGraphEdge>) -> Result<Self> {
        validate_code_symbol_manifest(&manifest)?;
        for edge in &edges {
            validate_code_symbol_graph_edge(edge)?;
        }
        edges.sort_by(compare_code_symbol_graph_edges);
        edges.dedup_by(|left, right| {
            left.source == right.source
                && left.kind == right.kind
                && left.target == right.target
                && left.weight.to_bits() == right.weight.to_bits()
        });
        Ok(Self { manifest, edges })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeSymbolDefinition {
    pub entity_id: EntityId,
    pub path: String,
    pub name: String,
    pub kind: String,
    pub fingerprint: [u8; CODE_SYMBOL_FINGERPRINT_LEN],
    pub start_line: u32,
    pub end_line: u32,
}
