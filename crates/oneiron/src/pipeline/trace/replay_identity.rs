//! Snapshot identity shared by replay-input records and retrieval fork hashes.

use std::collections::BTreeMap;

use crate::config::VectorEvidenceFloors;
use crate::embed::{EmbeddingSpace, embedding_space_in_txn};
use crate::error::{Error, Result};
use crate::store::{ManifestDbs, TEXT_ANALYZER_MANIFEST_HASH_KEY, TEXT_BM25_FIELD_SCHEMA_HASH_KEY};

use super::super::budget::media_space_floors;
use super::super::builder::PipelineBuilder;

/// Media declarations and effective floors read beside the retrieval transaction.
pub(in crate::pipeline) struct MediaSpaceReplayIdentity {
    pub(in crate::pipeline) space: EmbeddingSpace,
    pub(in crate::pipeline) floors: VectorEvidenceFloors,
    pub(in crate::pipeline) kind_overrides: BTreeMap<u8, VectorEvidenceFloors>,
}

/// Non-candidate identity that both replay records and the fork hash consume.
pub(in crate::pipeline) struct RetrievalReplayIdentity {
    pub(in crate::pipeline) media_spaces: Vec<MediaSpaceReplayIdentity>,
    pub(in crate::pipeline) analyzer_manifest_hash: Option<Vec<u8>>,
    pub(in crate::pipeline) bm25_field_schema_hash: Option<Vec<u8>>,
    _media_memory: Option<crate::host_memory::MemoryLease>,
}

/// Captures the live declarations and the run's own floor snapshot once. The
/// caller uses the result for every record and hash in this attempt.
pub(in crate::pipeline) fn capture_replay_identity_in_txn(
    builder: &PipelineBuilder<'_>,
    rtxn: &heed::RoTxn<'_>,
) -> Result<RetrievalReplayIdentity> {
    let floors = builder.no_match_floors();
    let mut media_memory = builder
        .media_search
        .memory()
        .map(crate::host_memory::MachineMemory::empty_lease);
    let mut media_spaces = Vec::with_capacity(builder.media_search.len());
    if let Some(memory) = media_memory.as_mut() {
        memory.materialized(
            0,
            (media_spaces.capacity() as u64)
                .saturating_mul(std::mem::size_of::<MediaSpaceReplayIdentity>() as u64),
        );
    }
    for query in &builder.media_search {
        let Some(space) = embedding_space_in_txn(&builder.read, rtxn, &query.space_id)? else {
            return Err(Error::InvalidConfig(format!(
                "embedding space {} is not declared",
                query.space_id
            )));
        };
        if let Some(memory) = media_memory.as_mut() {
            memory.materialized(0, space.id.capacity() as u64);
        }
        media_spaces.push(MediaSpaceReplayIdentity {
            floors: media_space_floors(&floors, &space, None),
            kind_overrides: floors.keyed.get(&space.id).cloned().unwrap_or_default(),
            space,
        });
    }
    let analyzer_manifest_hash = builder
        .read
        .vault_meta()
        .get(rtxn, TEXT_ANALYZER_MANIFEST_HASH_KEY)?
        .map(|bytes| bytes.as_ref().to_vec());
    if let (Some(memory), Some(hash)) = (media_memory.as_mut(), analyzer_manifest_hash.as_ref()) {
        memory.materialized(0, hash.capacity() as u64);
    }
    let bm25_field_schema_hash = builder
        .read
        .vault_meta()
        .get(rtxn, TEXT_BM25_FIELD_SCHEMA_HASH_KEY)?
        .map(|bytes| bytes.as_ref().to_vec());
    if let (Some(memory), Some(hash)) = (media_memory.as_mut(), bm25_field_schema_hash.as_ref()) {
        memory.materialized(0, hash.capacity() as u64);
    }
    Ok(RetrievalReplayIdentity {
        media_spaces,
        analyzer_manifest_hash,
        bm25_field_schema_hash,
        _media_memory: media_memory,
    })
}
