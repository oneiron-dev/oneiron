//! The native manifest chunks, in their original serialization and error order.

use super::RecoveryManifest;
use crate::error::Result;
use crate::recovery::canonical::{CanonicalSnapshot, pack};
use std::collections::BTreeMap;

#[derive(Default)]
pub(in crate::recovery) struct ManifestChunks {
    stage: Stage,
    next_document: usize,
    chunks: BTreeMap<String, [u8; 32]>,
}

#[derive(Default)]
enum Stage {
    #[default]
    EntityBlobs,
    BaseEdges,
    Tombstones,
    EntityDocuments,
    DocumentHeads,
    HeadMoveReceipts,
    NoteForks,
    NoteProposals,
    RowBirths,
    WithdrawnCutoffs,
    AssetBodyRefs,
    SourceAudiences,
    SchemaManifest,
    ContainerManifests,
    Documents,
    Complete,
}

impl ManifestChunks {
    pub(in crate::recovery) fn advance(
        &mut self,
        snapshot: &CanonicalSnapshot,
        max_rows: usize,
    ) -> Result<bool> {
        for _ in 0..max_rows.max(1) {
            if self.advance_row(snapshot)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(in crate::recovery) fn into_manifest(self, snapshot_blake3: [u8; 32]) -> RecoveryManifest {
        RecoveryManifest {
            snapshot_blake3,
            chunks: self.chunks,
        }
    }

    fn advance_row(&mut self, snapshot: &CanonicalSnapshot) -> Result<bool> {
        let (key, bytes, next_stage) = match self.stage {
            Stage::EntityBlobs => ("entities", pack(&snapshot.entity_blobs)?, Stage::BaseEdges),
            Stage::BaseEdges => ("edges", pack(&snapshot.base_edges)?, Stage::Tombstones),
            Stage::Tombstones => (
                "tombstones",
                pack(&snapshot.tombstones)?,
                Stage::EntityDocuments,
            ),
            Stage::EntityDocuments => (
                "entity_documents",
                pack(&snapshot.entity_documents)?,
                Stage::DocumentHeads,
            ),
            Stage::DocumentHeads => (
                "document_heads",
                pack(&snapshot.document_heads)?,
                Stage::HeadMoveReceipts,
            ),
            Stage::HeadMoveReceipts => (
                "head_move_receipts",
                pack(&snapshot.head_move_receipts)?,
                Stage::NoteForks,
            ),
            Stage::NoteForks => (
                "note_forks",
                pack(&snapshot.note_forks)?,
                Stage::NoteProposals,
            ),
            Stage::NoteProposals => (
                "note_proposals",
                pack(&snapshot.note_proposals)?,
                Stage::RowBirths,
            ),
            Stage::RowBirths => (
                "row_births",
                pack(&snapshot.row_births)?,
                Stage::WithdrawnCutoffs,
            ),
            Stage::WithdrawnCutoffs => (
                "withdrawn_cutoffs",
                pack(&snapshot.withdrawn_cutoffs)?,
                Stage::AssetBodyRefs,
            ),
            Stage::AssetBodyRefs => (
                "asset_body_refs",
                pack(&snapshot.asset_body_refs)?,
                Stage::SourceAudiences,
            ),
            Stage::SourceAudiences => (
                "source_audiences",
                pack(&snapshot.source_audiences)?,
                Stage::SchemaManifest,
            ),
            Stage::SchemaManifest => (
                "schema",
                pack(&snapshot.schema_manifest)?,
                Stage::ContainerManifests,
            ),
            Stage::ContainerManifests => (
                "containers",
                pack(&snapshot.container_manifests)?,
                Stage::Documents,
            ),
            Stage::Documents => {
                let Some(document) = snapshot.doc_snapshots.get(self.next_document) else {
                    self.stage = Stage::Complete;
                    return Ok(true);
                };
                let key = document.key();
                self.add(&key, pack(document)?);
                self.next_document += 1;
                return Ok(false);
            }
            Stage::Complete => return Ok(true),
        };
        self.add(key, bytes);
        self.stage = next_stage;
        Ok(false)
    }

    fn add(&mut self, key: &str, bytes: Vec<u8>) {
        self.chunks
            .insert(key.to_owned(), *blake3::hash(&bytes).as_bytes());
    }
}
