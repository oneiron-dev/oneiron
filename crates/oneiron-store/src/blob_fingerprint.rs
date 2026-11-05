//! Entity-local four-rung birth fingerprints over the ingest pipeline's own segments.
use crate::document_segments::DocsSegment;
use crate::document_segments::docs_semantic_segments;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FingerprintRung {
    Asset,
    TextRoot,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlobBirthDecision {
    Unchanged(FingerprintRung),
    Changed {
        sections: Vec<String>,
        blocks: Vec<String>,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobFingerprintSnapshot {
    pub asset_hash: [u8; 32],
    pub text_hash: [u8; 32],
    pub sections: BTreeMap<String, [u8; 32]>,
    pub blocks: BTreeMap<String, [u8; 32]>,
}
/// One section's hash and each of its blocks' hashes, by block id. The tree
/// holds hashes and structural ids only, never source text.
#[derive(Clone, Serialize, Deserialize)]
pub struct Section {
    pub hash: [u8; 32],
    pub blocks: BTreeMap<String, [u8; 32]>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Tree {
    pub asset_hash: [u8; 32],
    pub text_hash: [u8; 32],
    pub sections: BTreeMap<String, Section>,
}
