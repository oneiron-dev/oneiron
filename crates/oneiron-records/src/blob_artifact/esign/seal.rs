//! Moved from `crates/oneiron/src/blob_artifact/esign/seal.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::blob_artifact::esign::model::*;
use oneiron_store::blob_artifact::esign::sealer::SealProfileEvidence;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", content = "data", rename_all = "snake_case")]
pub enum EsignSealAttemptResult {
    Sealed(SealedDocument),
    VerificationFailed { verify_reasons: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedItem {
    pub original_artifact: String,
    pub original_version: u64,
    pub sealed_artifact: String,
    pub sealed_version: u64,
    pub sha256: [u8; 32],
    pub profile: SealProfileEvidence,
    pub active_content: super::sealer::SealActiveContentFacts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedDocument {
    pub document: String,
    pub attempt_ref: String,
    pub audit_chain_sha256: [u8; 32],
    pub items: Vec<SealedItem>,
    pub rejected: bool,
}
