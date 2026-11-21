//! Moved from `crates/oneiron/src/store/blob_fingerprint.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
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
