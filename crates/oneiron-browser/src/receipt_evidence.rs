//! An effect receipt's screenshot kept past its session (FIX 2150). A
//! session holds its last 16 images and drops them all when its guest goes,
//! so the host's sink keeps a receipt's masked pixels the moment the receipt
//! is made, and the receipt names where they are. A keep that fails says so:
//! the effect still happened, and its receipt still stands.
use serde::{Deserialize, Serialize};

use crate::EffectReceipt;

/// Where a receipt's screenshot was kept, or why it was not.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ReceiptEvidence {
    /// One blob artifact version holds the pixels.
    Kept {
        artifact_ref: String,
        version: u64,
        /// BLAKE3 of the pixels, in hex.
        content_hash: String,
    },
    /// The host could not keep them (the caller may not write, or the
    /// write failed): they last only while the session holds them.
    NotKept { code: String },
}

/// The host's keeper of receipt screenshots, given to a session per call.
pub trait ReceiptEvidenceSink: Send {
    /// Keep `png`, the screenshot `receipt` names.
    fn keep(&mut self, receipt: &EffectReceipt, png: &[u8]) -> ReceiptEvidence;
}
