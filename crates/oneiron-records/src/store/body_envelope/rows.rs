//! Moved from `crates/oneiron/src/store/body_envelope/rows.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use getrandom::SysRng;
use heed::RoTxn;
use heed::RwTxn;
use oneiron_base::error::Error;
use oneiron_crypto::SuiteId;
use serde::Deserialize;
use serde::Serialize;
use std::sync::Arc;
use zeroize::Zeroizing;

pub const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;

pub const EPOCH: u64 = 1;

/// How a sealed body file is cut into envelopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BodyFileFormat {
    /// E0 chunks of 64 KiB of the body each, then a terminal record.
    #[serde(rename = "e0_chunks_64k")]
    E0Chunks64k,
}

impl BodyFileFormat {
    const fn code(self) -> u8 {
        match self {
            Self::E0Chunks64k => 1,
        }
    }
}

pub const FORMAT: BodyFileFormat = BodyFileFormat::E0Chunks64k;

pub fn corrupt() -> Error {
    Error::CorruptedIndex("body file key row")
}
