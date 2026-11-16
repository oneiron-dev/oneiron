//! Moved from `crates/oneiron/src/recovery/checkpoint/payload/seal.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_store::key_custody::identity::CustodyKind;

pub fn corrupt() -> Error {
    CustodyKind::CheckpointPayload.corrupt()
}
