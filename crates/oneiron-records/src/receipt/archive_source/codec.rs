//! Moved from `crates/oneiron/src/receipt/archive_source/codec.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
pub(super) use oneiron_store::receipt_identity::MAGIC;
pub(crate) use oneiron_store::receipt_identity::is_receipt_archive_source;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn invalid() -> Error {
    Error::InvalidConfig("archived receipt source is malformed, mismatched or retired".into())
}

pub fn is_inert_holder(bytes: &[u8]) -> bool {
    oneiron_store::write_envelope::claim_body::decode_claim_body(bytes, true).is_ok_and(|body| {
        body.source == Some(oneiron_contracts::claim::ClaimSource::Imported)
            && matches!(
                body.approval,
                oneiron_contracts::claim::ClaimApprovalStatus::Proposed
                    | oneiron_contracts::claim::ClaimApprovalStatus::Rejected
            )
    })
}
