//! Door for `tests/fingerprint_keep_custody_digests.rs` (PLAN-UC-04 stage 6.1b): a custody
//! input witness's digests, a subject restore review's row digest and a key custody head's
//! compartment commitments, which the engine computes in private code.

use oneiron_contracts::fingerprint::LegacyPurpose;

/// A custody input witness digest of `bytes` under `purpose`.
#[must_use]
pub fn custody_witness_digest(purpose: LegacyPurpose, bytes: &[u8]) -> [u8; 32] {
    crate::secret_custody::custody_witness_digest_for_test(purpose, bytes)
}

/// The digest a subject restore review carries of an entity's stored raw row `bytes`.
#[must_use]
pub fn archive_review_digest(bytes: &[u8]) -> [u8; 32] {
    crate::subject_model::archive_review_digest_for_test(bytes)
}

/// A key custody head's commitment under `purpose` over `wire`'s canonical encoding.
///
/// # Errors
/// When `wire` does not encode.
pub fn custody_head_digest(
    purpose: LegacyPurpose,
    wire: &impl serde::Serialize,
) -> crate::Result<[u8; 32]> {
    crate::store::custody_head_digest_for_test(purpose, wire)
}
