//! Door for `tests/fingerprint_keep_codec_digests.rs` (PLAN-UC-04 stage 6.1c): a calendar
//! connector literal's digest, which the engine computes in private code. The test
//! reaches the section manifest digest, the plugin suggestion key and the project
//! revision hash through their public paths.

/// The digest of `value`'s calendar connector literal encoding.
///
/// # Errors
/// When `value` does not encode.
pub fn calendar_literal_digest(value: &impl serde::Serialize) -> crate::Result<[u8; 32]> {
    crate::calendar::connectors::literal_digest_for_test(value)
}
