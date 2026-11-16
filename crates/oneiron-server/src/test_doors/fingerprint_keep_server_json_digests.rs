//! Door for `tests/fingerprint_keep_server_json_digests.rs` (PLAN-UC-04 stage 6.4c): the
//! server's sorted-JSON digests that it takes in private code.

use oneiron_contracts::fingerprint::LegacyPurpose;
use serde::Serialize;

/// The training pin the question-head loader, the parity check and the held-out
/// evaluation take of `value`.
///
/// # Errors
///
/// A value with no sorted JSON.
pub fn training_pin(value: &impl Serialize) -> serde_json::Result<[u8; 32]> {
    crate::oneironer::training_pin(value)
}

/// The meeting-audio command's digest of `bytes` under `purpose`, as lowercase hex.
#[must_use]
pub fn meeting_audio_digest(purpose: LegacyPurpose, bytes: &[u8]) -> String {
    crate::commands::meeting_audio_digest_for_test(purpose, bytes)
}

/// [`crate::mcp::mcp_page_argument_digest`] of a payload whose
/// `arguments.spec.content_base64` its host holds outside it.
///
/// # Errors
///
/// What `write_content` returns; a payload that does not name the content under
/// `arguments.spec`.
pub fn mcp_page_argument_digest_held<T: Serialize>(
    arguments: &T,
    content_len: u64,
    write_content: impl FnOnce(&mut blake3::Hasher) -> std::io::Result<()>,
) -> std::io::Result<[u8; 32]> {
    crate::mcp::mcp_page_argument_digest_held(arguments, content_len, write_content)
}
