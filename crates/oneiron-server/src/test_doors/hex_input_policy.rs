//! Doors for `tests/hex_input_policy_server.rs` (UC-07 PR 6, HEX-CASE-POLICY = A):
//! whether two hex spellings read through the production decoders, each as
//! its door reads it. Thin wrappers over the named items only; every
//! assertion stays in the test file.

/// The rows of an accounts file's `text` (`embedder::serve::parse_rows`):
/// how many, or why not as text.
///
/// # Errors
///
/// What `parse_rows` refused, as text.
pub fn embedder_accounts_rows(text: &str) -> Result<usize, String> {
    crate::embedder::serve::parse_rows(text)
        .map(|rows| rows.len())
        .map_err(|error| error.to_string())
}

/// Whether `header` reads as a Linear signature
/// (`linear_host::signature_bytes`).
#[must_use]
pub fn linear_signature_reads(header: &str) -> bool {
    crate::linear_host::signature_bytes(header).is_some()
}
