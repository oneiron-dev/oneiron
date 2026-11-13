//! Door for `tests/openapi_document_reuse.rs` and
//! `tests/openapi_document_precompute.rs`: how many times this process has
//! assembled the served OpenAPI document, and the precompute `serve` starts.

/// How many times this process has assembled the OpenAPI document that
/// `GET /api/openapi.json` serves.
#[must_use]
pub fn assemblies() -> usize {
    crate::api::openapi_document_assemblies()
}

/// Starts the precompute `serve` starts and hands back its thread.
///
/// # Errors
///
/// The OS refused the thread.
pub fn spawn_precompute() -> std::io::Result<std::thread::JoinHandle<()>> {
    crate::api::spawn_openapi_document_precompute()
}

/// Diagnostic, pin only: the assembly's stages, timed in milliseconds.
#[must_use]
pub fn stage_ms() -> Vec<(&'static str, f64)> {
    crate::api::openapi_document_stage_ms()
}
