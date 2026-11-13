//! Door for `tests/openapi_document_reuse.rs`: how many times this process
//! has assembled the served OpenAPI document.

/// How many times this process has assembled the OpenAPI document that
/// `GET /api/openapi.json` serves.
#[must_use]
pub fn assemblies() -> usize {
    crate::api::openapi_document_assemblies()
}
