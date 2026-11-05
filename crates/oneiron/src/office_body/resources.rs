//! Office error mapping over the document-resource port.

use oneiron_docedit::resource::ResourceRefusal;

pub use crate::entity_doc::document_resources::{
    DocumentMemory, document_resources, document_resources_until, register_document_memory,
};
pub(crate) use crate::entity_doc::document_resources::{document_refused, machine_memory_refused};

/// A DOCX read's or projection's failure as the engine's error: a resource
/// refusal as itself ([`document_refused`]), a ceiling the package passed as
/// a refusal naming it (FIX 5354), any other one invalid under `message`.
pub(crate) fn docx_error(
    error: &oneiron_docedit::DoceditError,
    message: &str,
) -> crate::error::Error {
    if let Some(refusal) = error.resource() {
        return document_refused(refusal);
    }
    error.parse_limit_refusal().map_or_else(
        || super::invalid(message),
        |refusal| crate::error::Error::Refused(refusal.to_owned()),
    )
}

/// A document read's failure as the engine's error: a resource refusal as
/// itself ([`document_refused`]), any other one invalid under `message`.
pub(crate) fn document_error(
    refusal: Option<ResourceRefusal>,
    message: &str,
) -> crate::error::Error {
    refusal.map_or_else(|| super::invalid(message), document_refused)
}
