//! Origin authority, checkout binding, export, publication, register and mirror records.
//! `OriginRepoRequest` is the first of its records.
//! These are local definitions; `memory::origin_doors` re-exports them.

#[doc(hidden)]
pub use oneiron_verb_wire::memory::origin_doors::types::{
    CheckoutDoorBindRequest, CheckoutDoorBinding, CodeExportRequest, CodeExportResult,
    OriginAuthoritySetRequest, OriginAuthorityView, OriginMirrorView, OriginPublicationState,
    OriginPublicationView, OriginPublicationsRequest, OriginPublicationsView,
    OriginRegisterRequest, OriginRegistered, OriginRepoRequest,
};
