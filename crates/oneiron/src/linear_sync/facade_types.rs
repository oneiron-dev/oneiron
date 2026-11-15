//! The wire shapes of the TASK ↔ issue mirror doors (OF-427 C6, C7):
//! `vault.tasks.linear.mapping`, `vault.tasks.linear.mapping.edit` and
//! `vault.tasks.linear.provenance`.

/// A provenance page's rows when the caller names no limit, or zero.
pub const LINEAR_PROVENANCE_PAGE_DEFAULT: u32 = 50;

#[doc(hidden)]
pub use oneiron_verb_wire::linear_sync::facade_types::{
    LinearLinkView, LinearMappingEdit, LinearMappingEditReceipt, LinearMappingOp,
    LinearMappingRequest, LinearMappingView, LinearProvenanceEntry, LinearProvenancePage,
    LinearProvenanceRequest,
};
