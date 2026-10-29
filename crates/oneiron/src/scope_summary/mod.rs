//! Retained spawned sub-sessions and Dreamer-composed scope summaries.
//!
//! A summary stores its complete covers list. DerivedFrom is a capped index,
//! not the truth list. Merge headers use the normal claim write gate.

mod arc;
mod arc_completion;
mod arc_gate;
mod arc_sources;
mod arc_validation;
mod arc_work;
mod arc_work_store;
mod codec;
mod derivation;
mod doors;
mod producer;
mod public;
mod public_types;
mod purpose;
pub use public_types::*;
mod request;
mod session;
mod status;
pub(crate) use arc_gate::{ArcPendingCause, next_arc_due_in_txn, sweep_due_arcs_in_txn};
pub(crate) use arc_sources::ArcSources;
pub(crate) use arc_work::{
    ArcChildPlan, ArcChildRow, ArcLineRef, ArcManifest, ArcMember, ArcPins, ArcRange, ArcReduceRow,
    ArcStepRef, ArcWorkState, ChildMode, MemberKind, arc_member_kinds, check_manifest,
    owned_by_parts, result_digest,
};
pub use derivation::{
    ScopeSummaryMetadata, SummaryDerivation, SummaryLineSources, SummaryLineSpan,
    SummarySourceVersion,
};
pub(crate) use derivation::{
    defer_rederive, rederive_changed_in_txn, rederive_deferred, roll_back_summary_in_txn,
};
pub use purpose::SummaryPurpose;
pub use status::{ArcPendingStatus, ScopeSummaryResult, ScopeSummaryStatus, SummaryStale};
mod word_sources;

pub use codec::{
    ScopeSummaryBody, SummarySourceMessage, SummarySourceNote, decode_scope_summary_body,
    encode_scope_summary_body,
};
pub use doors::LandedHeader;
pub(crate) use doors::{
    body_covers_in_txn, merge_summary_ref, merge_word_sources_in_txn, validate_summary_put,
};
pub(crate) use request::{ComposedSummary, ScopeSummaryPlan, decode_target};
pub use request::{ScopeSummaryQueued, ScopeSummaryRequest, ScopeSummaryTarget};
pub(crate) use session::enqueue_session_summary_in_txn;
pub(crate) use word_sources::{WordSources, word_sources_in, word_sources_through_in};

#[cfg(test)]
mod tests;
