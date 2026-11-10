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
use oneiron_store::scope_summary::codec;
mod derivation;
mod doors;
mod landing_reply;
mod landing_writer;
mod producer;
mod public;
mod public_types;
mod purpose;
pub use public_types::*;
mod request;
mod scrub;
mod self_model;
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
    defer_rederive, rederive_changed_in_txn, rederive_deferred, rederive_owed_in_txn,
    roll_back_summary_in_txn,
};
pub use purpose::SummaryPurpose;
pub use status::{ArcPendingStatus, ScopeSummaryResult, ScopeSummaryStatus, SummaryStale};
mod word_sources;

pub use codec::{
    ScopeSummaryBody, SummarySourceMessage, SummarySourceNote, decode_scope_summary_body,
    encode_scope_summary_body,
};
pub use doors::LandedHeader;
#[cfg(oneiron_test_support)]
pub(crate) use doors::mint_scope_summary_for_test;
pub(crate) use doors::{
    body_covers_in_txn, body_covers_through_in, merge_summary_ref, merge_word_sources_in_txn,
    merge_word_sources_through_in, turn_needs_summary_cover, validate_summary_put,
};
pub(crate) use landing_reply::{LandingReplyVerdict, validate_landing_reply_in};
pub(crate) use landing_writer::{check_landing_append, landing_writer, landing_writer_id};
pub(crate) use request::{ComposedSummary, ScopeSummaryPlan, decode_target};
pub use request::{ScopeSummaryQueued, ScopeSummaryRequest, ScopeSummaryTarget};
pub(crate) use scrub::scrub_withdrawn_copy_in_txn;
pub(crate) use self_model::SelfModelRead;
pub(crate) use session::{enqueue_session_summary_in_txn, session_summary_excluded};
pub(crate) use word_sources::{WordSources, word_sources_in, word_sources_through_in};

pub(crate) mod tables;
#[cfg(test)]
mod tests;
