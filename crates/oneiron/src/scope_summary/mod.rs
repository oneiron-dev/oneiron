//! Retained spawned sub-sessions and Dreamer-composed scope summaries.
//!
//! A summary stores its complete covers list. DerivedFrom is a capped index,
//! not the truth list. Merge headers use the normal claim write gate.

mod codec;
mod derivation;
mod doors;
mod producer;
mod purpose;
mod request;
mod status;
pub use derivation::{ScopeSummaryMetadata, SummaryDerivation, SummarySourceVersion};
pub(crate) use derivation::{rederive_changed_in_txn, roll_back_summary_in_txn};
pub use purpose::SummaryPurpose;
pub use status::{ScopeSummaryResult, ScopeSummaryStatus};
mod word_sources;

pub use codec::{
    ScopeSummaryBody, SummarySourceMessage, decode_scope_summary_body, encode_scope_summary_body,
};
pub use doors::LandedHeader;
pub(crate) use doors::{
    body_covers_in_txn, merge_summary_ref, merge_word_sources_in_txn, validate_summary_put,
};
pub(crate) use request::ComposedSummary;
pub use request::{ScopeSummaryQueued, ScopeSummaryRequest, ScopeSummaryTarget};
pub(crate) use word_sources::{WordSources, word_sources_in};

#[cfg(test)]
mod tests;
