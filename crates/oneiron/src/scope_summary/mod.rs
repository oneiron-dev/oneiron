//! Retained spawned sub-sessions and Dreamer-composed scope summaries.
//!
//! A summary stores its complete covers list. DerivedFrom is a capped index,
//! not the truth list. Merge headers use the normal claim write gate.

mod codec;
mod doors;
mod request;

pub use codec::{
    ScopeSummaryBody, SummarySourceMessage, decode_scope_summary_body, encode_scope_summary_body,
};
pub use doors::LandedHeader;
pub(crate) use doors::{
    body_covers_in_txn, merge_covers_in_txn, merge_summary_ref, merge_word_sources_in_txn,
    validate_summary_put,
};
pub(crate) use request::ComposedSummary;
pub use request::{ScopeSummaryQueued, ScopeSummaryRequest, ScopeSummaryTarget};

#[cfg(test)]
mod tests;
