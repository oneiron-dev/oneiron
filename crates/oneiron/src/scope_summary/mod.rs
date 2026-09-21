//! Retained spawned sub-sessions and caller-composed scope summaries.
//!
//! A summary stores its complete covers list. DerivedFrom is a capped index,
//! not the truth list. Merge headers use the normal claim write gate.

mod codec;
mod doors;

pub use codec::{ScopeSummaryBody, decode_scope_summary_body, encode_scope_summary_body};
pub use doors::LandedHeader;

#[cfg(test)]
mod tests;
