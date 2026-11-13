//! Moved from `crates/oneiron/src/llm/seat.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::llm::seat::policy::SeatPrecedence;
use oneiron_base::error::Error;
use serde::Deserialize;
use serde::Serialize;

pub fn invalid(reason: impl Into<String>) -> Error {
    Error::InvalidConfig(reason.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DescriptionSource {
    Owner,
    Measured,
    Benchmarks,
    Vendor,
}
pub mod policy;
