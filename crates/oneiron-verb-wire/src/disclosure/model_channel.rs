//! Moved from `crates/oneiron/src/disclosure/model_channel.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureDataClass {
    Names,
    Dates,
    Contact,
    Ids,
    Health,
}

impl DisclosureDataClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Names => "names",
            Self::Dates => "dates",
            Self::Contact => "contact",
            Self::Ids => "ids",
            Self::Health => "health",
        }
    }
}

/// One registry dial. Omit class to address the whole connection.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisclosureCeilingRequest {
    /// The credential-bound connection, e.g. agent:<principal hex>.
    pub connection: String,
    #[serde(default)]
    pub class: Option<DisclosureDataClass>,
}
