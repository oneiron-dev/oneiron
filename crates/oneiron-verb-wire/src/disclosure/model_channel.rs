//! Moved from `crates/oneiron/src/disclosure/model_channel.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::federation::Sensitivity;
use oneiron_store::write_envelope::claim_body::ClaimBody;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureBand {
    Public,
    Private,
    Sensitive,
    Restricted,
}

impl DisclosureBand {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
            Self::Sensitive => "sensitive",
            Self::Restricted => "restricted",
        }
    }

    fn sensitivity(self) -> Sensitivity {
        match self {
            Self::Public => Sensitivity::Public,
            Self::Private => Sensitivity::Private,
            Self::Sensitive => Sensitivity::Sensitive,
            Self::Restricted => Sensitivity::Restricted,
        }
    }

    pub fn of_claim(body: &ClaimBody) -> Self {
        match oneiron_store::write_envelope::claim_body::claim_sensitivity_band(body) {
            Some(0) => Self::Public,
            Some(1) => Self::Private,
            Some(2) => Self::Sensitive,
            _ => Self::Restricted,
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

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisclosureCeilingSet {
    pub connection: String,
    #[serde(default)]
    pub class: Option<DisclosureDataClass>,
    pub ceiling: DisclosureBand,
}

/// None means no dial: class falls back to connection, then actor inference.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisclosureCeilingView {
    pub connection: String,
    pub class: Option<DisclosureDataClass>,
    pub ceiling: Option<DisclosureBand>,
}
