//! Moved from `crates/oneiron/src/channel_identity/binding.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

/// Async fulfillment lane for PENDING_FULFILLMENT.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ChannelIdentityFulfillment {
    Api,
    Manual,
    Review,
}

impl ChannelIdentityFulfillment {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::Manual => "manual",
            Self::Review => "review",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "api" => Some(Self::Api),
            "manual" => Some(Self::Manual),
            "review" => Some(Self::Review),
            _ => None,
        }
    }
}
