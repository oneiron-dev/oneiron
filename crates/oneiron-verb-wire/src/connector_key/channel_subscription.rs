//! Moved from `crates/oneiron/src/connector_key/channel_subscription.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

/// One agent's standing subscription to a built-in channel's messages.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct ChannelMessageSubscription {
    pub subscription: String,
    pub connector_key: String,
    pub connector: String,
    pub agent: String,
    /// The subscription was already standing; nothing new was written.
    pub existing: bool,
}
