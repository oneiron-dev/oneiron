//! Moved from `crates/oneiron/src/channel_identity/lifecycle.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

/// ChannelIdentity lifecycle state as it appears on the wire (OF-347 R3/R5).
///
/// A PROJECTION of [`SelfHeldLifecycle`] / [`DelegatedLifecycle`], never the
/// state itself: it is what the codec writes, what `channel_identity.state`
/// claims carry, and what lifecycle receipts name. It has no edge table —
/// admission belongs to the machine that owns the row.
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
pub enum ChannelIdentityState {
    Requested,
    PendingFulfillment,
    Active,
    Rotating,
    Released,
    Quarantine,
    Tombstone,
}

impl ChannelIdentityState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::PendingFulfillment => "pending_fulfillment",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Released => "released",
            Self::Quarantine => "quarantine",
            Self::Tombstone => "tombstone",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "requested" => Some(Self::Requested),
            "pending_fulfillment" => Some(Self::PendingFulfillment),
            "active" => Some(Self::Active),
            "rotating" => Some(Self::Rotating),
            "released" => Some(Self::Released),
            "quarantine" => Some(Self::Quarantine),
            "tombstone" => Some(Self::Tombstone),
            _ => None,
        }
    }
}
