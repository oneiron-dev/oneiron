//! Moved from `crates/oneiron/src/surface_event/inbound.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Provider app a normalized inbound event came from.
///
/// Closed by ruling (OF-247 R4 channel reconciliation): adapters map their
/// provider key onto one of these, and an unmapped key is an adapter defect,
/// not an open extension point.
///
/// The wire spelling is the provider channel key verbatim, so
/// [`SurfaceSourceApp::from_channel_key`] round-trips. The two acronym
/// variants are renamed explicitly because serde's mechanical snake_case
/// inserts a leading underscore on the interior capital, producing
/// `i_message` / `linked_in` rather than the pinned `imessage` / `linkedin`
/// channel keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceSourceApp {
    Email,
    Slack,
    Discord,
    Web,
    Voice,
    #[serde(rename = "imessage")]
    IMessage,
    Line,
    Telegram,
    #[serde(rename = "linkedin")]
    LinkedIn,
}

impl SurfaceSourceApp {
    /// Derives the source app from a raw provider channel key.
    ///
    /// The raw key stays authoritative for identity assignment lookups; this
    /// is the closed projection adapters get for free through
    /// [`InboundSurfaceEventInput::new`].
    #[must_use]
    pub fn from_channel_key(channel: &str) -> Option<Self> {
        match channel {
            "email" => Some(Self::Email),
            "slack" => Some(Self::Slack),
            "discord" => Some(Self::Discord),
            "web" => Some(Self::Web),
            "voice" => Some(Self::Voice),
            "imessage" | "imessage_bridge" | "imessage_mfb" => Some(Self::IMessage),
            "line" => Some(Self::Line),
            "telegram" => Some(Self::Telegram),
            "linkedin" => Some(Self::LinkedIn),
            _ => None,
        }
    }
}

/// Non-message interaction kinds carried by an inbound surface event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceInteractionKind {
    Reaction,
    CardCompletion,
    Dwell,
    Tap,
    /// The counterparty asked for no more messages on this channel (a STOP
    /// reply, or the provider's own opt-out signal).
    OptOut,
}

/// The provider facts of one reaction interaction. The generation is the
/// provider's identity for one add, never the delivery id; a new add carries
/// its occurrence time, an echo of our own reaction names the original claim,
/// and a removal carries only the generation it removes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceReaction {
    pub glyph: String,
    pub external_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurred_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_ref: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub removed: bool,
}

/// Downstream flow a routed surface event hands off to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceEventDispatchRoute {
    /// A CC intake hands the thread to coordination proposal/confirmation, not execution.
    ProposeConfirm,
    ActorSelf,
    ObservedSourceEnrichment,
}

pub fn hash_hex(raw_hash: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in raw_hash {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

/// Stable rejection reasons for inbound SurfaceEvent routing receipts.
///
/// Closed on purpose, like [`SurfaceSourceApp`]: adapters branch on the reason
/// and the `/v1/core` schema enumerates these four spellings, so a projection
/// of this enum onto a wire contract must stay exhaustive. Sealing it would
/// only buy semver headroom this pre-release crate has no consumer for, at the
/// cost of letting a fifth reason ship a schema that silently lies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InboundSurfaceRejectionReason {
    UnknownReceivingIdentity,
    NonAgentBoundIdentity,
    InactiveReceivingIdentity,
    TombstonedReceivingIdentity,
}

impl InboundSurfaceRejectionReason {
    /// Stable string used in adapter logs and receipts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownReceivingIdentity => "unknown_receiving_identity",
            Self::NonAgentBoundIdentity => "non_agent_bound_identity",
            Self::InactiveReceivingIdentity => "inactive_receiving_identity",
            Self::TombstonedReceivingIdentity => "tombstoned_receiving_identity",
        }
    }
}
