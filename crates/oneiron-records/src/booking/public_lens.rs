//! Moved from `crates/oneiron/src/booking/public_lens.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_verb_wire::booking::constraint::EventTypeKey;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value as JsonValue;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EventTypeCard {
    pub key: EventTypeKey,
    pub title: String,
    pub duration_min: u32,
    pub description: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstraintFieldConfig {
    pub enabled: bool,
    pub placeholder: String,
}

/// Transport only. No token names, defaults, or visual rules belong here.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ThemeTokens(pub JsonValue);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BookingPageModelError {
    NonSlotsProjection,
    InvalidSlotMask,
    EmptyOwnerDisplay,
    EmptyEventTypes,
    UnlistedEventType,
    InvalidLanding,
    InvalidPreview,
    InvalidTimeZone,
}

/// A handle supplied by the published-page capability resolver, never an entity id.
/// This envelope does not mint, resolve, or grant authority to a token.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublicBookingPageToken(pub String);

impl PublicBookingPageToken {
    /// Derive the existing opaque page address. This grants no authority:
    /// public serving still requires a live owner-authored publication claim.
    #[must_use]
    pub fn for_page(page_ref: oneiron_contracts::entity_id::EntityId) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron.booking.agent_api.page_token.v1\0");
        hasher.update(page_ref.as_bytes());
        let hex = hasher.finalize().to_hex();
        Self(format!("bkp_{}", &hex.as_str()[..32]))
    }
}
