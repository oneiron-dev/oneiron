//! Moved from `crates/oneiron/src/calendar/inbox_card.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_lens_wire::lens::generated_ui::GeneratedLens;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// Which card a row holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalendarCardKind {
    /// The T-45 prep pack.
    Prep,
    /// The check-in after the meeting's end and grace.
    CheckIn,
}

impl CalendarCardKind {
    /// Stable token: the row key's kind and the INBOX handle's prefix.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prep => "meeting_prep",
            Self::CheckIn => "meeting_check_in",
        }
    }

    fn from_token(token: &str) -> Option<Self> {
        match token {
            "meeting_prep" => Some(Self::Prep),
            "meeting_check_in" => Some(Self::CheckIn),
            _ => None,
        }
    }
}

/// Where a check-in's one morning re-ask stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckInReAsk {
    /// Asked again at `at`, unless an answer or a dismissal comes first.
    Planned { at: u64 },
    /// Asked again at `at`; never asked a third time.
    Asked { at: u64 },
    /// Dismissed before its morning, found so at `at`; never asked again.
    Cancelled { at: u64 },
}

impl CheckInReAsk {
    /// When the re-ask settled; `None` while it is still planned.
    const fn settled_at(self) -> Option<u64> {
        match self {
            Self::Planned { .. } => None,
            Self::Asked { at } | Self::Cancelled { at } => Some(at),
        }
    }
}

/// One meeting card as the pass delivered it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarInboxCard {
    pub kind: CalendarCardKind,
    pub event_ref: EntityId,
    /// Who the card is for: `None` for the vault's owners (a meeting the
    /// vault's own calendars hold); `Some` for the PERSON whose own pack
    /// calendar landed the meeting, the card built on their lane and shown
    /// to them alone (FIX 16308).
    pub recipient: Option<EntityId>,
    /// The EVENT's start the card was built for, unix seconds UTC.
    pub scheduled_start_utc: u64,
    /// The EVENT's end the card was built for, unix seconds UTC.
    pub scheduled_end_utc: u64,
    /// When the card was first delivered.
    pub delivered_at: u64,
    /// When the card was last put in front of the owners: its delivery, or
    /// its re-ask. The INBOX row's time.
    pub asked_at: u64,
    /// The card as delivered. `None` on a prep wake that fired and found
    /// nothing to say, or whose meeting was cancelled since: the wake ran,
    /// and the owners are shown nothing.
    pub lens: Option<GeneratedLens>,
    /// Every vault row the delivered lens copied, the EVENT itself excluded:
    /// the prep pack's cited rows. Empty on a check-in, which copies none,
    /// and on a card with no lens.
    pub source_refs: BTreeSet<EntityId>,
    /// A check-in's one morning re-ask; `None` on a prep card.
    pub re_ask: Option<CheckInReAsk>,
}

impl CalendarInboxCard {
    /// The INBOX handle: kind, EVENT and start, so a moved meeting's card is
    /// a new row and a read mark on the old one never closes it.
    #[must_use]
    pub fn item_id(&self) -> String {
        format!(
            "{}:{}:{}",
            self.kind.as_str(),
            self.event_ref.to_hex(),
            self.scheduled_start_utc
        )
    }
}
