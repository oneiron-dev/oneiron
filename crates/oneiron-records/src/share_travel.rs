//! Moved from `crates/oneiron/src/share_travel.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::share_travel::agent_pack_export::AgentPackExportFile;
pub use oneiron_authority::share_travel::BornWith;
pub use oneiron_authority::share_travel::BornWithField;
pub use oneiron_authority::share_travel::TravelChoice;
pub use oneiron_authority::share_travel::TravelKind;
pub use oneiron_verb_wire::share_travel::agent_pack::AgentPackKnowledge;
pub use oneiron_verb_wire::share_travel::agent_pack_export::AgentPackExportRequest;
pub use oneiron_verb_wire::share_travel::copy::CopyRefs;
pub use oneiron_verb_wire::share_travel::copy::CopyTravelChoice;
pub use oneiron_verb_wire::share_travel::guest_window::GuestWindowTravelNote;
pub use oneiron_verb_wire::share_travel::pack_notice::AGENT_PACK_IMPORT_DOUBLE_CHECK;
pub use oneiron_verb_wire::share_travel::pack_notice::OWNER_PACK_EXPORT_RECIPIENT_NOTICE;
pub use oneiron_verb_wire::share_travel::pack_notice::PACK_NOTICE_AUDIENCE;
pub use oneiron_verb_wire::share_travel::pack_notice::PACK_NOTICE_CHANNEL;
pub use oneiron_verb_wire::share_travel::pack_notice::PACK_NOTICE_VOICE;
pub use oneiron_verb_wire::share_travel::pack_notice::PACK_NOTICE_WORDING;
pub use oneiron_verb_wire::share_travel::pack_notice::PackNoticeWording;
use serde::Deserialize;
use serde::Serialize;

/// The born-with text one federation grant's windows carry to another vault,
/// with when the owner set it: the effective choice the grant travel door
/// reads (`Vault::federation_grant_travel`, FIX 2998).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantTravel {
    pub travel: TravelChoice,
    pub set_at: u64,
}
pub mod agent_pack_export;
