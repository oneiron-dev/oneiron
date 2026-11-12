//! Moved from `crates/oneiron/src/share_travel/pack_notice.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::settings::destination::RecipientLimit;
use crate::settings::destination::ReleaseHold;
use oneiron_authority::share_travel::BornWith;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::record_layout::EntityMetadataHeader;
use oneiron_store::write_envelope::provenance::made_by::MadeByInputRole;
use oneiron_wake_contract::settings::destination::ReadDestination;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// The owner's own export carried a world his recipient choice would keep
/// from where the pack goes.
pub const OWNER_PACK_EXPORT_RECIPIENT_NOTICE: &str = "owner_pack_export_recipient_notice";

/// An import lands in a world whose current setting does not cover this
/// install's machine.
pub const AGENT_PACK_IMPORT_DOUBLE_CHECK: &str = "agent_pack_import_double_check";

/// The channel every pack travel notice is said on.
pub const PACK_NOTICE_CHANNEL: &str = "share_travel";

/// The voice: the system's, never an agent's or a persona's.
pub const PACK_NOTICE_VOICE: &str = "system";

/// The audience: the owner alone.
pub const PACK_NOTICE_AUDIENCE: &str = "owner";

/// The default words of each notice, the one wording hook (CALLS `FIX 5493
/// notice wording`). `{world_name}` and `{reason}` are filled in; a host
/// that says it otherwise renders from the notice's typed fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackNoticeWording {
    /// The owner's own export.
    pub export: &'static str,
    /// An import, said before it lands and kept on its receipt.
    pub import: &'static str,
    /// What an import's check reads, said after it: the sender's world
    /// settings never travel with a pack (CALLS `FIX 5493 import scope`).
    pub import_scope: &'static str,
    /// `{world_name}` for a world whose body names none a read may show.
    pub unnamed: &'static str,
}

/// The wording every pack travel notice is rendered in.
pub const PACK_NOTICE_WORDING: PackNoticeWording = PackNoticeWording {
    export: "Included {world_name} in your export. Your recipient choice would keep it from \
             this destination: {reason}.",
    import: "Please double-check {world_name} before import: {reason}. The import will continue.",
    import_scope: "The sender's world settings do not travel with a pack; this is this world's \
                   current setting for this machine.",
    unnamed: "an unnamed world",
};
