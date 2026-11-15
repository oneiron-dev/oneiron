//! Moved from `crates/oneiron/src/skill_hub/pack_catalog/setup_session.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use heed::RwTxn;
pub use oneiron_verb_wire::skill_hub::pack_catalog::setup_session::PackSetupAnswer;
pub use oneiron_verb_wire::skill_hub::pack_catalog::setup_session::PackSetupCheck;
pub use oneiron_verb_wire::skill_hub::pack_catalog::setup_session::PackSetupConnectionState;
pub use oneiron_verb_wire::skill_hub::pack_catalog::setup_session::PackSetupPermissionState;
pub use oneiron_verb_wire::skill_hub::pack_catalog::setup_session::PackSetupSecretState;
use serde::Deserialize;
use serde::Serialize;

/// The stored session: refs and check results, never a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSetupSession {
    pub session_id: String,
    pub principal_ref: String,
    pub pack_name: String,
    pub source_id: String,
    pub content_hash: String,
    /// Digest of the permission card the exact source computes. A card that
    /// no longer matches ends the session.
    pub permissions_hash: String,
    pub custody: Vec<PackSetupCustodyRef>,
    pub grants: Vec<PackSetupGrantRef>,
    pub keys: Vec<PackSetupKeyRef>,
    pub checks: Vec<PackSetupCheckRecord>,
    pub opened_at: u64,
    pub updated_at: u64,
}

/// The custody record a declared credential name resolved to when pinned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSetupCustodyRef {
    pub connection: String,
    pub secret: String,
    pub custody_id: String,
    pub generation: u32,
}

/// The standing consent grant one allowed permission minted, and the Gate
/// decision its receipt was recorded under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSetupGrantRef {
    pub connection: String,
    pub permission: String,
    pub grant_ref: String,
    pub decision_id: String,
    pub granted_at: u64,
}

/// A registered connector key bound to a connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSetupKeyRef {
    pub connection: String,
    pub key_id: String,
}

/// One connection's latest check, over the grants, custody and key it ran
/// against (`basis`). A basis that moved makes the result stale.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSetupCheckRecord {
    pub connection: String,
    pub verified: bool,
    pub account: Option<String>,
    /// The provider's own stable id for the account (a Slack team id, a LINE
    /// bot user id), when its check reports one. A served host binds inbound
    /// provider events to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_account: Option<String>,
    pub evidence: Option<String>,
    pub reason: Option<String>,
    pub basis: String,
    pub checked_at: u64,
}
