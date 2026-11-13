//! Moved from `crates/oneiron/src/skill_hub/pack_catalog/setup_session.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PackSetupConnectionState {
    pub id: String,
    pub secrets: Vec<PackSetupSecretState>,
    pub permissions: Vec<PackSetupPermissionState>,
    pub connector_key: Option<String>,
    pub check: PackSetupCheck,
    /// Credentials stored, required permissions allowed, and a check that
    /// passed against exactly these.
    pub ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PackSetupSecretState {
    pub name: String,
    /// A live custody record holds the name.
    pub stored: bool,
    /// The live custody record the view read the name to, in the same
    /// transaction; a host lists it beside the view. Never on the wire, and
    /// never a value.
    #[serde(skip)]
    pub custody_id: Option<EntityId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PackSetupPermissionState {
    pub id: String,
    pub granted: bool,
    pub grant_ref: Option<String>,
    pub decision_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PackSetupCheck {
    Unchecked,
    Verified {
        account: String,
        evidence: String,
        checked_at: u64,
    },
    Failed {
        reason: String,
        checked_at: u64,
    },
    /// A grant, credential or key moved after the check.
    Stale {
        checked_at: u64,
    },
}

/// One owner answer. A credential's value never passes here: it goes to the
/// owner secrets door, and this answer pins the custody record it made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "answer", rename_all = "snake_case", deny_unknown_fields)]
pub enum PackSetupAnswer {
    SecretStored {
        connection: String,
        secret: String,
    },
    /// The owner reviewed the connection's permissions and allowed exactly
    /// these. Each one mints a standing consent grant with its Gate receipt;
    /// one withdrawn is revoked through the consent door.
    Allow {
        connection: String,
        permissions: Vec<String>,
    },
    /// A registered connector key governs the connection; its real
    /// qualification becomes the connection's check.
    BindKey {
        connection: String,
        key: String,
    },
}
