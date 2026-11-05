//! Stored policy metadata and pure decision input vocabulary.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::ENTITY_ID_LEN;
use oneiron_contracts::entity_id::EntityId;
use rmpv::Value;

pub const POLICY_SCHEMA_VERSION: &str = "1.2";

pub const SCOPED_READ_EFFECTOR_CORE_READ: &str = "core:read";

const DEFAULT_POLICY_MANIFEST_ID: [u8; ENTITY_ID_LEN] = [0xD7; ENTITY_ID_LEN];

pub const DEFAULT_POLICY_MANIFEST_TIMESTAMP: u64 = 0;

pub fn default_policy_manifest_id() -> Result<EntityId> {
    EntityId::from_bytes(DEFAULT_POLICY_MANIFEST_ID)
        .map_err(|_| Error::InvariantViolation("invalid default policy manifest id"))
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateActor {
    pub actor_class: String,
    pub actor_ref: Option<String>,
    pub delegation_grant_ref: Option<String>,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ExternalEffectPolicyRisk {
    #[default]
    Normal,
    HoldToProposal,
}

#[cfg_attr(not(test), allow(dead_code))]
impl ExternalEffectPolicyRisk {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::HoldToProposal => "hold_to_proposal",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PolicyEvaluationScope {
    pub world: Option<EntityId>,
    pub project: Option<EntityId>,
    pub subproject: Option<EntityId>,
    pub thread: Option<EntityId>,
    /// The caller has not been authorized to learn this world exists.
    pub hidden_world: bool,
}
