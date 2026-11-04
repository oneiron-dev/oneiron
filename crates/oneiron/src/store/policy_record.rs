//! Stored policy metadata and pure decision input vocabulary.

use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::store::agent_record::AgentCeiling;
use rmpv::Value;

pub(crate) const POLICY_SCHEMA_VERSION: &str = "1.2";

pub(crate) const SCOPED_READ_EFFECTOR_CORE_READ: &str = "core:read";

const DEFAULT_POLICY_MANIFEST_ID: [u8; ENTITY_ID_LEN] = [0xD7; ENTITY_ID_LEN];

pub(crate) const DEFAULT_POLICY_MANIFEST_TIMESTAMP: u64 = 0;

pub(crate) fn default_policy_manifest_id() -> Result<EntityId> {
    EntityId::from_bytes(DEFAULT_POLICY_MANIFEST_ID)
        .map_err(|_| Error::InvariantViolation("invalid default policy manifest id"))
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GateActor {
    pub(crate) actor_class: String,
    pub(crate) actor_ref: Option<String>,
    pub(crate) delegation_grant_ref: Option<String>,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum ExternalEffectPolicyRisk {
    #[default]
    Normal,
    HoldToProposal,
}

#[cfg_attr(not(test), allow(dead_code))]
impl ExternalEffectPolicyRisk {
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::HoldToProposal => "hold_to_proposal",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PolicyEvaluationScope {
    pub(crate) world: Option<EntityId>,
    pub(crate) project: Option<EntityId>,
    pub(crate) subproject: Option<EntityId>,
    pub(crate) thread: Option<EntityId>,
    /// The caller has not been authorized to learn this world exists.
    pub(crate) hidden_world: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyApprovalCeiling {
    Auto,
    Proposed,
}

impl PolicyApprovalCeiling {
    pub(crate) fn parse(value: &Value) -> Option<Self> {
        match value.as_str()? {
            "auto" => Some(Self::Auto),
            "proposed" => Some(Self::Proposed),
            _ => None,
        }
    }

    /// Gate-side conversion from the persisted AGENT_DEF descriptor mirror.
    /// Lives here so the dependency direction stays `gate.rs` → `agent_def.rs`
    /// and `PolicyApprovalCeiling` stays `pub(crate)`.
    pub(crate) fn from_agent_ceiling(ceiling: AgentCeiling) -> Self {
        match ceiling {
            AgentCeiling::Auto => Self::Auto,
            AgentCeiling::Proposed => Self::Proposed,
        }
    }

    pub(crate) fn restrict(self, other: Self) -> Self {
        if matches!(self, Self::Proposed) || matches!(other, Self::Proposed) {
            Self::Proposed
        } else {
            Self::Auto
        }
    }
}
