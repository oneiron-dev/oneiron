//! Core half of `store::policy_record`: its store-layer items live in `oneiron_store::policy_record` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::policy_record::*;

use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::store::agent_record::AgentCeiling;
use rmpv::Value;

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
