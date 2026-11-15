//! Moved from `crates/oneiron/src/code_run/actions.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::agent_record::AgentCeiling;
use oneiron_store::write_envelope::WriteActor;
use oneiron_verb_wire::lens::SelfUiActionId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionArgKind {
    Bool,
    Number,
    Text,
    Token,
    Entity,
    Json,
}

/// The most one [`ActionJson`] holds, encoded, in bytes.
pub const MAX_ACTION_JSON_BYTES: usize = oneiron_base::request_limits::MAX_REMOTE_REQUEST_BYTES;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionVerbDefinition {
    pub id: SelfUiActionId,
    pub args_schema: Vec<ActionArgKind>,
    #[serde(with = "ceiling_wire")]
    pub required_ceiling: AgentCeiling,
}

#[derive(Debug, Clone, Copy)]
pub struct ActionBuildContext {
    pub effect_id: EntityId,
    pub actor: WriteActor,
    pub frozen_unix_ms: u64,
}

pub fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}

pub mod ceiling_wire {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        value: &AgentCeiling,
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        value.as_str().serialize(s)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> std::result::Result<AgentCeiling, D::Error> {
        AgentCeiling::parse(&String::deserialize(d)?)
            .ok_or_else(|| serde::de::Error::custom("unknown action ceiling"))
    }
}
