//! Moved from `crates/oneiron/src/runtime_hooks/lineage.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::borrow::Cow;
use std::collections::BTreeSet;

/// One hop of a chain: a run of one binding on one fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LineageLink {
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub binding: EntityId,
    pub run_key: String,
    // The entity the run fired on, a verb run's caller; the erased marker,
    // spelled `ERASED_CALL_IDENTITY`, once a permanent erase took it.
    #[serde(with = "link_entity")]
    #[schemars(with = "String")]
    pub entity: EntityId,
    pub position: String,
}

/// A link's entity as its hex ref, or
/// [`ERASED_CALL_IDENTITY`](oneiron_store::receipt_identity::ERASED_CALL_IDENTITY) for
/// [`erased_entity`].
mod link_entity {
    use serde::{Deserialize, Deserializer, Serializer};

    use oneiron_contracts::entity_id::EntityId;
    use oneiron_store::receipt_identity::ERASED_CALL_IDENTITY;

    pub(super) fn serialize<S: Serializer>(
        entity: &EntityId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if *entity == super::erased_entity() {
            serializer.serialize_str(ERASED_CALL_IDENTITY)
        } else {
            serializer.serialize_str(&entity.to_hex())
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<EntityId, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text == ERASED_CALL_IDENTITY {
            return Ok(super::erased_entity());
        }
        EntityId::from_hex(&text).map_err(serde::de::Error::custom)
    }
}

/// Why a check was raised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HookCheckReason {
    /// The same hook fired again inside its own causal chain.
    Cycle,
    /// The chain reached [`MAX_LINEAGE_DEPTH`].
    Depth,
}

impl HookCheckReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cycle => "cycle",
            Self::Depth => "depth",
        }
    }
}

/// An "is everything okay" check for the owner, with the chain shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HookCheck {
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub binding: EntityId,
    pub run_key: String,
    pub reason: HookCheckReason,
    pub chain: Vec<LineageLink>,
    pub raised_at: u64,
}
