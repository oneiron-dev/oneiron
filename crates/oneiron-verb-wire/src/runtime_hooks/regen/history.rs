//! Moved from `crates/oneiron/src/runtime_hooks/regen/history.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Who ran or enacted a regen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "by", rename_all = "snake_case")]
pub enum HookRegenActor {
    /// The engine's own pass after a verb-table or sandbox-contract change.
    Engine,
    /// The vault's owner, on any hook of the vault's own packs.
    Owner {
        #[serde(with = "oneiron_contracts::serialize::entity_ref")]
        #[schemars(with = "String")]
        actor: EntityId,
    },
    /// A resident agent, on a hook it authored.
    Agent {
        #[serde(with = "oneiron_contracts::serialize::entity_ref")]
        #[schemars(with = "String")]
        agent: EntityId,
    },
}

/// What a regen decided, as its receipt keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HookRegenDecision {
    AutoAdopt,
    NeedsHumanStamp,
    RolledBack,
}
