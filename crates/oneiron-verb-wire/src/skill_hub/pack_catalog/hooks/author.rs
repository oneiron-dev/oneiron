//! Moved from `crates/oneiron/src/skill_hub/pack_catalog/hooks/author.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Who a hook runs as (ARCH-0080 §6, §7, §9): the owner who bound it, a
/// resident agent that wrote it into the `local` pack, or a hub pack's
/// publisher as a foreign actor. The foreign fields name ARCH-0072's
/// foreign-actor admission: the actor's kind, its identity record, the hub
/// it offers from and the one Grant that admits it, plus the vault-resident
/// actor its outcomes stamp. Hub trust never chains to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HookAuthor {
    Owner,
    /// A resident agent's own hook: its outcomes run as the agent, and it
    /// reads at the agent's ceiling unless the owner grants it otherwise.
    Agent {
        #[serde(with = "oneiron_contracts::serialize::entity_ref")]
        #[schemars(with = "String")]
        agent: EntityId,
    },
    ForeignActor {
        actor_kind: String,
        identity: String,
        #[serde(with = "oneiron_contracts::serialize::entity_ref")]
        #[schemars(with = "String")]
        hub: EntityId,
        /// The digest of the publisher's standing Grant.
        grant: String,
        #[serde(with = "oneiron_contracts::serialize::entity_ref")]
        #[schemars(with = "String")]
        actor: EntityId,
    },
}
