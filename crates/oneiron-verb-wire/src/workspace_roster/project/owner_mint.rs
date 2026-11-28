//! The wire shapes of the owner's project mint (FIX [OWNER-PROJECT-MINT-DOOR]):
//! `vault.projects.mint` and its read `vault.projects.minted`. `oneiron`
//! re-exports each item under `workspace_roster`.

use oneiron_contracts::entity_id::EntityId;
use serde::{Deserialize, Serialize};

/// `vault.projects.mint`: the owner mints one project under a parent of
/// their own. The host binds the authenticated owner and the owner project
/// signer; neither travels here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerProjectMintRequest {
    /// The project's name: one line, no NUL, at most 128 bytes once
    /// trimmed. Names need not be unique.
    pub name: String,
    /// The parent project. Absent, the vault's root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<EntityId>,
    /// The ask's identity: the same key with the same name and parent
    /// answers the same project; the same key with another name or parent
    /// is refused.
    pub intent_key: String,
}

/// One project the owner minted through `vault.projects.mint`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerMintedProject {
    pub project: EntityId,
    pub name: String,
    /// The parent it was minted under.
    pub parent: EntityId,
    /// Its parents as the project's signed history serves them now.
    pub parents: Vec<EntityId>,
    /// When it was minted, in wall milliseconds on the vault's clock.
    pub minted_at_ms: u64,
    /// The door that minted it: `vault.projects.mint`.
    pub minted_by: String,
}

/// `vault.projects.mint`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerProjectMintAnswer {
    pub project: OwnerMintedProject,
    /// True when the intent key had already minted this project: nothing
    /// was written.
    pub replayed: bool,
}

/// `vault.projects.minted`: one page of the projects the owner minted, in
/// mint order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerMintedProjectsRequest {
    /// The page starts after this project.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<EntityId>,
    /// At most this many rows: 1..=500, 100 when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// `vault.projects.minted`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerMintedProjectsPage {
    pub projects: Vec<OwnerMintedProject>,
    /// The `after` of the next page; absent on the last.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_after: Option<EntityId>,
}
