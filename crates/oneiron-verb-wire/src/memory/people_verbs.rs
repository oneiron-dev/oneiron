//! Moved from `crates/oneiron/src/memory/people_verbs.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// `vault.people.list`'s input.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PeopleListRequest {
    /// The vault tag the board's `<people vault=…>` names; this vault when
    /// absent.
    #[serde(default)]
    pub vault: Option<String>,
    /// Zero-based page of [`PEOPLE_PAGE_SIZE`] rows.
    #[serde(default)]
    pub page: Option<u32>,
}

/// `vault.people.get`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PersonRequest {
    /// `pr<n>`.
    pub pr: String,
}

/// `self.message`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessagePersonRequest {
    pub pr: String,
    pub text: String,
    /// The saved mention `pr` came from, when the agent named the person
    /// (OF-123): the message refuses while that mention is unsettled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mention: Option<crate::dreamer_runner::maintenance::identity::MentionProvenance>,
    /// When the sender leads several projects and sends from no run that
    /// names one: the project (entity hex) it speaks for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_project: Option<String>,
    /// When the person leads several projects: the project (entity hex) the
    /// message addresses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_project: Option<String>,
}

/// What `self.grants.ask` asks for. A space is a conversation or
/// relationship id, in hex.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GrantAskScope {
    Messages {
        space_ref: String,
    },
    Summaries {
        space_ref: String,
    },
    RelationshipClaims {
        space_ref: String,
    },
    /// The asked person's companion profile, optionally one facet of it.
    CompanionProfile {
        #[serde(default)]
        facet_ref: Option<String>,
    },
}

/// `self.grants.ask`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantAskRequest {
    pub pr: String,
    pub scope: GrantAskScope,
}

/// `self.grants.asked`'s input (FIX 11147): one page of the pending access
/// requests that ask the caller.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantAskedRequest {
    /// Exclusive request-id cursor (32-hex) from a prior page.
    #[serde(default)]
    pub after: Option<String>,
    /// Page size, clamped to 1..=100; 50 when absent.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// What an answered request asked for.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GrantRequestedScope {
    Messages {
        space_ref: EntityId,
    },
    Summaries {
        space_ref: EntityId,
    },
    RelationshipClaims {
        space_ref: EntityId,
    },
    CompanionProfile {
        person_ref: EntityId,
        facet_ref: Option<EntityId>,
    },
}
