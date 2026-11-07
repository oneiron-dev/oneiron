//! GRANT (Engine ruling 21:47): the dated list of the Grants that stand for
//! the brief's agent, each one whole. Each act is admitted by one Grant
//! alone, so the brief never meets or unions their scopes; the run,
//! credential and parent ceilings ride beside the list as their own
//! descriptions ([`super::ceilings`]), never as a Grant.

use crate::entity_id::EntityId;
use crate::federation::{RepoAccessBounds, Scope};

/// The line identity states beside the grants when a host produced them.
pub(super) const GRANT_ADMISSION_RULE: &str = "each act must be admitted by one grant";

/// The Grants that stand for the brief's agent, as one read observed them.
/// A list that is `None` is one no host produced, or one whose read could not
/// judge every row: the brief names it unavailable and never states it as an
/// empty list. `Some` of an empty list is a known empty list.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BriefGrants {
    /// The vault's authority instant the read observed, in Unix seconds. The
    /// read is one storage snapshot; a check under it that reads its own
    /// clock is not frozen to this instant.
    pub as_of_secs: u64,
    /// The owner's agent Grants (`vault.agents.grants.mint`) that stand for
    /// the agent for at least one verb of their own explicit verb list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_agent_grants: Option<Vec<BriefGrant>>,
    /// The other federation Grants that name the agent, whose admission
    /// families judge them by their own rules.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other_federation_grants: Option<Vec<BriefGrant>>,
}

/// One Grant, whole: its id, its exact stored scope and repo bounds, and the
/// signed act that minted it. A `null` value is the Grant's own none; a key
/// left out is a value no read produced, named on the unavailable line.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BriefGrant {
    pub id: EntityId,
    /// The six-axis scope exactly as stored, never narrowed to one verb.
    pub scope: Scope,
    /// The repo, refs and read and edit globs the owner gave besides the
    /// scope; `null` for a Grant without them.
    pub repo_bounds: Option<RepoAccessBounds>,
    /// The lowercase hex of the authority entry hash of the signed act that
    /// minted this Grant; `None` when this vault no longer holds that act's
    /// body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act_hash: Option<String>,
    /// The recording time of that retained mint entry, in Unix seconds: when
    /// this vault recorded the act, not a time the owner signed. `None` with
    /// `act_hash`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minted_at: Option<u64>,
}
