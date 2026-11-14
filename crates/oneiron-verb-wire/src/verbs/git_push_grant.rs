//! Moved from `crates/oneiron/src/verbs/git_push_grant.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::federation::GitPushRepo;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::Path;

/// `vault.repo.git_push.mint`'s input: the holder, the repos and an
/// optional expiry. The host chooses the grant's vault scope, its mint time
/// and its delegator (the owner), never the input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GitPushGrantMintInput {
    /// The holder (32 hex): a live person or a live agent definition of
    /// this vault, whichever the owner names. Never a device.
    pub member: EntityId,
    /// The repos it may push to, each whole: a CODE anchor (a CODE_ARTIFACT
    /// whose stored repo is a served Git store) and its PROJECT. At least
    /// one; there is no wildcard.
    pub repos: BTreeSet<GitPushRepo>,
    /// When it stops admitting pushes (Unix seconds, later than now).
    /// Omitted: it stands until revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

/// One `git_push` Grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GitPushGrantView {
    /// The grant's FEDERATION_GRANT row.
    pub grant_ref: EntityId,
    /// The holder it names.
    pub member: EntityId,
    /// The repos it names.
    pub repos: BTreeSet<GitPushRepo>,
    /// The owner PERSON who granted it.
    pub delegated_by: EntityId,
    /// When it stops admitting pushes (Unix seconds); absent: until revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// Whether it stands now: unexpired.
    pub stands: bool,
    /// The one-tap revoke command: `vault.repo.git_push.revoke`.
    pub revoke_command: String,
}

/// `vault.repo.git_push.mint`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GitPushGrantMintOutput {
    pub grant: GitPushGrantView,
    /// The signed authority entry that records the owner's mint (64 hex).
    pub act_ref: String,
}

/// `vault.repo.git_push.revoke`'s input: the grant, by its id.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GitPushGrantRevokeInput {
    /// The grant's FEDERATION_GRANT row (32 hex).
    pub grant_ref: EntityId,
    /// The revision the surface showed (64 lower-case hex), checked for its
    /// shape only: the owner's revoke always lands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen: Option<String>,
}

/// `vault.repo.git_push.revoke`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GitPushGrantRevokeOutput {
    pub grant_ref: EntityId,
    /// False when the grant was already revoked and this call changed
    /// nothing.
    pub changed: bool,
    /// The holder the revoked grant named; absent when it changed nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<EntityId>,
    /// The signed authority entry that records this revoke (64 hex); absent
    /// when it changed nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act_ref: Option<String>,
}

/// `vault.repo.anchor.bind`'s input (FIX 6867, G1 PR3b; FIX 4299): one
/// repository and the live PROJECT it belongs to. Exactly one of `repo` and
/// `local_folder` names it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoAnchorBindInput {
    /// A served repo: its served name, with no `.git` suffix, as
    /// `vault.code.origin.register` registered it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// An external local Git repository (FIX 4299): an absolute folder
    /// inside it on the host that serves this vault, registered at the
    /// repository's root as the importer opens it. It grants nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_folder: Option<String>,
    /// The live PROJECT (32 hex) the repo belongs to.
    pub project: EntityId,
    /// The registered local repository a config update names (32 hex): the
    /// anchor its first registration returned. Omitted: the folder's
    /// registration in this PROJECT, else a new one. A served repo's anchor
    /// is derived, never named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<EntityId>,
    /// The editable whitelist (FIX 4299): exact normalized repo-relative
    /// paths, no globs. Every change to the repo must be on it, beside the
    /// Grant's editable globs. Empty: read-only. Omitted: the whitelist
    /// stands as it is; a new local registration starts read-only, and a
    /// served repo bound with none keeps no whitelist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<Vec<String>>,
}

/// A registered repository's retained configuration (FIX 4299), shown to
/// the owner only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoRegistrationView {
    /// Where the importer reads the repo: `local:<folder>` or
    /// `served:<name>`. Config, never identity.
    pub source: String,
    /// The editable whitelist, ascending. Empty: read-only.
    pub editable: Vec<String>,
}

/// `vault.repo.anchor.bind`'s answer: the CODE anchor and PROJECT a
/// `git_push` Grant, a run's repo bounds, a capture or a publish names this
/// repo by, its portable id and its retained configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoAnchorBindOutput {
    /// The served name, for a served repo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    pub anchor: GitPushRepo,
    /// The repo's portable id (64 hex), minted in the same writer as the
    /// anchor (FIX 4299, FIX 6870).
    pub portable: String,
    /// The retained configuration; absent for a served repo bound with no
    /// whitelist, which keeps no edit ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration: Option<RepoRegistrationView>,
    /// False when the anchor, its PROJECT edge, its configuration and its
    /// portable id already stood and this call changed nothing.
    pub changed: bool,
}
