//! The inputs and answers of the owner's `git_push` Grant rows (FIX 6867,
//! G1-PUSH): `vault.repo.git_push.mint` and `.revoke`, host doors. A server
//! runs each under the vault owner's proof, with where his say-so reached
//! it; an embedded handle runs them as its embedded owner, on this install.
//! No holder reaches these doors for its own grant.
//!
//! Raw git push into this vault's `/git` endpoint is its own Grant: the
//! owner holds it, and anyone else only through one of these grants, minted
//! to a live person or a live agent definition he names, on explicitly named
//! repos (each a CODE anchor and its PROJECT, granted whole), until he
//! revokes it or the expiry he set. A vault write grant never implies it.
//! Each grant shows in `vault.consent.registry` with its own one-tap revoke.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::authority::ActSurface;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::federation::git_push::{GIT_PUSH_REVOKE_COMMAND, GitPushGrantStanding};
use crate::federation::{GitPushBounds, GitPushRepo};
use crate::memory::{MEMORY_CODE_BAD_REQUEST, MemoryError, MemoryResult};

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

/// `vault.repo.git_push.mint` under the owner's proof, his act recording
/// `surface`.
pub fn mint_git_push_grant_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    input: GitPushGrantMintInput,
) -> MemoryResult<GitPushGrantMintOutput> {
    let minted = vault.mint_git_push_grant(
        owner,
        surface,
        input.member,
        GitPushBounds { repos: input.repos },
        input.expires_at,
    )?;
    Ok(GitPushGrantMintOutput {
        grant: git_push_grant_view(&minted.standing, minted.standing.created_at),
        act_ref: minted.act.to_hex(),
    })
}

/// `vault.repo.git_push.revoke` under the owner's proof, his act recording
/// `surface`. A repeat answers `changed: false`; an id that names no
/// `git_push` Grant is not found.
pub fn revoke_git_push_grant_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    input: GitPushGrantRevokeInput,
) -> MemoryResult<GitPushGrantRevokeOutput> {
    if let Some(seen) = &input.seen {
        revision_shape(seen)?;
    }
    let revoked = vault.revoke_git_push_grant(owner, surface, input.grant_ref)?;
    Ok(GitPushGrantRevokeOutput {
        grant_ref: input.grant_ref,
        changed: revoked.act.is_some(),
        member: revoked.member,
        act_ref: revoked.act.map(|act| act.to_hex()),
    })
}

/// `vault.repo.anchor.bind`'s input (FIX 6867, G1 PR3b): one served repo,
/// by its served name, and the live PROJECT it belongs to.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoAnchorBindInput {
    /// The served name, with no `.git` suffix, as `vault.code.origin.register`
    /// registered it.
    pub repo: String,
    /// The live PROJECT (32 hex) the repo belongs to.
    pub project: EntityId,
}

/// `vault.repo.anchor.bind`'s answer: the CODE anchor and PROJECT a
/// `git_push` Grant, a run's repo bounds or a publish names this repo by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoAnchorBindOutput {
    pub repo: String,
    pub anchor: GitPushRepo,
    /// False when the anchor and its PROJECT edge already stood and this
    /// call changed nothing.
    pub changed: bool,
}

/// `vault.repo.anchor.bind` under the owner's proof: binds the served repo
/// to its CODE anchor in the PROJECT he names. A repeat changes nothing.
pub fn bind_repo_anchor_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: RepoAnchorBindInput,
) -> MemoryResult<RepoAnchorBindOutput> {
    let bound = vault.bind_served_repo_anchor(owner, &input.repo, input.project)?;
    Ok(RepoAnchorBindOutput {
        repo: input.repo,
        anchor: GitPushRepo {
            repo: bound.repo,
            project: bound.project,
        },
        changed: bound.created,
    })
}

fn git_push_grant_view(standing: &GitPushGrantStanding, now: u64) -> GitPushGrantView {
    GitPushGrantView {
        grant_ref: standing.id,
        member: standing.grant.member_ref,
        repos: standing.bounds.repos.clone(),
        delegated_by: standing.delegated_by,
        expires_at: standing.grant.expires_at,
        stands: standing.stands_at(now),
        revoke_command: GIT_PUSH_REVOKE_COMMAND.to_owned(),
    }
}

/// A revision as a surface shows it: 64 lower-case hex.
fn revision_shape(seen: &str) -> MemoryResult<()> {
    if seen.len() == 64
        && seen
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(MemoryError::new(
            MEMORY_CODE_BAD_REQUEST,
            "seen must be 64 lower-case hex",
            &["Pass the revision the surface showed, or omit seen."],
        ))
    }
}
