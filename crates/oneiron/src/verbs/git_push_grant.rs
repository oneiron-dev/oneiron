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
//!
//! `.mint` widens the holder's grant (ARCH-0082 #act-table "Widen another's
//! grant"): the owner's own act on their own proof, never gated, and its
//! answer records that decision (`check_in`). A Deputy who may not reach
//! this door asks through `vault.check_in.open` for the exact mint; once
//! the owner approves, the owner applies it here with `check_in_ref`, and
//! the mint's writer spends the ask (ROLES-CHECKIN 2k7; Engine RULING
//! P25-SHAPE Q1 = A).
//!
//! `vault.repo.anchor.bind` is also the owner's repository registration
//! (FIX 4299, CODE-CUSTODY-01): it binds a served repo, or registers an
//! external local Git repository, as one stable CODE anchor with its
//! retained editable whitelist and portable id. It grants nobody membership.

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::revision_shape;
use crate::Vault;
use crate::authority::ActSurface;
use crate::check_in::{AppliedCheckIn, CheckInDecision};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::federation::git_push::{GIT_PUSH_REVOKE_COMMAND, GitPushGrantStanding};
use crate::federation::{GitPushBounds, GitPushRepo};
use crate::memory::{MemoryError, MemoryResult};
use crate::store::code_repo_registration::CodeRepoRegistration;

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
    /// Another asker's approved check-in for this exact mint, 32 hex: the
    /// owner applies it on their own proof, and the mint's writer spends it
    /// (ROLES-CHECKIN 2k7). Omitted: the owner's own mint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in_ref: Option<String>,
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
    /// The decision the mint ran on: the owner's own proof, naming the
    /// asker's approved check-in it applied (ROLES-CHECKIN 2k7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in: Option<CheckInDecision>,
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
/// `surface`, applying with `check_in_ref` another asker's approved
/// check-in for this exact mint (2k7; P25-SHAPE Q1 = A): the mint's writer
/// spends it. The answer records the decision.
///
/// # Errors
///
/// `BAD_REQUEST` for a malformed `check_in_ref`; the owner's refusals and
/// the mint's; a check-in that is not an approved ask for this mint.
pub fn mint_git_push_grant_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    input: GitPushGrantMintInput,
) -> MemoryResult<GitPushGrantMintOutput> {
    let applied = match super::shared::check_in_ref(input.check_in_ref.as_deref())? {
        Some(id) => Some(AppliedCheckIn {
            id,
            verb: "vault.repo.git_push.mint",
            effect_digest: git_push_grant_mint_effect_digest(&input)?,
        }),
        None => None,
    };
    let minted = vault.mint_git_push_grant(
        owner,
        surface,
        input.member,
        GitPushBounds { repos: input.repos },
        input.expires_at,
        applied.as_ref(),
    )?;
    Ok(GitPushGrantMintOutput {
        grant: git_push_grant_view(&minted.standing, minted.standing.created_at),
        act_ref: minted.act.to_hex(),
        check_in: Some(minted.check_in),
    })
}

/// The digest of the owner's git_push mint `request`: the effect an asker's
/// `vault.check_in.open` names for `vault.repo.git_push.mint`, and the one
/// the owner's mint spends (2k7; P25-SHAPE Q1 = A). BLAKE3, key derived
/// from `oneiron check_in git push grant mint v1`, over the request's
/// MessagePack encoding with field names, without its `check_in_ref`: the
/// holder, the repos ascending and the expiry.
///
/// # Errors
///
/// The request does not encode.
pub fn git_push_grant_mint_effect_digest(
    request: &GitPushGrantMintInput,
) -> MemoryResult<[u8; 32]> {
    let mint = GitPushGrantMintInput {
        check_in_ref: None,
        ..request.clone()
    };
    let encoded = rmp_serde::to_vec_named(&mint)
        .map_err(|_| crate::error::Error::InvariantViolation("git push grant mint encode"))?;
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in git push grant mint v1");
    hasher.update(&encoded);
    Ok(*hasher.finalize().as_bytes())
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

/// `vault.repo.anchor.bind` under the owner's proof: binds the served repo,
/// or registers the external local repository, as its CODE anchor in the
/// PROJECT he names (FIX 4299). A repeat changes nothing. The repo's
/// portable id is minted in the same writer; after it commits, a
/// best-effort manifest refresh keeps that identity available without
/// changing this door's answer.
///
/// # Errors
/// A request that names both or neither of `repo` and `local_folder`, or
/// an anchor beside a served repo; the owner refusal, `InvalidConfig` and
/// store failures of the registration writer.
pub fn bind_repo_anchor_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: RepoAnchorBindInput,
) -> MemoryResult<RepoAnchorBindOutput> {
    let editable = input.editable.as_deref();
    let bound = match (&input.repo, &input.local_folder, input.anchor) {
        (Some(repo), None, None) => {
            vault.bind_served_repo_anchor_with(owner, repo, input.project, editable)?
        }
        (None, Some(folder), anchor) => vault.register_local_repository_as_owner(
            owner,
            Path::new(folder),
            input.project,
            anchor,
            editable,
        )?,
        _ => {
            return Err(MemoryError::bad_request_with(
                "name exactly one of repo and local_folder; anchor names a local registration",
                &[
                    "Name a served repo by repo, or an external local Git repository by local_folder.",
                ],
            ));
        }
    };
    Ok(RepoAnchorBindOutput {
        repo: input.repo,
        anchor: GitPushRepo {
            repo: bound.repo,
            project: bound.project,
        },
        portable: bound.portable.to_hex(),
        registration: bound.registration.as_ref().map(registration_view),
        changed: bound.changed,
    })
}

fn registration_view(registration: &CodeRepoRegistration) -> RepoRegistrationView {
    RepoRegistrationView {
        source: registration.source().spelling(),
        editable: registration.editable().to_vec(),
    }
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
