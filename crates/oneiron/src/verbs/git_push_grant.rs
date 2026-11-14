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
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::federation::git_push::{GIT_PUSH_REVOKE_COMMAND, GitPushGrantStanding};
use crate::federation::{GitPushBounds, GitPushRepo};
use crate::memory::{MemoryError, MemoryResult};
use crate::store::code_repo_registration::CodeRepoRegistration;

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::git_push_grant::{
    GitPushGrantMintInput, GitPushGrantMintOutput, GitPushGrantRevokeInput,
    GitPushGrantRevokeOutput, GitPushGrantView, RepoAnchorBindInput, RepoAnchorBindOutput,
    RepoRegistrationView,
};

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
