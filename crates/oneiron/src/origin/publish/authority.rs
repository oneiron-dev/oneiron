//! Who acts on an exact publish request (FIX 6866; CALLS "FIX 6866
//! approval" and "FIX 6866 grant destination").
//!
//! The vault's live owner, from any linked surface, acts on every request.
//! Anyone else acts only under ONE live agent Grant, judged in the snapshot
//! the act commits in by [`Vault::admit_origin_publish_grant_in_txn`]: G1's
//! read admission (FIX 6867), over the same live candidate Grants
//! (`admit_repo_read_passing_in_txn`), must admit the request's branch over
//! EVERY path its review names under that Grant's repo bounds, and the same
//! Grant's Scope must list `publish` (`publish_rewrite` too, for a rewrite).
//! The first Grant meeting both stands, so a read-only Grant never masks a
//! publishing one. The destination is the repository's one
//! owner-configured mirror; the repo bounds gain no field. Grants are never
//! combined, the outer `Result` is a store error and never "no membership",
//! and the Grant's id is bound on the act and checked again at dispatch. A
//! caller is admitted to the repo handle before anything it names is read.
//! Mirror setup and strategy stay the owner's alone.

use std::collections::BTreeSet;
use std::path::Path;

use super::PublishScope;
use super::types::{OriginPublishAuthority, OriginPublishForce, OriginPublishRequestView};
use crate::Vault;
use crate::codebase::RepoRef;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::{AgentGrantStanding, RepoAccessRefusal, RepoTarget, ScopeAxis};

/// The verb class a Grant's Scope lists to publish within its repo bounds.
pub const ORIGIN_PUBLISH_GRANT_VERB: &str = "publish";

/// The verb class a Grant's Scope lists, beside `publish`, to rewrite a
/// mirror branch's history.
pub const ORIGIN_PUBLISH_REWRITE_GRANT_VERB: &str = "publish_rewrite";

/// A caller refused before its act: the stable code and a plain message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginPublishDenial {
    pub code: &'static str,
    pub message: String,
}

/// A publish verb's answer, or its caller's denial. The outer `Result` of
/// each publish entry point is a store or input error.
pub type PublishAnswer<T> = std::result::Result<T, OriginPublishDenial>;

/// The caller of one publish verb, as its door bound it: never a field of
/// the request.
#[derive(Debug, Clone, Copy)]
pub struct OriginPublishCaller<'a> {
    pub actor: EntityId,
    pub class: EdgeActorClass,
    /// The owner's live proof, when the caller presented one.
    pub owner: Option<&'a AuthenticatedOwner>,
}

/// What a caller's admission to the repo found.
pub(super) enum PublishMember {
    Owner,
    /// One Grant admits the caller to the repo handle whose anchor serves
    /// this repository.
    Grant {
        anchor: RepoRef,
    },
}

/// The one Grant an act stands on, and the anchor's repo it read.
pub(crate) struct OriginPublishGrant {
    pub(crate) grant: EntityId,
    pub(crate) repo_ref: RepoRef,
}

/// What an act names: the repo handle, the branch and whether it rewrites.
#[derive(Clone, Copy)]
pub(super) struct PublishTarget<'a> {
    pub(super) code_repo: Option<EntityId>,
    pub(super) ref_name: &'a str,
    pub(super) rewrite: bool,
}

impl<'a> PublishTarget<'a> {
    pub(super) fn of(view: &'a OriginPublishRequestView) -> Self {
        Self {
            code_repo: view.code_repo,
            ref_name: &view.ref_name,
            rewrite: view.force == OriginPublishForce::Rewrite,
        }
    }
}

fn denial(code: &'static str, message: impl Into<String>) -> OriginPublishDenial {
    OriginPublishDenial {
        code,
        message: message.into(),
    }
}

fn repo_denial(refused: RepoAccessRefusal) -> OriginPublishDenial {
    denial(refused.public_code(), refused.message())
}

/// Whether the Grant's Scope lists `verb` explicitly.
fn lists(standing: &AgentGrantStanding, verb: &str) -> bool {
    matches!(
        &standing.grant.authority_scope.verbs,
        ScopeAxis::Some(verbs) if verbs.contains(verb)
    )
}

impl Vault {
    /// The Grant half of publish admission: `actor`, of `class`, publishes
    /// `target`'s ref of its repo handle when G1's read admission admits it
    /// over every one of its paths under one Grant whose Scope also lists
    /// [`ORIGIN_PUBLISH_GRANT_VERB`] (and, for a rewrite,
    /// [`ORIGIN_PUBLISH_REWRITE_GRANT_VERB`]), judged in one walk of the
    /// live candidate Grants. With `bound` (an approval's recheck at
    /// dispatch), only that very Grant stands.
    ///
    /// # Errors
    /// A store, fold or clock failure; never a refusal.
    pub(crate) fn admit_origin_publish_grant_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        actor: EntityId,
        class: EdgeActorClass,
        target: &RepoTarget,
        rewrite: bool,
        bound: Option<EntityId>,
    ) -> Result<PublishAnswer<OriginPublishGrant>> {
        let publishes = |standing: &AgentGrantStanding| {
            lists(standing, ORIGIN_PUBLISH_GRANT_VERB) && bound.is_none_or(|id| id == standing.id)
        };
        let admitted = self.admit_repo_read_passing_in_txn(
            txn,
            actor,
            class,
            target.repo,
            target,
            |standing: &AgentGrantStanding| {
                publishes(standing)
                    && (!rewrite || lists(standing, ORIGIN_PUBLISH_REWRITE_GRANT_VERB))
            },
        )?;
        let membership = match admitted {
            Ok(membership) => membership,
            Err(Some(refused)) => return Ok(Err(repo_denial(refused))),
            Err(None) => {
                let publishing = rewrite
                    && self
                        .admit_repo_read_passing_in_txn(
                            txn,
                            actor,
                            class,
                            target.repo,
                            target,
                            &publishes,
                        )?
                        .is_ok();
                return Ok(Err(if publishing {
                    denial(
                        "publish_rewrite_not_granted",
                        "a history rewrite needs the owner, or a Grant that also lists \
                         publish_rewrite",
                    )
                } else {
                    denial(
                        "publish_not_granted",
                        "no single Grant that admits this read lists publish",
                    )
                }));
            }
        };
        Ok(Ok(OriginPublishGrant {
            grant: membership.grant,
            repo_ref: membership.repo_ref,
        }))
    }

    /// Admits the caller to the repo before anything it names is read: the
    /// owner's live proof, or one Grant admitting it to the repo handle
    /// `code_repo` whose anchor is this served repository.
    pub(super) fn admit_publish_member(
        &self,
        scope: &PublishScope<'_>,
        caller: &OriginPublishCaller<'_>,
        code_repo: Option<EntityId>,
    ) -> Result<PublishAnswer<PublishMember>> {
        let txn = self.store.env.read_txn()?;
        if let Some(owner) = caller.owner {
            let owner = self.owner_publishes_in_txn(&txn, caller, owner)?;
            return Ok(owner.map(|()| PublishMember::Owner));
        }
        let Some(code_repo) = code_repo else {
            return Ok(Err(denial(
                RepoAccessRefusal::NoMembership.public_code(),
                "a Grant holder names the repo handle (code_repo) its Grant's repo bounds name",
            )));
        };
        let anchor =
            match self.admit_repo_member_in_txn(&txn, caller.actor, caller.class, code_repo)? {
                Ok(membership) => membership.repo_ref,
                Err(refused) => return Ok(Err(repo_denial(refused))),
            };
        drop(txn);
        if !anchor_serves(scope, &anchor) {
            return Ok(Err(repo_denial(RepoAccessRefusal::WrongRepo)));
        }
        Ok(Ok(PublishMember::Grant { anchor }))
    }

    /// The act admission, in the snapshot the act commits in. `paths` is
    /// read only for a Grant holder.
    pub(super) fn admit_publish_act_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        caller: &OriginPublishCaller<'_>,
        member: &PublishMember,
        target: PublishTarget<'_>,
        paths: impl FnOnce() -> Result<BTreeSet<String>>,
    ) -> Result<PublishAnswer<OriginPublishAuthority>> {
        let PublishMember::Grant { anchor } = member else {
            let owner = caller.owner.ok_or(Error::InvariantViolation(
                "an owner member carries the owner's proof",
            ))?;
            let owner = self.owner_publishes_in_txn(txn, caller, owner)?;
            return Ok(owner.map(|()| OriginPublishAuthority::Owner));
        };
        let code_repo = target.code_repo.ok_or(Error::InvariantViolation(
            "a Grant member names its repo handle",
        ))?;
        let asked = RepoTarget {
            repo: code_repo,
            git_ref: target.ref_name.to_owned(),
            paths: paths()?,
        };
        let admitted = self.admit_origin_publish_grant_in_txn(
            txn,
            caller.actor,
            caller.class,
            &asked,
            target.rewrite,
            None,
        )?;
        Ok(match admitted {
            Err(refused) => Err(refused),
            Ok(grant) if &grant.repo_ref != anchor => {
                Err(repo_denial(RepoAccessRefusal::WrongRepo))
            }
            Ok(grant) => Ok(OriginPublishAuthority::Grant { grant: grant.grant }),
        })
    }

    /// The owner's proof, live in `txn` and naming this very caller.
    fn owner_publishes_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        caller: &OriginPublishCaller<'_>,
        owner: &AuthenticatedOwner,
    ) -> Result<PublishAnswer<()>> {
        let actor = owner.revalidate_in_txn(self, txn)?;
        if actor != caller.actor || caller.class != EdgeActorClass::Human {
            return Ok(Err(denial(
                "publish_not_owner",
                "the owner's proof names another actor than the caller",
            )));
        }
        Ok(Ok(()))
    }
}

/// Whether the anchor's repo is a local folder whose object store is this
/// served repository's.
pub(super) fn anchor_serves(scope: &PublishScope<'_>, anchor: &RepoRef) -> bool {
    let RepoRef::LocalFolder { path, .. } = anchor else {
        return false;
    };
    Path::new(path)
        .canonicalize()
        .ok()
        .and_then(|root| scope.wire.canonical_common_dir(&root).ok())
        .is_some_and(|common| common == scope.common)
}
