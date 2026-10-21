//! The one receive-pack decision (FIX 6867, G1-PUSH): who may push into a
//! served repository, read in the caller's snapshot from the Grant alone.
//!
//! [`Vault::admit_git_receive_pack_in_txn`] admits, in this order:
//! - **Owner**: the pusher is the vault's live owner. Every form he pushed
//!   with before keeps working; the transport's credential gates are his as
//!   they were.
//! - **Grant**: a live GitPush grant names the pusher and a repo whose CODE
//!   anchor resolves, through its stored CODE and PROJECT records, to the
//!   very Git object store being served. The owner who granted it is still
//!   a live owner, the holder still exists, and on a shared vault the vault
//!   is neither deleted nor its root conflicted, and the Grant itself is not
//!   inactive under its pact (FIX 7548).
//! - **Checkout**: on the lease route only, the ticket's stored checkout is
//!   live and held by the pusher on this repository, its TASK stands, and
//!   the run's own Grant (PR1 repo bounds) admits the pusher to this repo.
//!   Its ref moves and every changed path are judged under that same Grant
//!   by `admit_repo_edit_in_txn` before the quarantine is released.
//!
//! None of the three reads the holder's class to decide; a class reaches
//! the Checkout arm only as the run's own identity, which PR1's seam judges
//! as it judges every run. A push that meets none is refused with
//! [`crate::error::CodeError::GitPushCapabilityRequired`], naming the repo and the
//! missing `git_push` capability. A push from an in-process caller that no
//! host transport authenticated is the owner's or nothing: no Grant arm is
//! made from a request's remote user alone.
//!
//! [`Vault::recheck_git_push_in_txn`] runs in the final intent writer and
//! rechecks the same authority, the same Grant, and the current credential.

use crate::Vault;
use crate::authority::{GIT_PUSH_PACT_STANDING_LAPSED, git_push_pact_standing_lapsed_in_txn};
use crate::codebase::RepoRef;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::{FederationGrantScope, GitPushRepo, RepoTarget};
use crate::policy_model::owners_in_txn;

use super::GitPushGrantStanding;
use super::caller::{
    GitPushAdmission, GitPushArm, GitPushCaller, GitPushRefChange, GitPushStamp, ServedPushRepo,
    class_byte, refused,
};

/// No live GitPush grant names this pusher and this repo.
const NO_GRANT: &str = "no live git_push Grant names this principal and this repository";
/// The lease route's checkout is not live, not the pusher's or not this
/// repo's, or its bound attempt no longer runs.
const STALE_CHECKOUT: &str =
    "the checkout lease is not live, not held by this principal, or not on this repository";
/// The checkout's run holds no Grant over this repo.
const NO_RUN_GRANT: &str = "the checkout's run holds no live Grant over this repository";
/// The credential binds no actor class for the run's Grant to judge.
const NO_RUN_CLASS: &str = "the credential names no actor class for the run's Grant to judge";
/// An in-process push is the owner's alone.
const IN_PROCESS_OWNER_ONLY: &str = "a push no host transport authenticated is the owner's alone";
/// The admitted authority no longer stands at the final writer.
const NO_LONGER_STANDS: &str = "the authority this push was admitted under no longer stands";
/// The credential was revoked while the push ran.
const CREDENTIAL_REVOKED: &str = "the credential this push was admitted under is revoked";
/// A checkout push whose changed paths the door could not list.
const PATHS_UNKNOWN: &str = "the checkout push's changed paths could not be listed";

impl Vault {
    /// The one receive-pack decision, in the caller's snapshot `txn`, for
    /// the push `caller` makes into `served`, over the checkout `ticket`
    /// when it came on the lease route.
    ///
    /// # Errors
    /// [`crate::error::CodeError::GitPushCapabilityRequired`] when no arm admits the push;
    /// a store, fold or clock failure.
    pub(crate) fn admit_git_receive_pack_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        caller: &GitPushCaller,
        served: &ServedPushRepo,
        ticket: Option<&str>,
    ) -> Result<GitPushAdmission> {
        if self.git_push_owner_in_txn(txn, caller.principal)? {
            return Ok(GitPushAdmission::sealed(GitPushStamp::new(
                GitPushArm::Owner,
                caller,
                served,
            )));
        }
        if !caller.host {
            return Err(refused(&served.name, IN_PROCESS_OWNER_ONLY));
        }
        // A Grant read that fails refuses only a push no other arm admits:
        // it is logged, and a checkout's own fence and Grant still decide.
        let no_grant = match self.git_push_grant_admits_in_txn(txn, caller, served) {
            Ok(Ok(stamp)) => return Ok(GitPushAdmission::sealed(stamp)),
            Ok(Err(reason)) => reason,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "git push: the git_push Grants did not read; no git_push Grant admits"
                );
                NO_GRANT
            }
        };
        let Some(ticket) = ticket else {
            return Err(refused(&served.name, no_grant));
        };
        match self.git_push_checkout_admits_in_txn(txn, caller, served, ticket)? {
            Ok(stamp) => Ok(GitPushAdmission::sealed(stamp)),
            Err(reason) => Err(refused(&served.name, reason)),
        }
    }

    /// The Grant arm: the first live GitPush grant, in id order, that names
    /// the pusher and a repo whose anchor is the served store, and on a
    /// shared vault is not inactive under its pact (FIX 7548: an inactive
    /// one is passed over for a later one). Else the reason none admits:
    /// [`GIT_PUSH_PACT_STANDING_LAPSED`] when a Grant fell on its pact alone.
    fn git_push_grant_admits_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        caller: &GitPushCaller,
        served: &ServedPushRepo,
    ) -> Result<std::result::Result<GitPushStamp, &'static str>> {
        if !self.git_push_grants_stand_here_in_txn(txn)?
            || !self.git_push_grantee_stands_in_txn(txn, caller.principal)?
        {
            return Ok(Err(NO_GRANT));
        }
        let now = self.instant_in_txn(txn)?.secs();
        let Some(owners) = owners_or_logged(self, txn) else {
            return Ok(Err(NO_GRANT));
        };
        let scope = self.git_push_grant_scope_in_txn(txn)?;
        let mut lapsed = false;
        'grants: for standing in self.git_push_grants_in_txn(txn)? {
            if !standing_names(&standing, caller.principal, now, &owners, scope) {
                continue;
            }
            for repo in &standing.bounds.repos {
                let Some(anchor) = self.git_push_anchor_in_txn(txn, repo)? else {
                    continue;
                };
                if served.is_store(self.git_push_store_identity(&anchor).as_deref()) {
                    if git_push_pact_standing_lapsed_in_txn(self, txn, standing.id, &standing.grant)
                    {
                        lapsed = true;
                        continue 'grants;
                    }
                    return Ok(Ok(GitPushStamp::new(GitPushArm::Grant, caller, served)
                        .naming(standing.id, *repo, anchor)));
                }
            }
        }
        Ok(Err(if lapsed {
            GIT_PUSH_PACT_STANDING_LAPSED
        } else {
            NO_GRANT
        }))
    }

    /// Whether `principal` is a live owner of this vault, co-owners
    /// included. A read of the owner set that fails (a grant row that does
    /// not decode, say) never refuses a live owner: it is logged, and the
    /// pusher's own live Owner grant, or the personal vault's embedded
    /// owner, still admits him as before.
    fn git_push_owner_in_txn(&self, txn: &heed::RoTxn<'_>, principal: EntityId) -> Result<bool> {
        match owners_in_txn(self, txn) {
            Ok(owners) => Ok(owners.contains(&principal)),
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "git push: the owner set did not read; judging the pusher's own Owner grant"
                );
                self.recorded_owner_in_txn(txn, principal)
            }
        }
    }

    /// The pusher's own live Owner grant under this shared vault's scope,
    /// read row by row so one unreadable row refuses no one; on a personal
    /// vault, the embedded owner.
    fn recorded_owner_in_txn(&self, txn: &heed::RoTxn<'_>, principal: EntityId) -> Result<bool> {
        let Some(creation) = self.shared_vault_creation_in_txn(txn)? else {
            return Ok(principal == crate::vault::embedded_owner_actor_id()?);
        };
        let now = self.instant_in_txn(txn)?.secs();
        for id in crate::ports::EntityStoreRead::port_entity_ids_by_type(
            &self.store,
            txn,
            crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
            None,
        )? {
            let Ok(id) = id else {
                continue;
            };
            let Ok(crate::vault::LiveEntityRow::Live { body, .. }) =
                crate::vault::live_entity_row_in_txn(&self.store, txn, &id)
            else {
                continue;
            };
            if crate::federation::decode_federation_grant_body(&body).is_ok_and(|grant| {
                grant.member_ref == principal
                    && grant.role == crate::federation::FederationGrantRole::Owner
                    && grant.scope == FederationGrantScope::vault(creation.vault_id)
                    && grant.confers_at(now)
            }) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether any GitPush grant may stand here at all: a shared vault that
    /// is deleted, or whose root is conflicted, admits none.
    fn git_push_grants_stand_here_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<bool> {
        if self.shared_vault_creation_in_txn(txn)?.is_none() {
            return Ok(true);
        }
        Ok(self.shared_vault_deletion_in_txn(txn)?.is_none()
            && !self
                .authority_fold_readonly_in_txn(txn)?
                .vault_root_is_conflicted())
    }

    /// The Checkout arm: the ticket's live checkout, its standing TASK, and
    /// the run's own Grant over the served repo.
    fn git_push_checkout_admits_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        caller: &GitPushCaller,
        served: &ServedPushRepo,
        ticket: &str,
    ) -> Result<std::result::Result<GitPushStamp, &'static str>> {
        if !self.git_push_checkout_stands_in_txn(txn, caller.principal, served, ticket)? {
            return Ok(Err(STALE_CHECKOUT));
        }
        let Some(class) = caller.class else {
            return Ok(Err(NO_RUN_CLASS));
        };
        for standing in self.agent_grants_in_txn(txn)? {
            let Some(bounds) = standing.grant.repo_bounds.as_ref() else {
                continue;
            };
            if standing.grant.member_ref != caller.principal {
                continue;
            }
            let repo = GitPushRepo {
                repo: bounds.repo,
                project: bounds.project,
            };
            let Some(anchor) = self.git_push_anchor_in_txn(txn, &repo)? else {
                continue;
            };
            if !served.is_store(self.git_push_store_identity(&anchor).as_deref()) {
                continue;
            }
            if let Ok(membership) =
                self.admit_repo_member_in_txn(txn, caller.principal, class, bounds.repo)?
            {
                let mut stamp = GitPushStamp::new(GitPushArm::Checkout, caller, served).naming(
                    membership.grant,
                    repo,
                    anchor,
                );
                stamp.checkout = Some(ticket.to_owned());
                stamp.class = Some(class_byte(class));
                return Ok(Ok(stamp));
            }
        }
        Ok(Err(NO_RUN_GRANT))
    }

    /// The liveness fence of a lease push: the ticket's exact checkout id
    /// and epoch, live at the vault's own time, held by `principal` on the
    /// served repo, and the TASK it was claimed for still standing. This is
    /// liveness, not policy: a stale or expired lease never publishes.
    fn git_push_checkout_stands_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        principal: EntityId,
        served: &ServedPushRepo,
        ticket: &str,
    ) -> Result<bool> {
        let Ok(lease) = crate::credential_door::require_checkout_lease_in_txn(
            self,
            txn,
            ticket,
            &principal.to_hex(),
            &served.repo_ref(),
        ) else {
            return Ok(false);
        };
        let task = lease.task_ref;
        Ok(
            crate::vault::live_entity_row_in_txn(&self.store, txn, &task)?.is_live()
                && self
                    .task_standing_in(txn, task)?
                    .is_some_and(|standing| !standing.cancelled)
                // FIX 7130: a BYOA-bound epoch stands only while its attempt runs.
                && crate::checkout::lease::attempt_binding::bound_attempt_runs_in_txn(
                    self, txn, &lease,
                )?,
        )
    }

    /// The final intent writer's recheck of `stamp`, in its own write
    /// snapshot, before the quarantine is released: the owner is still a
    /// live owner; the same GitPush grant still stands for the same repo
    /// and anchor; or the same checkout still holds, and the run's same
    /// Grant admits every ref move and changed path in `changes`. The
    /// current credential is still unrevoked. In-process pushes have no
    /// credential to recheck.
    ///
    /// # Errors
    /// [`crate::error::CodeError::GitPushCapabilityRequired`] when the authority no longer
    /// stands; a store, fold or clock failure.
    pub(crate) fn recheck_git_push_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        stamp: &GitPushStamp,
        repo: &RepoRef,
        changes: Option<&[GitPushRefChange]>,
    ) -> Result<()> {
        let principal = EntityId::from_hex(&stamp.principal)
            .map_err(|_| refused(&stamp.served, NO_LONGER_STANDS))?;
        let stands = match stamp.arm {
            // A recheck that cannot read refuses no owner push it admitted:
            // it is logged, and the push lands as it did before G1-PUSH.
            GitPushArm::Owner => {
                return match self.git_push_owner_rechecks_in_txn(txn, stamp, principal) {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(refused(&stamp.served, NO_LONGER_STANDS)),
                    Err(error) => {
                        tracing::warn!(
                            kind = ?error.kind(),
                            "git push: an owner push's recheck did not read; it lands as admitted"
                        );
                        Ok(())
                    }
                };
            }
            GitPushArm::Grant => self.git_push_grant_rechecks_in_txn(txn, stamp, principal)?,
            GitPushArm::Checkout => {
                let changes = changes.ok_or_else(|| refused(&stamp.served, PATHS_UNKNOWN))?;
                return self
                    .git_push_checkout_rechecks_in_txn(txn, stamp, principal, repo, changes);
            }
        };
        if !stands {
            return Err(refused(&stamp.served, NO_LONGER_STANDS));
        }
        self.git_push_credential_rechecks_in_txn(txn, stamp)
    }

    /// The owner, read again: still a live owner, his credential unrevoked.
    fn git_push_owner_rechecks_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        stamp: &GitPushStamp,
        principal: EntityId,
    ) -> Result<bool> {
        Ok(self.git_push_owner_in_txn(txn, principal)?
            && self.git_push_credential_live_in_txn(txn, stamp)?)
    }

    /// The same GitPush grant, read again: it still names the pusher and
    /// the stamped repo, stands, and its anchor still names the same store.
    /// On a shared vault it is still not inactive under its pact, else the
    /// typed refusal [`GIT_PUSH_PACT_STANDING_LAPSED`] (FIX 7548); no other
    /// Grant stands in for it.
    fn git_push_grant_rechecks_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        stamp: &GitPushStamp,
        principal: EntityId,
    ) -> Result<bool> {
        let (Some(grant), Some(repo), Some(anchor)) = (
            stamp
                .grant
                .as_deref()
                .and_then(|hex| EntityId::from_hex(hex).ok()),
            stamp.repo,
            stamp.anchor.as_deref(),
        ) else {
            return Ok(false);
        };
        let Some(standing) = self.git_push_grant_in_txn(txn, grant)? else {
            return Ok(false);
        };
        let now = self.instant_in_txn(txn)?.secs();
        let Some(owners) = owners_or_logged(self, txn) else {
            return Ok(false);
        };
        let scope = self.git_push_grant_scope_in_txn(txn)?;
        let stands = self.git_push_grants_stand_here_in_txn(txn)?
            && self.git_push_grantee_stands_in_txn(txn, principal)?
            && standing_names(&standing, principal, now, &owners, scope)
            && standing.bounds.repos.contains(&repo)
            && self.git_push_anchor_in_txn(txn, &repo)?.as_deref() == Some(anchor);
        if stands && git_push_pact_standing_lapsed_in_txn(self, txn, grant, &standing.grant) {
            return Err(refused(&stamp.served, GIT_PUSH_PACT_STANDING_LAPSED));
        }
        Ok(stands)
    }

    /// The same checkout and the run's same Grant, over every ref move and
    /// changed path of the push.
    fn git_push_checkout_rechecks_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        stamp: &GitPushStamp,
        principal: EntityId,
        repo: &RepoRef,
        changes: &[GitPushRefChange],
    ) -> Result<()> {
        let no_longer = || refused(&stamp.served, NO_LONGER_STANDS);
        let (Some(ticket), Some(grant), Some(anchor_repo), Some(class)) = (
            stamp.checkout.as_deref(),
            stamp
                .grant
                .as_deref()
                .and_then(|hex| EntityId::from_hex(hex).ok()),
            stamp.repo,
            stamp.class.and_then(EdgeActorClass::try_from_u8),
        ) else {
            return Err(no_longer());
        };
        let lease = crate::credential_door::require_checkout_lease_in_txn(
            self,
            txn,
            ticket,
            &principal.to_hex(),
            repo,
        )
        .map_err(|_| refused(&stamp.served, STALE_CHECKOUT))?;
        if !crate::vault::live_entity_row_in_txn(&self.store, txn, &lease.task_ref)?.is_live()
            || self
                .task_standing_in(txn, lease.task_ref)?
                .is_none_or(|standing| standing.cancelled)
            || !crate::checkout::lease::attempt_binding::bound_attempt_runs_in_txn(
                self, txn, &lease,
            )?
        {
            return Err(refused(&stamp.served, STALE_CHECKOUT));
        }
        for change in changes {
            let target = RepoTarget {
                repo: anchor_repo.repo,
                git_ref: change.git_ref.clone(),
                paths: change.paths.clone(),
            };
            match self.admit_repo_edit_in_txn(txn, principal, class, anchor_repo.repo, &target)? {
                Ok(membership) if membership.grant == grant => {}
                Ok(_) => return Err(no_longer()),
                Err(refusal) => return Err(refused(&stamp.served, refusal.message())),
            }
        }
        self.git_push_credential_rechecks_in_txn(txn, stamp)
    }

    /// The credential the push was admitted under is still unrevoked, or
    /// the typed refusal naming it.
    fn git_push_credential_rechecks_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        stamp: &GitPushStamp,
    ) -> Result<()> {
        if self.git_push_credential_live_in_txn(txn, stamp)? {
            Ok(())
        } else {
            Err(refused(&stamp.served, CREDENTIAL_REVOKED))
        }
    }

    /// Whether the credential is still unrevoked: its capability slip is
    /// live, and its token carries no revocation mark.
    fn git_push_credential_live_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        stamp: &GitPushStamp,
    ) -> Result<bool> {
        if let Some(slip) = stamp.slip.as_ref()
            && !self.capability_slip_id_is_live_in_txn(txn, slip)?
        {
            return Ok(false);
        }
        Ok(stamp
            .revoked_marker
            .as_deref()
            .map(|marker| self.store.sync_state.get(txn, marker))
            .transpose()?
            .flatten()
            .is_none())
    }
}

/// The vault's live owners, or `None` (logged) when the set does not read:
/// a non-owner's Grant arm then admits nothing, and the push is refused
/// with the typed capability refusal.
fn owners_or_logged(vault: &Vault, txn: &heed::RoTxn<'_>) -> Option<Vec<EntityId>> {
    owners_in_txn(vault, txn)
        .inspect_err(|error| {
            tracing::warn!(
                kind = ?error.kind(),
                "git push: the owner set did not read; no git_push Grant stands"
            );
        })
        .ok()
}

/// Whether the GitPush grant `standing` names `principal` and stands now:
/// unexpired, under this vault's own grant scope, granted by a live owner.
fn standing_names(
    standing: &GitPushGrantStanding,
    principal: EntityId,
    now: u64,
    owners: &[EntityId],
    scope: FederationGrantScope,
) -> bool {
    standing.grant.member_ref == principal
        && standing.stands_at(now)
        && standing.grant.scope == scope
        && owners.contains(&standing.delegated_by)
}
