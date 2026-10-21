//! Exact-commit publication to a repository's mirror (FIX 6866, part 1):
//! a public mirror changes only when we choose.
//!
//! A request names one destination (the repository's one owner-configured
//! mirror, at its target generation), one full branch ref and one exact
//! commit, and leases the push on the branch's tip as an authenticated read
//! saw it when the request was made (absent, or a commit). Its full-ancestry
//! review (`review`) is recorded on it before anything goes out, and its
//! idempotency key can never name another tuple. Its life:
//! `pending` → `approved` (the owner or one Grant approves the exact review
//! digest) → `dispatching` (its one push claimed) → `published` or
//! `observed_published`, or `refused` with a typed reason; `cancelled` and
//! `expired` end it unspent. A failed or retried publish never widens:
//! the same ref and commit, or a typed refusal naming the change, never a
//! second send (`reconcile`).
//!
//! Requests work on a mirror of either strategy and never read it: a
//! strategy change leaves every pending or approved request as it stands.
//! The store is LIVE with an actor scrub (`store`); a request whose commit a
//! restore took is refused at dispatch.
//!
//! A `schedule` or `full_auto` mirror's whole-ref pushes (FIX 6866, part 2)
//! reuse the same review, credential and outbound profile without an
//! approval step: each run freezes a reviewed `MirrorPushPlan` before
//! egress (`mirror_plan`, `mirror_review`), sends it in claimed, leased
//! batches (`mirror_plan_dispatch`) and reconciles before any resend
//! (`mirror_plan_reconcile`), in the LIVE store `ORIGIN_MIRROR_WORK`
//! (`mirror_plan_store`).

mod approval;
mod authority;
mod dispatch;
mod inputs;
mod lifecycle;
mod mirror_plan;
mod mirror_plan_dispatch;
mod mirror_plan_reconcile;
mod mirror_plan_remote;
mod mirror_plan_run;
mod mirror_plan_store;
mod mirror_plan_types;
mod mirror_review;
mod reconcile;
mod review;
mod store;
mod types;

use std::path::PathBuf;

pub use authority::{
    ORIGIN_PUBLISH_GRANT_VERB, ORIGIN_PUBLISH_REWRITE_GRANT_VERB, OriginPublishCaller,
    OriginPublishDenial, PublishAnswer,
};
pub use inputs::*;
pub(crate) use mirror_plan::{MirrorRunScope, MirrorSelection};
pub(crate) use mirror_plan_reconcile::MirrorReconcile;
pub use mirror_plan_reconcile::{
    AUTOMATIC_RECONCILE_UNREAD_BEFORE_RESEND, AUTOMATIC_UNREADABLE_RECONCILE_RESENDS_SAME_PLAN,
};
pub(crate) use mirror_plan_run::MirrorPlanSummary;
pub(crate) use mirror_plan_store::erase_mirror_work_actor_in_txn;
pub use reconcile::ORIGIN_PUBLISH_DISPATCH_SETTLE_SECS;
pub use review::ORIGIN_PUBLISH_REVIEW_PAGE_ITEMS;
pub(crate) use store::erase_publish_request_actor_in_txn;
pub use types::*;

use authority::PublishTarget;
use reconcile::remote_of;
use store::{ORIGIN_PUBLISH_MAX_KEY_BYTES, keyed_request_id};

use crate::Vault;
use crate::codebase::RepoRef;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitRefName, GitWire, GitWireRepo};
use crate::origin::smart_http::origin_repo_dir;

/// The branch namespace a request may name.
const BRANCH_PREFIX: &str = "refs/heads/";

/// One served repository, as every publish verb reads it.
pub(super) struct PublishScope<'v> {
    pub(super) repo_id: EntityId,
    pub(super) root: PathBuf,
    /// Its canonical object store.
    pub(super) common: PathBuf,
    pub(super) wire: GitWire<'v>,
}

impl PublishScope<'_> {
    /// A proven handle on the repository pinned at `commit`: the commit is
    /// here, and is a commit.
    pub(super) fn handle_at(&self, commit: &GitOid) -> Result<GitWireRepo> {
        let repo_ref = RepoRef::LocalFolder {
            path: self.root.to_string_lossy().into_owned(),
            commit: commit.as_str().to_owned(),
        };
        self.wire.open_repo(repo_ref, &self.root)
    }
}

/// Whether a request's caller expiry has passed.
pub(super) fn expired(view: &OriginPublishRequestView, now: u64) -> bool {
    view.expires_at.is_some_and(|at| now >= at)
}

/// The refusal of a call that could not read the mirror's branch: nothing
/// is recorded or sent (CALLS "FIX 6866 unknown remote tip").
pub(super) fn remote_tip_unknown(ref_name: &str, error: &Error) -> Error {
    Error::Refused(format!(
        "remote_tip_unknown: the mirror's {ref_name} could not be read with its credential \
         ({error}); nothing was recorded or sent, and no absent branch is assumed"
    ))
}

impl Vault {
    /// The served repository `repo`.
    pub(super) fn publish_scope(&self, repo: &str) -> Result<PublishScope<'_>> {
        let root = origin_repo_dir(self, repo)?;
        let wire = GitWire::new(self)?;
        let common = wire.canonical_common_dir(&root.canonicalize()?)?;
        Ok(PublishScope {
            repo_id: self.served_mirror_repo_id(repo)?,
            root,
            common,
            wire,
        })
    }

    /// Records a request to publish one exact commit to one branch of the
    /// repository's mirror, once, with its full-ancestry review. The same
    /// idempotency key answers the same request.
    pub fn origin_publish_request(
        &self,
        caller: &OriginPublishCaller<'_>,
        input: OriginPublishRequestInput,
    ) -> Result<PublishAnswer<OriginPublishRequestView>> {
        let (name, commit) = validated(&input, self.now_recorded_at())?;
        let scope = self.publish_scope(&input.repo)?;
        let member = match self.admit_publish_member(&scope, caller, input.code_repo)? {
            Ok(member) => member,
            Err(denial) => return Ok(Err(denial)),
        };
        let request_id = match &input.idempotency_key {
            Some(key) => keyed_request_id(&scope.repo_id, key)?,
            None => EntityId::now(),
        };
        let target = PublishTarget {
            code_repo: input.code_repo,
            ref_name: &input.ref_name,
            rewrite: input.force == OriginPublishForce::Rewrite,
        };
        if let Some(existing) = self.publish_request(scope.repo_id, request_id)? {
            let txn = self.store.env.read_txn()?;
            return self.replay_publish_request(&txn, caller, &member, target, &input, existing);
        }
        let mirror = self.served_origin_mirror(&input.repo)?.ok_or_else(|| {
            Error::Refused("the repository has no mirror; the owner sets one first".to_owned())
        })?;
        let destination = OriginPublishDestination {
            url: mirror.url,
            user: mirror.user,
            secret_ref: mirror.secret_ref,
            target_generation: mirror.target_generation,
        };
        let handle = scope.handle_at(&commit)?;
        let observed = self
            .read_publish_remote(&scope.wire, &handle, &destination, &name)
            .map_err(|error| remote_tip_unknown(&input.ref_name, &error))?;
        // The tip's history is subtracted only when this store holds it.
        let base = match observed.oid() {
            Some(tip) => {
                let kinds = scope.wire.object_info(&handle, std::slice::from_ref(tip))?;
                kinds
                    .get(tip)
                    .is_some_and(|kind| kind == "commit")
                    .then(|| tip.clone())
            }
            None => None,
        };
        let descends = match (observed.oid(), &base) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(tip), Some(_)) => scope.wire.commits_reachable_from(
                &handle,
                std::slice::from_ref(tip),
                std::slice::from_ref(&commit),
            )?,
        };
        if input.force == OriginPublishForce::FastForward
            && !descends
            && let Some(tip) = observed.oid()
        {
            return Err(Error::Refused(format!(
                "not_fast_forward: the mirror's {} stands at {}, which this commit does not \
                 descend from here; a history rewrite asks with force rewrite",
                input.ref_name,
                tip.as_str()
            )));
        }
        let built = self.build_publish_review(&scope.wire, &handle, &commit, base.as_ref())?;
        self.pin_publish_commit(&scope, &handle, request_id, &commit)?;
        let now = self.now_recorded_at();
        let mut txn = self.store.env.write_txn()?;
        if let Some(raced) = self.publish_request_in_txn(&txn, scope.repo_id, request_id)? {
            // Another writer took the key first: its row answers as a replay
            // does, and this call's pin goes only when it is not that row's.
            let distinct = raced.commit != input.commit;
            let answer = self.replay_publish_request(&txn, caller, &member, target, &input, raced);
            drop(txn);
            if distinct {
                self.release_pin_of(&scope, &handle, request_id, &commit);
            }
            return answer;
        }
        let authority =
            match self.admit_publish_act_in_txn(&txn, caller, &member, target, || {
                Ok(built.paths.clone())
            })? {
                Ok(authority) => authority,
                Err(denial) => {
                    drop(txn);
                    self.release_pin_of(&scope, &handle, request_id, &commit);
                    return Ok(Err(denial));
                }
            };
        let view = OriginPublishRequestView {
            request_id,
            repo: input.repo,
            repo_id: scope.repo_id,
            destination,
            ref_name: input.ref_name,
            commit: input.commit,
            expected_remote: remote_of(&observed),
            force: input.force,
            code_repo: input.code_repo,
            idempotency_key: input.idempotency_key,
            expires_at: input.expires_at,
            review: built.review,
            state: OriginPublishState::Pending,
            requested: OriginPublishAct {
                actor: Some(caller.actor),
                class: caller.class.into(),
                authority,
                at: now,
            },
            approved: None,
            dispatched: None,
            refusal: None,
            created_at: now,
            finished_at: None,
        };
        self.put_publish_request_in_txn(&mut txn, &view, &built.pages)?;
        txn.commit()?;
        Ok(Ok(view))
    }

    /// Drops a pin a refused request took before it was recorded.
    fn release_pin_of(
        &self,
        scope: &PublishScope<'_>,
        handle: &GitWireRepo,
        request_id: EntityId,
        commit: &GitOid,
    ) {
        let owner = request_id.to_hex();
        let kind = crate::origin::publication::OriginKeepRefKind::PublishRequest;
        let at = self.now_recorded_at();
        if let Err(error) = self.unpin_origin_object(&scope.wire, handle, kind, &owner, commit, at)
        {
            tracing::warn!(kind = ?error.kind(), "publish request pin was not released");
        }
    }
}

/// The input's branch and commit, checked: a full `refs/heads/` ref, an
/// exact commit, a bounded printable key and an expiry still ahead.
fn validated(input: &OriginPublishRequestInput, now: u64) -> Result<(GitRefName, GitOid)> {
    let name = GitRefName::parse_full(input.ref_name.clone())?;
    if !input.ref_name.starts_with(BRANCH_PREFIX) {
        return Err(Error::InvalidConfig(
            "an exact publish names a full branch ref, refs/heads/...".to_owned(),
        ));
    }
    let commit = GitOid::parse_hex(input.commit.clone())?;
    if let Some(key) = &input.idempotency_key
        && (key.is_empty()
            || key.len() > ORIGIN_PUBLISH_MAX_KEY_BYTES
            || key.chars().any(char::is_control))
    {
        return Err(Error::InvalidConfig(format!(
            "an idempotency key is 1 to {ORIGIN_PUBLISH_MAX_KEY_BYTES} bytes with no control \
             character"
        )));
    }
    if input.expires_at.is_some_and(|at| at <= now) {
        return Err(Error::InvalidConfig(
            "expires_at has already passed".to_owned(),
        ));
    }
    Ok((name, commit))
}

/// Whether a request already under the key is the one asked for again.
fn same_request(
    existing: &OriginPublishRequestView,
    input: &OriginPublishRequestInput,
    actor: EntityId,
) -> bool {
    existing.ref_name == input.ref_name
        && existing.commit == input.commit
        && existing.force == input.force
        && existing.code_repo == input.code_repo
        && existing.expires_at == input.expires_at
        && existing.requested.actor == Some(actor)
}
