//! The one dispatch of an approved exact publish request (FIX 6866).
//!
//! Before anything goes out it checks, in order: the request is approved and
//! not expired; this host is the repository's origin; the commit is still
//! held here; the mirror's URL, user, custody record and generation are the
//! request's (before any credential or remote IO); the branch at the mirror,
//! read with the mirror's credential, still holds the leased tip (or already
//! holds the commit). Then one write transaction, under the coordinator a
//! cutover takes, admits the caller again, finds the request unexpired at
//! the vault's time, the mirror unchanged, this host still the origin and
//! the approval's owner or Grant still standing, and claims the request
//! `dispatching`. The mirror's push hold is held from that read to the
//! push's end, so no automatic run reaches the mirror between the lease's
//! read and the push (FIX 7174). Only then does its one push run, and its
//! outcome settles the request (`reconcile`), unless the publication gate
//! holds the commit's history first: a public or unstated mirror never
//! takes a marked live key, and the request settles refused, typed
//! (`secret_hold`). The strategy is never read: an approved request executes
//! once on a mirror of either.

use super::authority::{OriginPublishCaller, PublishAnswer, PublishTarget};
use super::inputs::OriginPublishIdRequest;
use super::reconcile::{expected_oid, refusal};
use super::types::{
    OriginPublishAct, OriginPublishDestination, OriginPublishRefusalReason,
    OriginPublishRequestView, OriginPublishState,
};
use crate::Vault;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitRefName, lock_repository};
use crate::origin::mirror::{OriginMirrorTarget, TARGETS};
use crate::origin::mirror_run::mirror_hold_dir;
use crate::origin::smart_http::push_queue_key;

const APPROVED: [OriginPublishState; 1] = [OriginPublishState::Approved];

impl Vault {
    /// Pushes an approved request's commit to its branch once, or settles a
    /// claimed one from the mirror. A pending request is refused: its review
    /// digest is approved first.
    pub fn origin_publish_execute(
        &self,
        caller: &OriginPublishCaller<'_>,
        input: OriginPublishIdRequest,
    ) -> Result<PublishAnswer<OriginPublishRequestView>> {
        let (scope, member, view) = match self.admitted_publish_request(
            caller,
            &input.repo,
            input.request_id,
            input.code_repo,
        )? {
            Ok(admitted) => admitted,
            Err(denial) => return Ok(Err(denial)),
        };
        match view.state {
            OriginPublishState::Approved => {}
            OriginPublishState::Dispatching => {
                return Ok(Ok(self.settle_stale_dispatch(&scope, view)?));
            }
            OriginPublishState::Pending => {
                return Err(Error::Refused(
                    "approve the request's review digest with vault.code.origin.publish.approve \
                     first"
                        .to_owned(),
                ));
            }
            _ => return Ok(Ok(view)),
        }
        if super::expired(&view, self.now_recorded_at()) {
            let expired =
                self.settle_publish(&view, &APPROVED, OriginPublishState::Expired, None)?;
            return Ok(Ok(expired));
        }
        self.require_mirror_pusher(&view.repo)?;
        let commit = GitOid::parse_hex(view.commit.clone())?;
        let name = GitRefName::parse_full(view.ref_name.clone())?;
        let Ok(handle) = scope.handle_at(&commit) else {
            let missing = refusal(
                OriginPublishRefusalReason::ObjectsMissing,
                None,
                Vec::new(),
                None,
            );
            let refused =
                self.settle_publish(&view, &APPROVED, OriginPublishState::Refused, Some(missing))?;
            return Ok(Ok(refused));
        };
        let anchor = match &member {
            super::authority::PublishMember::Grant { anchor } => Some(anchor.clone()),
            super::authority::PublishMember::Owner => self.approval_anchor(&scope, &view)?,
        };
        let current = {
            let txn = self.store.env.read_txn()?;
            TARGETS.get(&self.store, &txn, &view.repo_id)?
        };
        let changed = changed_fields(&view.destination, current.as_ref());
        if !changed.is_empty() {
            let reason = OriginPublishRefusalReason::DestinationChanged;
            let moved = refusal(reason, None, changed, None);
            let refused =
                self.settle_publish(&view, &APPROVED, OriginPublishState::Refused, Some(moved))?;
            return Ok(Ok(refused));
        }
        // The mirror's push hold, from the read the lease stands on to the
        // push's end: no automatic run reaches the mirror meanwhile, and the
        // push's child inherits it, so a claim is settled elsewhere only once
        // no push of it runs. Taken before the coordinator, as a run does.
        let push_hold = mirror_hold_dir(&handle)?;
        let _held = lock_repository(&push_hold)?;
        let observed = self
            .read_publish_remote(&scope.wire, &handle, &view.destination, &name)
            .map_err(|error| super::remote_tip_unknown(&view.ref_name, &error))?;
        let expected = expected_oid(&view.expected_remote)?;

        let coordinator = lock_repository(&push_queue_key(self, &view.repo)?)?;
        let mut txn = self.store.env.write_txn()?;
        let paths = self.publish_review_paths_in_txn(&txn, &view)?;
        let authority = match self.admit_publish_act_in_txn(
            &txn,
            caller,
            &member,
            PublishTarget::of(&view),
            || Ok(paths.clone()),
        )? {
            Ok(authority) => authority,
            Err(denial) => return Ok(Err(denial)),
        };
        let changed = changed_fields(
            &view.destination,
            TARGETS.get(&self.store, &txn, &view.repo_id)?.as_ref(),
        );
        let (to, refused) = if super::expired(&view, self.now_recorded_at()) {
            (OriginPublishState::Expired, None)
        } else if !changed.is_empty() {
            let reason = OriginPublishRefusalReason::DestinationChanged;
            (
                OriginPublishState::Refused,
                Some(refusal(reason, None, changed, None)),
            )
        } else if !self.origin_pusher_stands_in_txn(&txn, scope.repo_id)?
            || !self.approval_stands_in_txn(&txn, &view, anchor.as_ref(), &paths)?
        {
            let reason = OriginPublishRefusalReason::AuthorityChanged;
            (
                OriginPublishState::Refused,
                Some(refusal(reason, None, Vec::new(), None)),
            )
        } else if observed.oid() == Some(&commit) {
            (OriginPublishState::ObservedPublished, None)
        } else if observed.oid() != expected.as_ref() {
            let reason = OriginPublishRefusalReason::RemoteMoved;
            let observed = Some(&observed);
            (
                OriginPublishState::Refused,
                Some(refusal(reason, observed, Vec::new(), None)),
            )
        } else {
            (OriginPublishState::Dispatching, None)
        };
        let act = OriginPublishAct {
            actor: Some(caller.actor),
            class: caller.class.into(),
            authority,
            at: self.now_recorded_at(),
        };
        let (claimed, moved) =
            self.transition_publish_in_txn(&mut txn, &view, &APPROVED, to, |row| {
                if to == OriginPublishState::Dispatching {
                    row.dispatched = Some(act);
                }
                row.refusal = refused;
            })?;
        txn.commit()?;
        drop(coordinator);
        if !moved {
            return Ok(Ok(claimed));
        }
        if claimed.state.is_terminal() {
            self.release_publish_pin(&claimed);
            return Ok(Ok(claimed));
        }
        if let Some(hold) = self.hold_publish_commit(&scope, &handle, &commit) {
            return Ok(Ok(self.settle_publish_hold(&claimed, hold)?));
        }
        let outcome = self.push_publish_once(
            &scope.wire,
            &handle,
            &claimed.destination,
            &name,
            &commit,
            expected.as_ref(),
            &push_hold,
        );
        Ok(Ok(
            self.settle_publish_push(&scope, &handle, &claimed, outcome)?
        ))
    }
}

/// The destination fields the mirror's current row holds otherwise than the
/// request recorded; every field when the mirror was cleared.
fn changed_fields(
    recorded: &OriginPublishDestination,
    current: Option<&OriginMirrorTarget>,
) -> Vec<String> {
    let Some(current) = current else {
        return vec!["mirror".to_owned()];
    };
    let mut changed = Vec::new();
    if current.url != recorded.url {
        changed.push("url".to_owned());
    }
    if current.user != recorded.user {
        changed.push("user".to_owned());
    }
    if current.secret_ref != recorded.secret_ref {
        changed.push("secret_ref".to_owned());
    }
    if current.target_generation != recorded.target_generation {
        changed.push("target_generation".to_owned());
    }
    changed
}
