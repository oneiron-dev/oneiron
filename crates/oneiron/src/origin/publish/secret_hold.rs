//! The publication gate at both kinds of send (FIX 7608 slice 9, A1): an
//! exact request's one push and each batch of an automatic plan ask
//! `require_no_marked_live_history` (`origin::secret_publication`) after
//! their claim and before the mirror's credential leaves custody.
//!
//! A held exact request settles `refused`, typed `marked_live_secret` or
//! `secret_history_unknown`, with the hold's value-free notice: it is never
//! sent, and a new request goes once a way out is taken. A held automatic
//! ref is never sent and stays `held` in its open plan (CALLS HOLD-AUTO):
//! each later run's reconcile reads it at the mirror, and its same frozen
//! tuple asks the gate again, so a mark written since holds it too. The
//! batch's clean refs go out as before, and so do the plan's later batches.

use super::PublishScope;
use super::mirror_plan::MirrorRunScope;
use super::mirror_plan_types::MirrorPushPlan;
use super::reconcile::refusal;
use super::types::{OriginPublishRefusalReason, OriginPublishRequestView, OriginPublishState};
use crate::Vault;
use crate::error::Result;
use crate::git_wire::{GitOid, GitPlanPushReport, GitWireRepo};
use crate::origin::secret_publication::SecretPublicationHold;

/// What one batch's send did.
pub(super) struct MirrorPlanSend {
    /// The members the gate held, never sent, and why.
    pub(super) held: Vec<(u32, SecretPublicationHold)>,
    /// The members that went out in one child, in order.
    pub(super) sent: Vec<u32>,
    /// That child's report; an empty one when the gate held every member
    /// and no child ran.
    pub(super) report: Result<GitPlanPushReport>,
}

impl MirrorPlanSend {
    /// The notice of the first hold, if the gate held any member.
    pub(super) fn hold_notice(&self) -> Option<String> {
        self.held.first().map(|(_, hold)| hold.notice())
    }
}

/// A run's failure part for the refs the gate holds, first in the run's
/// failure: the typed codes and the ways out, never a key or a mark.
pub(super) fn held_refs_failure(names: &[String]) -> String {
    format!(
        "secret_hold: {} held (marked_live_secret or secret_history_unknown): mark it not a \
         secret, revoke it at its provider, purge it, or state the mirror private",
        names.join(",")
    )
}

impl Vault {
    /// The gate's hold on an exact request's commit, at its mirror as the
    /// row stands now.
    pub(super) fn hold_publish_commit(
        &self,
        scope: &PublishScope<'_>,
        handle: &GitWireRepo,
        commit: &GitOid,
    ) -> Option<SecretPublicationHold> {
        self.require_no_marked_live_history(
            &scope.wire,
            handle,
            scope.repo_id,
            std::slice::from_ref(commit),
        )
        .into_iter()
        .next()
        .flatten()
    }

    /// Settles a claimed request the gate held: refused, typed, with the
    /// hold's notice. Nothing was sent.
    pub(super) fn settle_publish_hold(
        &self,
        view: &OriginPublishRequestView,
        hold: SecretPublicationHold,
    ) -> Result<OriginPublishRequestView> {
        let reason = match hold {
            SecretPublicationHold::MarkedLiveSecret => OriginPublishRefusalReason::MarkedLiveSecret,
            SecretPublicationHold::SecretHistoryUnknown => {
                OriginPublishRefusalReason::SecretHistoryUnknown
            }
        };
        let held = refusal(reason, None, Vec::new(), Some(hold.notice()));
        self.settle_publish(
            view,
            &[OriginPublishState::Dispatching],
            OriginPublishState::Refused,
            Some(held),
        )
    }

    /// Splits a batch's `members` into the refs the gate holds and the refs
    /// that go out, in order. A deletion exposes no history and is never
    /// held.
    pub(super) fn gate_mirror_plan_refs(
        &self,
        scope: &MirrorRunScope<'_, '_>,
        plan: &MirrorPushPlan,
        members: &[u32],
    ) -> (Vec<(u32, SecretPublicationHold)>, Vec<u32>) {
        let updates: Vec<(u32, GitOid)> = members
            .iter()
            .filter_map(|index| {
                let new = plan.refs.get(*index as usize)?.new.clone()?;
                GitOid::parse_hex(new).ok().map(|oid| (*index, oid))
            })
            .collect();
        let tips: Vec<GitOid> = updates.iter().map(|(_, oid)| oid.clone()).collect();
        let holds =
            self.require_no_marked_live_history(scope.wire, scope.handle, plan.repo_id, &tips);
        let held: Vec<(u32, SecretPublicationHold)> = updates
            .iter()
            .zip(holds)
            .filter_map(|((index, _), hold)| hold.map(|hold| (*index, hold)))
            .collect();
        let sent = members
            .iter()
            .copied()
            .filter(|index| !held.iter().any(|(member, _)| member == index))
            .collect();
        (held, sent)
    }
}
