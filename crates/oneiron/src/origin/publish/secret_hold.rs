//! Core half of `origin::publish::secret_hold`: its store-layer items live in `oneiron_store::origin::publish::secret_hold` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::origin::publish::secret_hold::*;

use super::PublishScope;
use super::mirror_plan::MirrorRunScope;
use super::mirror_plan_types::MirrorPushPlan;
use super::reconcile::refusal;
use super::types::{OriginPublishRefusalReason, OriginPublishRequestView, OriginPublishState};
use crate::Vault;
use crate::error::Result;
use crate::git_wire::{GitOid, GitPlanPushReport, GitWireRepo};
use crate::origin::secret_publication::SecretPublicationHold;

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
