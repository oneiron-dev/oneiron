//! The pins of automatic mirror push plans (FIX 7173): each open plan keeps
//! the objects it still sends behind its own keep owner
//! (`OriginKeepRefKind::MirrorWork`, the plan id), so a gc never takes one
//! that a same-plan resend needs.
//!
//! A plan pins before it is written (the physical-first pin protocol) and
//! releases once it settles; both run under the mirror's push hold, under
//! which alone a plan is frozen or settled. A plan forgotten, rebuilt away or
//! cleared, and one a crash left pinned before its row, is released by the
//! census, which sweeps only when it can take that hold at once. Only an
//! update whose object the mirror's ref did not hold when the plan read it
//! is pinned: a ref already there needs nothing kept. A pin or release that
//! fails only warns: a missing pin is the plan as it was before plans were
//! pinned, and a pin left behind keeps an object, never loses one.

use std::collections::BTreeSet;

use super::mirror_plan::MirrorRunScope;
use super::mirror_plan_types::MirrorPushPlan;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::git_wire::{GitOid, GitWire, GitWireRepo, try_lock_repository};
use crate::origin::mirror_run::mirror_hold_dir;
use crate::origin::publication::OriginKeepRefKind;

const KIND: OriginKeepRefKind = OriginKeepRefKind::MirrorWork;

impl Vault {
    /// Pins each object `plan` sends behind the plan's own owner, before
    /// the plan is written.
    pub(super) fn pin_mirror_plan_objects(
        &self,
        scope: &MirrorRunScope<'_, '_>,
        plan: &MirrorPushPlan,
    ) {
        let owner = plan.plan_id.to_hex();
        let now = self.now_recorded_at();
        let pinned = pinned_objects(plan).and_then(|objects| {
            for oid in &objects {
                self.pin_origin_object(scope.wire, scope.handle, KIND, &owner, oid, now)?;
            }
            Ok(())
        });
        if let Err(error) = pinned {
            tracing::warn!(kind = ?error.kind(), "an automatic mirror plan's objects were not pinned");
        }
    }

    /// Releases the pins of `plan`, settled or never written.
    pub(super) fn release_mirror_plan_pins(
        &self,
        wire: &GitWire<'_>,
        handle: &GitWireRepo,
        plan: &MirrorPushPlan,
    ) {
        let owner = plan.plan_id.to_hex();
        let now = self.now_recorded_at();
        let released = pinned_objects(plan).and_then(|objects| {
            for oid in &objects {
                if self.origin_keep_owner_held(plan.repo_id, oid, KIND, &owner)? {
                    self.unpin_origin_object(wire, handle, KIND, &owner, oid, now)?;
                }
            }
            Ok(())
        });
        if let Err(error) = released {
            tracing::warn!(kind = ?error.kind(), "an automatic mirror plan's pins were not released");
        }
    }

    /// The census's sweep: releases every plan pin of one repository whose
    /// plan is not its mirror's open one, when the mirror's push hold can be
    /// taken at once; a run holding it releases its own plan's.
    pub(super) fn sweep_settled_mirror_plan_pins(
        &self,
        git: &GitWire<'_>,
        repo_id: EntityId,
        repo: &GitWireRepo,
        learned_at: u64,
    ) -> Result<()> {
        // Listed before the hold: a plan pinned meanwhile was written under
        // the hold, so the head read under it names it open.
        let owners = self.origin_keep_owners_of_kind(repo_id, KIND)?;
        if owners.is_empty() {
            return Ok(());
        }
        let Some(_held) = try_lock_repository(&mirror_hold_dir(repo)?)? else {
            return Ok(());
        };
        let open = {
            let txn = self.store.env.read_txn()?;
            self.mirror_work_head_in_txn(&txn, repo_id)?.open
        };
        let open = open.map(|plan_id| plan_id.to_hex());
        for (oid, owner) in owners {
            if open.as_deref() != Some(owner.as_str()) {
                self.unpin_origin_object(git, repo, KIND, &owner, &oid, learned_at)?;
            }
        }
        Ok(())
    }
}

/// The objects a plan pins: each update a batch still sends whose object
/// the mirror's ref did not hold when the plan read it, once each.
fn pinned_objects(plan: &MirrorPushPlan) -> Result<Vec<GitOid>> {
    let objects: BTreeSet<&str> = plan
        .refs
        .iter()
        .filter(|plan_ref| plan_ref.batch.is_some())
        .filter_map(|plan_ref| {
            let new = plan_ref.new.as_deref()?;
            (plan_ref.observed.oid() != Some(new)).then_some(new)
        })
        .collect();
    objects.into_iter().map(GitOid::parse_hex).collect()
}
