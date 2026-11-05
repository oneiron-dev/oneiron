//! Core half of `origin::publish::mirror_plan_remote`: its store-layer items live in `oneiron_store::origin::publish::mirror_plan_remote` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::origin::publish::mirror_plan_remote::*;

use super::mirror_plan::MirrorRunScope;
use super::mirror_plan_types::{MirrorObservedTip, MirrorPushPlan};
use super::secret_hold::MirrorPlanSend;
use super::types::OriginPublishDestination;
use crate::Vault;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitPlanPushReport, GitPlanRef, GitRefName};
use std::collections::BTreeMap;

impl Vault {
    /// What the mirror holds at each of `names`, read with its credential.
    /// A read that fails leaves every name `unknown`, with its redacted
    /// cause, never absent.
    pub(super) fn observe_mirror_refs(
        &self,
        scope: &MirrorRunScope<'_, '_>,
        destination: &OriginPublishDestination,
        names: &[GitRefName],
    ) -> BTreeMap<GitRefName, MirrorObservedTip> {
        let mut answer = Err(Error::InvariantViolation("mirror remote read never ran"));
        let door = self.with_publish_credential(destination, &mut |header| {
            answer = scope
                .wire
                .read_remote_refs(scope.handle, &destination.url, names, header);
        });
        match door.and(answer) {
            Ok(tips) => names
                .iter()
                .map(|name| {
                    let tip = tips.get(name).map_or(MirrorObservedTip::Absent, |oid| {
                        MirrorObservedTip::At {
                            oid: oid.as_str().to_owned(),
                        }
                    });
                    (name.clone(), tip)
                })
                .collect(),
            Err(error) => {
                let cause = bounded(error.to_string());
                names
                    .iter()
                    .map(|name| {
                        let tip = MirrorObservedTip::Unknown {
                            cause: cause.clone(),
                        };
                        (name.clone(), tip)
                    })
                    .collect()
            }
        }
    }

    /// Pushes `members` of the plan in one child, each exactly as frozen,
    /// after the publication gate (`secret_hold`): a member it holds is
    /// never sent, and none goes before the gate has answered.
    pub(super) fn push_mirror_plan_refs(
        &self,
        scope: &MirrorRunScope<'_, '_>,
        plan: &MirrorPushPlan,
        members: &[u32],
    ) -> MirrorPlanSend {
        let (held, sent) = self.gate_mirror_plan_refs(scope, plan, members);
        let report = if sent.is_empty() {
            Ok(GitPlanPushReport {
                outcomes: Vec::new(),
                failure: None,
            })
        } else {
            self.push_mirror_plan_members(scope, plan, &sent)
        };
        MirrorPlanSend { held, sent, report }
    }

    /// The one child that pushes `members`.
    fn push_mirror_plan_members(
        &self,
        scope: &MirrorRunScope<'_, '_>,
        plan: &MirrorPushPlan,
        members: &[u32],
    ) -> Result<GitPlanPushReport> {
        let refs = members
            .iter()
            .map(|index| plan_ref_out(plan, *index))
            .collect::<Result<Vec<_>>>()?;
        let mut answer = Err(Error::InvariantViolation("mirror plan push never ran"));
        self.with_publish_credential(&plan.destination, &mut |header| {
            answer = scope.wire.push_mirror_plan_batch(
                scope.handle,
                &plan.destination.url,
                &refs,
                scope.hold,
                header,
            );
        })?;
        answer
    }
}

/// One frozen ref, as it goes out: its lease is the tip the plan read, or
/// none when the read failed.
fn plan_ref_out(plan: &MirrorPushPlan, index: u32) -> Result<GitPlanRef> {
    let plan_ref = plan
        .refs
        .get(index as usize)
        .ok_or(Error::CorruptedIndex("origin mirror plan ref"))?;
    let lease = match &plan_ref.observed {
        MirrorObservedTip::Absent => Some(None),
        MirrorObservedTip::At { oid } => Some(Some(GitOid::parse_hex(oid.clone())?)),
        MirrorObservedTip::Unknown { .. } => None,
    };
    Ok(GitPlanRef {
        name: GitRefName::parse_full(plan_ref.ref_name.clone())?,
        new: plan_ref
            .new
            .as_ref()
            .map(|new| GitOid::parse_hex(new.clone()))
            .transpose()?,
        lease,
    })
}
