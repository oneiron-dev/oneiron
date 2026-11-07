//! The remote half of an automatic mirror push plan (FIX 6866 part 2): the
//! authenticated read of what the mirror holds at a plan's refs, and the
//! push of some of a plan's refs exactly as frozen. On a served host both go
//! through its transport (`origin::git_transport`, FIX 19083) alone, which
//! sends each exchange through the credential broker: the mirror's token
//! never reaches git, and nothing falls back to the direct path. On an
//! embedded vault both go through the custody door bound to
//! `origin:mirror-push`, whose token reaches git only as the one child's
//! header. Either way they ride the mirror push's fixed outbound profile
//! (`git_wire::mirror_plan_push`) and send each child's refs exactly as
//! frozen; the plan's reconcile and same-plan resend are its own.

use std::collections::BTreeMap;

use super::mirror_plan::MirrorRunScope;
use super::mirror_plan_types::{MirrorObservedTip, MirrorPushPlan};
use super::secret_hold::MirrorPlanSend;
use super::types::OriginPublishDestination;
use crate::Vault;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitPlanPushReport, GitPlanRef, GitRefName};
use crate::origin::git_transport::{OriginGitPlanPush, OriginGitPlanPushReport};

/// The longest redacted cause a plan keeps.
pub(super) const MIRROR_PLAN_MAX_DETAIL_BYTES: usize = 256;

impl Vault {
    /// What the mirror holds at each of `names`, read with its credential:
    /// through the served host's transport when one is installed, which
    /// never falls back to the direct read. A read that fails leaves every
    /// name `unknown`, with its redacted cause, never absent.
    pub(super) fn observe_mirror_refs(
        &self,
        scope: &MirrorRunScope<'_, '_>,
        destination: &OriginPublishDestination,
        names: &[GitRefName],
    ) -> BTreeMap<GitRefName, MirrorObservedTip> {
        let read = if let Some(transport) = self.served_origin_git_transport() {
            transport.read_remote_refs(scope.wire, scope.handle, destination, names)
        } else {
            let mut answer = Err(Error::InvariantViolation("mirror remote read never ran"));
            let door = self.with_publish_credential(destination, &mut |header| {
                answer = scope
                    .wire
                    .read_remote_refs(scope.handle, &destination.url, names, header);
            });
            door.and(answer)
        };
        match read {
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
        let pushed = if sent.is_empty() {
            OriginGitPlanPushReport {
                report: Ok(GitPlanPushReport {
                    outcomes: Vec::new(),
                    failure: None,
                }),
                broker_isolation: None,
            }
        } else {
            self.push_mirror_plan_members(scope, plan, &sent)
        };
        MirrorPlanSend {
            held,
            sent,
            report: pushed.report,
            broker_isolation: pushed.broker_isolation,
        }
    }

    /// The one child that pushes `members`: through the served host's
    /// transport when one is installed, which sends it once and never falls
    /// back to the direct push.
    fn push_mirror_plan_members(
        &self,
        scope: &MirrorRunScope<'_, '_>,
        plan: &MirrorPushPlan,
        members: &[u32],
    ) -> OriginGitPlanPushReport {
        let refs = match members
            .iter()
            .map(|index| plan_ref_out(plan, *index))
            .collect::<Result<Vec<_>>>()
        {
            Ok(refs) => refs,
            Err(error) => {
                return OriginGitPlanPushReport {
                    report: Err(error),
                    broker_isolation: None,
                };
            }
        };
        if let Some(transport) = self.served_origin_git_transport() {
            let push = OriginGitPlanPush {
                repo_id: plan.repo_id,
                destination: &plan.destination,
                refs: &refs,
                hold: scope.hold,
            };
            let mut pushed = transport.push_mirror_plan_batch(scope.wire, scope.handle, &push);
            // The host names its refusal in the cause; the plan keeps it
            // bounded, as every cause it keeps.
            if let Ok(report) = &mut pushed.report {
                report.failure = report.failure.take().map(bounded);
            }
            return pushed;
        }
        let mut answer = Err(Error::InvariantViolation("mirror plan push never ran"));
        let door = self.with_publish_credential(&plan.destination, &mut |header| {
            answer = scope.wire.push_mirror_plan_batch(
                scope.handle,
                &plan.destination.url,
                &refs,
                scope.hold,
                header,
            );
        });
        OriginGitPlanPushReport {
            report: door.and(answer),
            broker_isolation: None,
        }
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

/// A cause cut to [`MIRROR_PLAN_MAX_DETAIL_BYTES`] on a character boundary.
pub(super) fn bounded(mut text: String) -> String {
    let mut cut = text.len().min(MIRROR_PLAN_MAX_DETAIL_BYTES);
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text.truncate(cut);
    text
}
