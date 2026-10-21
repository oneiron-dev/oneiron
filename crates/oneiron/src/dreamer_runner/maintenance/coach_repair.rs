//! The Coach's draft-first skill repair (ARCH-0066 #healer, OF-418). When a
//! case's or a blocked report's route question answers `skill_edit`, the
//! Coach drafts a revision of the skill the failure names, or else of the one
//! skill the failing run's pack loaded, through the optimizer's exact-target
//! door, aimed at the failure (FIX 2495) and at what the engine recorded of
//! its cause (OF-418 L10), and the heal carries it as a `SkillEdit` repair
//! for the owner to review. The revision is a gated
//! candidate like any optimizer draft: the Dreamer's optimize pass scores it,
//! and nothing here admits it. A draft that went stale before the heal's
//! write leaves that heal route-only, saying why (FIX 2497). The other
//! routes stay route-only.
use crate::attempt_queue::{AttemptId, AttemptQueue, ManifestEntry, ManifestKind};
use crate::claim::ClaimApprovalStatus;
use crate::failure_ladder::{HealerCase, HealerRepairRoute};
use crate::registry::ENTITY_TYPE_SKILL;
use crate::self_heal::HealEvidenceContext;
use crate::self_heal::blocked_reports::BlockedIssue;
use crate::skill::SkillLifecycle;
use crate::skill_optimize::{
    SkillEditCycle, SkillEditDraft, SkillFailureContext, SkillOptimizeBrief, SkillRepairStamp,
    propose_skill_repair_in_txn, proven_cycle, skill_repair_brief, validate_skill_draft,
};

use super::coach_heal::CoachHealAuthor;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Result, Vault};

/// Skill ids one page of the target sweep reads.
const SKILL_PAGE: usize = 256;

/// What the Coach drafted for one `skill_edit` heal.
pub(super) enum SkillRepairDraft {
    /// A validated revision of `brief`'s target, bound to the failing agent,
    /// with the candidate id it lands at and the stamp it is born with.
    Drafted {
        brief: SkillOptimizeBrief,
        desc: String,
        rationale: String,
        candidate: EntityId,
        route: HealerRepairRoute,
        actor: WriteActor,
        cycle: SkillEditCycle,
        resident: Option<EntityId>,
    },
    /// No revision: the heal stays route-only. `why` is a token the owner
    /// reads beside the route.
    Skipped {
        skill: Option<EntityId>,
        why: &'static str,
    },
}

impl SkillRepairDraft {
    /// The `repair` the heal's value carries: the drafted route with its
    /// instructions and rationale, or what was skipped and why.
    pub(super) fn value(&self) -> serde_json::Value {
        match self {
            Self::Drafted {
                desc,
                rationale,
                route,
                ..
            } => serde_json::json!({
                "route": route,
                "instructions": desc,
                "rationale": rationale,
            }),
            Self::Skipped { skill, why } => serde_json::json!({
                "skill": skill.map(|skill| skill.to_hex()),
                "skipped": why,
            }),
        }
    }
}

/// Which skill a heal repairs: the one the failure names; else, when the
/// failing run's pack loaded exactly one skill, that one; else none. The
/// policy hook for the Engine's 10-17 ruling (CALLS: OF-418 SkillEdit target).
fn repair_target(vault: &Vault, case: &HealerCase) -> Result<Option<EntityId>> {
    if let Some(skill) = &case.scope.skill_ref {
        return Ok(EntityId::from_hex(skill).ok());
    }
    run_target(vault, case.failing_attempt_id)
}

/// The one active skill the run `attempt` loaded, under the same ruled
/// policy for a case and a blocked report (FIX 2496): when its pack loaded
/// exactly one skill and exactly one active skill answers it, that one; else
/// none. A closed run's pack receipt says what its pack loaded; a run still
/// live has no receipt yet, and its attempt's manifest says what it has
/// loaded so far.
fn run_target(vault: &Vault, attempt: AttemptId) -> Result<Option<EntityId>> {
    let receipt_id = crate::receipt::attempt_pack_receipt_id(&attempt);
    let manifest = match crate::receipt::attempt_pack_receipt(vault, &receipt_id)? {
        Some(receipt) => receipt.pack_manifest_skills(),
        None => AttemptQueue::new(vault).get(attempt)?.map(|record| {
            record
                .manifest()
                .iter()
                .filter(|entry| entry.kind == ManifestKind::Skill)
                .map(ManifestEntry::wire_form)
                .collect()
        }),
    };
    let Some(manifest) = manifest else {
        return Ok(None);
    };
    let [entry] = manifest.as_slice() else {
        return Ok(None);
    };
    let resident = crate::skill::resident::receipt_resident(vault, &receipt_id)?;
    let mut found = None;
    let mut after = None;
    loop {
        let page = vault.entities_by_type_page(ENTITY_TYPE_SKILL, after.as_ref(), SKILL_PAGE)?;
        for id in &page {
            let Some(record) = vault.get_skill_record(id)? else {
                continue;
            };
            if record.lifecycle_status != SkillLifecycle::Active
                || !crate::skill_attribution::manifest_entry_names_skill(entry, &record)
            {
                continue;
            }
            let fork_of = crate::skill::resident_of(&record)?;
            if fork_of.is_some() && fork_of != resident {
                continue;
            }
            if found.replace(*id).is_some() {
                return Ok(None);
            }
        }
        if page.len() < SKILL_PAGE {
            return Ok(found);
        }
        after = page.last().copied();
    }
}

/// What one `skill_edit` heal drafts for: the skill it repairs, `None`
/// when no single one resolves, the agent and diagnosis its route names, the
/// failure the draft is aimed at, and what was recorded of its cause (OF-418
/// L10), which the author reads as data beside the brief.
struct RepairAim {
    skill: Option<EntityId>,
    agent_ref: String,
    diagnosis_ref: String,
    failure: SkillFailureContext,
    cause: HealEvidenceContext,
}

impl Vault {
    /// Drafts the revision a case's `skill_edit` heal carries, aimed at
    /// `failure` and its recorded `cause`, bound to the failing attempt's
    /// agent and its pre-fail context. `attempt` is the Coach's heal lease
    /// the candidate is born under.
    pub(super) fn draft_coach_skill_repair(
        &self,
        case: &HealerCase,
        failure: SkillFailureContext,
        cause: HealEvidenceContext,
        author: &dyn CoachHealAuthor,
        attempt: AttemptId,
        now: u64,
    ) -> Result<SkillRepairDraft> {
        let aim = RepairAim {
            skill: repair_target(self, case)?,
            agent_ref: case.scope.agent_ref.clone(),
            diagnosis_ref: case.evidence_ref.clone(),
            failure,
            cause,
        };
        let bound = |route: &HealerRepairRoute| {
            EntityId::from_hex(&case.pre_fail_checkpoint_ref).is_ok_and(|checkpoint| {
                crate::genui::require_diagnosed_route(
                    self,
                    case.failing_attempt_id,
                    checkpoint,
                    route,
                )
                .is_ok()
            })
        };
        self.draft_skill_repair(aim, bound, author, attempt, now)
    }

    /// Drafts the revision a blocked report's `skill_edit` heal carries
    /// (FIX 2496), aimed at `failure` and its recorded `cause`: of the one
    /// active skill the report's run loaded, bound to the agent the report
    /// was witnessed for, which must be the agent that run dispatched. A
    /// report with no durable run,
    /// or whose run loaded no single skill, stays route-only. No failed case
    /// or pre-fail checkpoint stands behind a report, and none is made up: a
    /// skill edit forks nothing.
    pub(super) fn draft_coach_issue_repair(
        &self,
        issue: &BlockedIssue,
        failure: SkillFailureContext,
        cause: HealEvidenceContext,
        author: &dyn CoachHealAuthor,
        attempt: AttemptId,
        now: u64,
    ) -> Result<SkillRepairDraft> {
        let run = issue
            .run
            .map(|run| AttemptId::from_bytes(run.as_bytes()))
            .transpose()?;
        let aim = RepairAim {
            skill: match run {
                Some(run) => run_target(self, run)?,
                None => None,
            },
            agent_ref: issue.reporter.to_hex(),
            diagnosis_ref: issue.diagnostic.to_hex(),
            failure,
            cause,
        };
        let bound = |_: &HealerRepairRoute| {
            run.and_then(|run| AttemptQueue::new(self).get(run).ok().flatten())
                .is_some_and(|record| {
                    crate::failure_ladder::dispatched_target_ref(&record) == Some(issue.reporter)
                })
        };
        self.draft_skill_repair(aim, bound, author, attempt, now)
    }

    /// Drafts the revision a `skill_edit` heal carries, outside any storage
    /// transaction: the target's DEV-only brief with the failure it is aimed
    /// at, and the route's binding (`bound`) to the failing agent, then the
    /// author, which reads the recorded cause beside the brief. A target that does not resolve, one the optimizer may not
    /// revise, an unbound route, a decline, a failed author and an unusable
    /// draft each leave the heal route-only.
    fn draft_skill_repair(
        &self,
        aim: RepairAim,
        bound: impl FnOnce(&HealerRepairRoute) -> bool,
        author: &dyn CoachHealAuthor,
        attempt: AttemptId,
        now: u64,
    ) -> Result<SkillRepairDraft> {
        let Some(skill) = aim.skill else {
            return Ok(SkillRepairDraft::Skipped {
                skill: None,
                why: "no_single_skill",
            });
        };
        let skipped = |why| {
            Ok(SkillRepairDraft::Skipped {
                skill: Some(skill),
                why,
            })
        };
        let Some(record) = self.get_skill_record(&skill)? else {
            return skipped("not_revisable");
        };
        let resident = crate::skill::resident_of(&record)?;
        let Ok(mut brief) = skill_repair_brief(self, &skill, now) else {
            return skipped("not_revisable");
        };
        // FIX 2495: the draft is aimed at the failure, read whole.
        brief.failure = Some(aim.failure);
        let candidate = self.store.clock.entity_id()?;
        let route = HealerRepairRoute::SkillEdit {
            agent_ref: aim.agent_ref,
            skill_ref: skill.to_hex(),
            patch_ref: candidate.to_hex(),
            diagnosis_ref: aim.diagnosis_ref,
        };
        if !bound(&route) {
            return skipped("unbound_agent");
        }
        let (desc, rationale) = match author.draft_skill(&brief, &aim.cause) {
            Ok(SkillEditDraft::Edit { desc, rationale }) => (desc, rationale),
            Ok(_) => return skipped("declined"),
            Err(_) => return skipped("author_failed"),
        };
        if validate_skill_draft(&brief, &desc, &rationale).is_err() {
            return skipped("unusable_draft");
        }
        Ok(SkillRepairDraft::Drafted {
            brief,
            desc,
            rationale,
            candidate,
            route,
            actor: self.dreamer_actor_for_attempt(attempt)?,
            cycle: proven_cycle(self, attempt)?,
            resident,
        })
    }
}

/// Lands a drafted revision as a gated candidate in the heal's transaction,
/// at the id its `SkillEdit` route names as the patch, stamped with the
/// Coach's `facet` and heal `attempt`. A skipped draft lands nothing. A draft
/// that went stale between its drafting and this transaction lands nothing
/// either, and the heal still files, route-only (FIX 2497): `Ok(Some(..))`
/// is the `repair` value it files in place of the draft's, naming why.
pub(super) fn land_skill_repair_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    draft: &SkillRepairDraft,
    facet: &str,
    attempt: AttemptId,
    now: u64,
) -> Result<Option<serde_json::Value>> {
    let SkillRepairDraft::Drafted {
        brief,
        desc,
        rationale,
        candidate,
        actor,
        cycle,
        resident,
        ..
    } = draft
    else {
        return Ok(None);
    };
    if let Some(why) = stale_in_txn(vault, txn, brief, *resident)? {
        let route_only = SkillRepairDraft::Skipped {
            skill: Some(brief.skill),
            why,
        };
        return Ok(Some(route_only.value()));
    }
    let stamp = SkillRepairStamp {
        actor: *actor,
        facet,
        attempt,
        cycle,
        owner: None,
        resident: *resident,
    };
    propose_skill_repair_in_txn(
        vault,
        txn,
        brief,
        desc,
        rationale,
        &stamp,
        candidate,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?;
    Ok(None)
}

/// Why a draft of `brief`'s target can no longer land, read in the heal's
/// write transaction, by the optimizer write door's own tests: the target
/// moved since the draft read it (`target_moved`), or it has an open proposed
/// revision now (`target_has_open_revision`). `None` while it still lands.
fn stale_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    brief: &SkillOptimizeBrief,
    resident: Option<EntityId>,
) -> Result<Option<&'static str>> {
    use crate::ports::EntityStoreRead;
    let Some(target) = vault.get_skill_record_in_txn(txn, &brief.skill)? else {
        return Ok(Some("target_moved"));
    };
    if target.lifecycle_status != SkillLifecycle::Active
        || target.version != brief.version
        || target.desc != brief.desc
        || crate::skill::resident_of(&target)? != resident
    {
        return Ok(Some("target_moved"));
    }
    for id in vault
        .store
        .port_entity_ids_by_type(txn, ENTITY_TYPE_SKILL, None)?
    {
        let Some(other) = vault.get_skill_record_in_txn(txn, &id?)? else {
            continue;
        };
        if other.lifecycle_status == SkillLifecycle::Candidate
            && other.approval_status == ClaimApprovalStatus::Proposed
            && other.skill_id == target.skill_id
            && crate::skill::resident_of(&other)? == resident
        {
            return Ok(Some("target_has_open_revision"));
        }
    }
    Ok(None)
}
