//! The Coach's draft-first skill repair (ARCH-0066 #healer, OF-418). When a
//! case's route question answers `skill_edit`, the Coach drafts a revision of
//! the skill the failure names, or else of the one skill the failing run's
//! pack loaded, through the optimizer's exact-target door, and the heal
//! carries it as a `SkillEdit` repair for the owner to review. The revision
//! is a gated candidate like any optimizer draft: the Dreamer's optimize pass
//! scores it, and nothing here admits it. The other routes stay route-only.
use crate::attempt_queue::AttemptId;
use crate::failure_ladder::{HealerCase, HealerRepairRoute};
use crate::registry::ENTITY_TYPE_SKILL;
use crate::skill::SkillLifecycle;
use crate::skill_optimize::{
    SkillEditCycle, SkillEditDraft, SkillOptimizeAuthor, SkillOptimizeBrief, SkillRepairStamp,
    propose_skill_repair_in_txn, proven_cycle, skill_repair_brief, validate_skill_draft,
};
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
    let receipt_id = crate::receipt::attempt_pack_receipt_id(&case.failing_attempt_id);
    let Some(receipt) = crate::receipt::attempt_pack_receipt(vault, &receipt_id)? else {
        return Ok(None);
    };
    let Some(manifest) = receipt.pack_manifest_skills() else {
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

impl Vault {
    /// Drafts the revision a `skill_edit` heal carries, outside any storage
    /// transaction: the target's DEV-only brief and the route's binding to the
    /// failing attempt's agent, then the author. A target that does not
    /// resolve, one the optimizer may not revise, an unbound route, a decline,
    /// a failed author and an unusable draft each leave the heal route-only.
    /// `attempt` is the Coach's heal lease the candidate is born under.
    pub(super) fn draft_coach_skill_repair(
        &self,
        case: &HealerCase,
        author: &dyn SkillOptimizeAuthor,
        attempt: AttemptId,
        now: u64,
    ) -> Result<SkillRepairDraft> {
        let Some(skill) = repair_target(self, case)? else {
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
        let Ok(brief) = skill_repair_brief(self, &skill, now) else {
            return skipped("not_revisable");
        };
        let candidate = self.store.clock.entity_id()?;
        let route = HealerRepairRoute::SkillEdit {
            agent_ref: case.scope.agent_ref.clone(),
            skill_ref: skill.to_hex(),
            patch_ref: candidate.to_hex(),
            diagnosis_ref: case.evidence_ref.clone(),
        };
        let bound = EntityId::from_hex(&case.pre_fail_checkpoint_ref).is_ok_and(|checkpoint| {
            crate::genui::require_diagnosed_route(self, case.failing_attempt_id, checkpoint, &route)
                .is_ok()
        });
        if !bound {
            return skipped("unbound_agent");
        }
        let (desc, rationale) = match author.draft(&brief) {
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
/// Coach's `facet` and heal `attempt`. A skipped draft lands nothing.
pub(super) fn land_skill_repair_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    draft: &SkillRepairDraft,
    facet: &str,
    attempt: AttemptId,
    now: u64,
) -> Result<()> {
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
        return Ok(());
    };
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
    )
}
