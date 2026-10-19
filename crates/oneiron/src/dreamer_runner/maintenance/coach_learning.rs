//! The Coach's own record (ARCH-0066 #coach: "calibration, meta-learning"):
//! each anchored outcome of the Coach's own work is evidence for a
//! `learning.reliability` cell, one per kind of work (the cell's axis). A
//! skill edit is a held-out outcome: the gate scored the edited instructions
//! against the current ones on reserved evidence. An unknown outcome is no
//! evidence. A checked training offer is an outcome for the offer skill that
//! drafted it instead (`skill_optimize::record_offer_check`).
//!
//! The improver's edit is an outcome of the `skill-optimize` workflow
//! revision its drafting attempt loaded, on the model that ran it (ARCH-0079:
//! each recipe is a workflow skill). Work no loaded workflow did (a tree
//! arm, a draft whose attempt pinned none) keys the Coach's actor as subject
//! and executor. Each cell sits at the vault tree's root, since this work has
//! no task type.
use rmpv::Value;

use crate::attempt_queue::{AttemptId, AttemptQueue, ManifestKind};
use crate::learning::{
    Anchor, LearningCell, LearningEvidence, LearningPredicate, Observation, record_evidence,
};
use crate::registry::ENTITY_TYPE_SKILL;
use crate::skill::SkillRecord;
use crate::skill_optimize::PROVENANCE_OPTIMIZE_ATTEMPT_KEY;
use crate::{EntityId, Result, Vault};

/// The Coach's skill edits, scored by the held-out gate.
pub const COACH_SKILL_EDIT_AXIS: &str = "skill_edit";
/// The shipped workflow the Coach's improver runs (`skills/skill-optimize`).
pub const COACH_IMPROVER_SKILL: &str = "skill-optimize";

/// The improver workflow's shipped revision: the Coach loads it on each
/// optimization attempt it drafts on.
///
/// # Errors
///
/// Never in practice: the id derives from a fixed name.
pub fn coach_improver_skill_id() -> Result<EntityId> {
    EntityId::derive(
        crate::entity_id::derived_domains::BOOTSTRAP_SKILL,
        &[COACH_IMPROVER_SKILL.as_bytes()],
    )
}

/// The Coach's reliability cell for one kind of its work.
///
/// # Errors
///
/// Storage errors reading the vault's type tree.
pub fn coach_reliability_cell(vault: &Vault, axis: &str) -> Result<LearningCell> {
    let coach = crate::dreamer_runner::authority::coach_actor_id()?;
    Ok(LearningCell::new(LearningPredicate::Reliability, coach)
        .executor(coach.to_hex())
        .type_ref(crate::task_type::type_tree(vault, None)?.root())
        .axis(axis))
}

/// One anchored outcome of the Coach's work on `axis`. Recording the same
/// receipt again replaces its row, so a replayed pass counts once.
pub(super) fn record_coach_outcome(
    vault: &Vault,
    axis: &str,
    receipt: String,
    at: u64,
    anchor: Anchor,
    success: bool,
    now: u64,
) -> Result<()> {
    // The cell's subject must exist: this seeds the Coach's actor on a vault
    // whose Coach has not run yet.
    vault.coach_authority()?;
    let cell = coach_reliability_cell(vault, axis)?;
    record_evidence(
        vault,
        &cell,
        &LearningEvidence::anchored(receipt, at, anchor, Observation::Success(success)),
        now,
    )?;
    Ok(())
}

/// One held-out outcome of the improver's draft `proposal`: the workflow
/// revision its drafting attempt loaded owns it, on that attempt's model, a
/// resumed draft as much as a fresh one. A draft whose attempt pinned none is
/// the Coach's own. Recording the same proposal again replaces its row.
///
/// # Errors
///
/// Storage errors.
pub(super) fn record_improver_outcome(
    vault: &Vault,
    proposal: &EntityId,
    success: bool,
    at: u64,
) -> Result<()> {
    let receipt = format!("skill_edit:{}", proposal.to_hex());
    let Some(cell) = improver_cell(vault, proposal)? else {
        return record_coach_outcome(
            vault,
            COACH_SKILL_EDIT_AXIS,
            receipt,
            at,
            Anchor::HeldOut,
            success,
            at,
        );
    };
    record_evidence(
        vault,
        &cell,
        &LearningEvidence::anchored(receipt, at, Anchor::HeldOut, Observation::Success(success)),
        at,
    )?;
    Ok(())
}

/// The cell of the improver revision that drafted `proposal`: the attempt
/// its birth provenance names pinned [`COACH_IMPROVER_SKILL`] in its pack
/// manifest and stamped the model it ran on. `None` when any part is gone.
fn improver_cell(vault: &Vault, proposal: &EntityId) -> Result<Option<LearningCell>> {
    let Some(record) = vault.get_skill_record(proposal)? else {
        return Ok(None);
    };
    let Some(attempt) = provenance_text(&record.provenance, PROVENANCE_OPTIMIZE_ATTEMPT_KEY)
        .and_then(|attempt| EntityId::from_hex(attempt).ok())
    else {
        return Ok(None);
    };
    let attempt = AttemptId::from_bytes(attempt.as_bytes())?;
    let Some(row) = AttemptQueue::new(vault).get(attempt)? else {
        return Ok(None);
    };
    let Some(executor) = row.executor_model.as_deref() else {
        return Ok(None);
    };
    let Some(entry) = row
        .manifest
        .iter()
        .rev()
        .find(|entry| entry.kind == ManifestKind::Skill && entry.reference == COACH_IMPROVER_SKILL)
    else {
        return Ok(None);
    };
    let Some(revision) = improver_revision(vault, &entry.version)? else {
        return Ok(None);
    };
    let cell = LearningCell::new(LearningPredicate::Reliability, revision)
        .executor(executor)
        .type_ref(crate::task_type::type_tree(vault, None)?.root())
        .axis(COACH_SKILL_EDIT_AXIS);
    Ok(Some(cell))
}

/// The shared improver revision at `version`: the shipped one when it is
/// that version, else the one SKILL record of that name and version. `None`
/// when none, or more than one, is.
fn improver_revision(vault: &Vault, version: &str) -> Result<Option<EntityId>> {
    let pinned = |record: &SkillRecord| {
        record.skill_id == COACH_IMPROVER_SKILL && record.version == version
    };
    let shipped = coach_improver_skill_id()?;
    if vault
        .get_skill_record(&shipped)?
        .is_some_and(|record| pinned(&record))
    {
        return Ok(Some(shipped));
    }
    let mut found = None;
    for id in vault.entities_by_type(ENTITY_TYPE_SKILL)? {
        let Some(record) = vault.get_skill_record(&id)? else {
            continue;
        };
        if !pinned(&record) || crate::skill::resident_of(&record)?.is_some() {
            continue;
        }
        if found.replace(id).is_some() {
            return Ok(None);
        }
    }
    Ok(found)
}

/// One text field of a SKILL record's provenance map.
fn provenance_text<'a>(provenance: &'a Value, key: &str) -> Option<&'a str> {
    let Value::Map(fields) = provenance else {
        return None;
    };
    fields.iter().find_map(|(name, value)| {
        (name.as_str() == Some(key))
            .then(|| value.as_str())
            .flatten()
    })
}
