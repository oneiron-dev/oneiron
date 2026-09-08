//! SKILL record-shape invariants and the update gate.

use std::collections::HashSet;

use rmpv::Value;

use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::error::{Error, Result};

use super::lifecycle::SkillLifecycle;
use super::record::{
    SKILL_DESC_MAX_BYTES, SKILL_ID_MAX_BYTES, SKILL_MAX_DEPENDENCIES, SKILL_VERSION_MAX_BYTES,
    SkillDependency, SkillRecord,
};

pub(super) fn validate_skill_record(record: &SkillRecord) -> Result<()> {
    validate_text_field(
        &record.skill_id,
        SKILL_ID_MAX_BYTES,
        "skillId must be a non-empty UTF-8 string at most 256 bytes",
    )?;
    validate_text_field(
        &record.desc,
        SKILL_DESC_MAX_BYTES,
        "desc must be a non-empty UTF-8 string at most 4096 bytes",
    )?;
    validate_text_field(
        &record.version,
        SKILL_VERSION_MAX_BYTES,
        "version must be a non-empty UTF-8 string at most 128 bytes",
    )?;
    if !record.confidence.is_finite() || !(0.0..=1.0).contains(&record.confidence) {
        return Err(Error::InvalidSkillBody(
            "confidence must be finite in [0, 1]",
        ));
    }
    if record.generated == record.human_authored {
        return Err(Error::InvalidSkillBody(
            "exactly one of generated or humanAuthored must be true",
        ));
    }
    if record.generated != (record.source == ClaimSource::Generated) {
        return Err(Error::InvalidSkillBody(
            "generated flag must match generated source",
        ));
    }
    // Record-SHAPE invariant (ONE-1735 review r1): quarantined is a
    // HUMAN-RATIFIED state — the proposal to quarantine is a row, never a
    // lifecycle state — so the only lawful shape is approval = approved.
    // Holds on EVERY door (create, update, sync replay): `quarantined`
    // did not exist on the skill wire before ONE-1735, so no lawful
    // legacy or peer row carries any other shape.
    if record.lifecycle_status == SkillLifecycle::Quarantined
        && record.approval_status != ClaimApprovalStatus::Approved
    {
        return Err(Error::InvalidSkillBody(
            "quarantined is a human-ratified state: approval must be approved",
        ));
    }
    validate_provenance(&record.provenance)?;
    validate_dependencies(&record.skill_id, &record.dependencies)?;
    Ok(())
}

fn validate_provenance(provenance: &Value) -> Result<()> {
    let Value::Map(entries) = provenance else {
        return Err(Error::InvalidSkillBody(
            "provenance must be a non-empty MessagePack map",
        ));
    };
    if entries.is_empty() {
        return Err(Error::InvalidSkillBody(
            "provenance must be a non-empty MessagePack map",
        ));
    }
    let mut seen = HashSet::new();
    for (key, _) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidSkillBody("provenance keys must be strings"));
        };
        if key.trim().is_empty() {
            return Err(Error::InvalidSkillBody(
                "provenance keys must be non-empty strings",
            ));
        }
        if !seen.insert(key) {
            return Err(Error::InvalidSkillBody("duplicate provenance key"));
        }
    }
    Ok(())
}

fn validate_dependencies(skill_id: &str, dependencies: &[SkillDependency]) -> Result<()> {
    if dependencies.len() > SKILL_MAX_DEPENDENCIES {
        return Err(Error::InvalidSkillBody(
            "dependencies must contain at most 64 entries",
        ));
    }
    let mut seen = HashSet::new();
    for dependency in dependencies {
        validate_text_field(
            &dependency.skill_id,
            SKILL_ID_MAX_BYTES,
            "dependency skillId must be a non-empty UTF-8 string at most 256 bytes",
        )?;
        if dependency.skill_id == skill_id {
            return Err(Error::InvalidSkillBody("skill must not depend on itself"));
        }
        if !seen.insert(dependency.skill_id.as_str()) {
            return Err(Error::InvalidSkillBody("duplicate skill dependency"));
        }
        if let Some(min_version) = &dependency.min_version {
            validate_text_field(
                min_version,
                SKILL_VERSION_MAX_BYTES,
                "dependency minVersion must be nil or a non-empty UTF-8 string at most 128 bytes",
            )?;
        }
    }
    Ok(())
}

pub(super) fn validate_text_field(
    text: &str,
    max_bytes: usize,
    context: &'static str,
) -> Result<()> {
    if text.trim().is_empty() || text.len() > max_bytes {
        return Err(Error::InvalidSkillBody(context));
    }
    Ok(())
}

pub(crate) fn validate_skill_update(prior: &SkillRecord, updated: &SkillRecord) -> Result<()> {
    validate_skill_update_for_door(prior, updated, false)
}

pub(crate) fn validate_hub_sync_skill_update(
    prior: &SkillRecord,
    updated: &SkillRecord,
) -> Result<()> {
    if prior.source != ClaimSource::Imported || updated.source != ClaimSource::Imported {
        return Err(Error::InvalidSkillBody(
            "hub sync only updates imported skills",
        ));
    }
    validate_skill_update_for_door(prior, updated, true)
}

fn validate_skill_update_for_door(
    prior: &SkillRecord,
    updated: &SkillRecord,
    allow_imported_content: bool,
) -> Result<()> {
    validate_skill_record(updated)?;
    if prior == updated {
        return Ok(());
    }
    if prior.skill_id != updated.skill_id {
        return Err(Error::InvalidSkillBody("skillId cannot change on update"));
    }
    if prior.generated != updated.generated || prior.human_authored != updated.human_authored {
        return Err(Error::InvalidSkillBody(
            "authorship flags cannot change on update",
        ));
    }
    if prior.source != updated.source {
        return Err(Error::InvalidSkillBody("source cannot change on update"));
    }
    if prior.forked_from != updated.forked_from {
        return Err(Error::InvalidSkillBody(
            "forkedFrom lineage cannot change on update",
        ));
    }
    // Lifecycle machine (ARCH-0053 §6): a superseded revision is frozen
    // history — it never loads as canon and never updates; continuing the
    // skill means admitting a NEW revision. All other moves must follow
    // the one transition table.
    if prior.lifecycle_status == SkillLifecycle::Superseded {
        return Err(Error::InvalidSkillBody(
            "superseded skill revision is frozen; admit a new revision instead",
        ));
    }
    if !prior
        .lifecycle_status
        .can_transition(updated.lifecycle_status)
    {
        return Err(Error::InvalidSkillBody(
            "illegal skill lifecycle transition",
        ));
    }
    // Quarantine is outcome-DRIVEN but human-RATIFIED: the proposal to
    // quarantine is a ROW (SK-05's floor-crossing proposal), never a
    // lifecycle state, so the only lawful entry is already-ratified.
    // The record-shape invariant in `validate_skill_record` enforces the
    // same law on every door; this transition-level check is kept as the
    // clearer early error.
    if updated.lifecycle_status == SkillLifecycle::Quarantined
        && prior.lifecycle_status != SkillLifecycle::Quarantined
        && updated.approval_status != ClaimApprovalStatus::Approved
    {
        return Err(Error::InvalidSkillBody(
            "quarantine entry is human-ratified: the proposal is a row, never a lifecycle state",
        ));
    }
    // Lifecycle/approval are STATE axes riding the record; flipping them
    // (stale ⇄ active, proposed → approved, supersession) does not mint a
    // content revision. Everything else is content and must bump `version`.
    if skill_content_changed(prior, updated) {
        if prior.version == updated.version {
            return Err(Error::InvalidSkillBody(
                "version must change when updating skill body",
            ));
        }
        // Fork law (ONE-1735, shared with ONE-1444): imported content
        // changes in place through NO generic door, whatever the approval
        // stamp — an in-place update marked "proposed" replaces canon the
        // moment it lands, which is a silent overwrite with a label. A
        // local edit is a fork (`Vault::fork_skill_record`); an upstream
        // update lands through the hub-sync door's own policy-checked
        // inlet (ONE-1736), which mints proposal artifacts / new
        // revisions instead of mutating this one.
        if prior.source == ClaimSource::Imported && !allow_imported_content {
            return Err(Error::InvalidSkillBody(
                "imported skill content never changes in place; local edits fork and upstream updates land through the hub-sync door",
            ));
        }
    }
    Ok(())
}

/// Whether anything OTHER than the two state axes (`approval_status`,
/// `lifecycle_status`) and the demoted `confidence` cache differs between the
/// two records.
pub(super) fn skill_content_changed(prior: &SkillRecord, updated: &SkillRecord) -> bool {
    let mut normalized = updated.clone();
    normalized.approval_status = prior.approval_status;
    normalized.lifecycle_status = prior.lifecycle_status;
    // `confidence` is a CACHE of the `skill.reliability` claim's posterior mean
    // (ONE-1738), so refreshing it asserts nothing new about the skill's
    // CONTENT: it is normalized away exactly like the state axes. Requiring a
    // version bump for it would mint a revision per attributed outcome, and
    // banning it on imports would make an imported skill's reliability
    // permanently unmaterializable.
    normalized.confidence = prior.confidence;
    // `governance_tier` (ONE-1448) is the third STATE axis, for the same
    // reason the first two are: marking a skill identity-tier says what the
    // automated loop may do WITH the instructions, and changes not one word
    // OF them. Treating it as content would require a version bump to answer
    // a governance question — and would make an imported pack's tier
    // permanently unmarkable, since imported CONTENT never changes in place.
    // The owner's mark has to be able to land on exactly those records.
    normalized.governance_tier = prior.governance_tier;
    normalized != *prior
}
