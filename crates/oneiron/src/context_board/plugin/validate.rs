//! Bounded-shape checks and the two-phase validation gate.
use super::super::frame::{ShedRank, section_policy_for_budget_ref};
use super::codec::digest_from_hex;
use super::errors::{PluginResult, PluginSectionError};
use super::install::{PluginInstallTarget, ValidatedSectionManifest};
use super::manifest::{
    PluginInstallSource, SECTION_MANIFEST_SCHEMA_VERSION, SectionBindingResolver,
    SectionManifestEnvelope, SectionManifestProvenance, SectionVerbAllowlist, SectionVerbRef,
};
use crate::skill::{SkillLifecycle, SkillRecord};
use std::collections::BTreeSet;

/// Engine-defined core section names a plugin manifest may never claim.
pub const CORE_SECTION_IDS: [&str; 4] = ["WORLDS", "MEMORIES", "TASKS", "AGENTS"];

/// Longest accepted `section_id`.
const MAX_SECTION_ID_BYTES: usize = 64;

/// Longest accepted display name / authority lane / state family / provenance
/// identifier. Bounds the manifest before anything renders or tokenizes.
const MAX_MANIFEST_TEXT_BYTES: usize = 128;

/// Most verbs a single manifest may advertise.
const MAX_MANIFEST_VERBS: usize = 32;

// ---------------------------------------------------------------------------
// §2 — two-phase validation
// ---------------------------------------------------------------------------
pub(super) fn bounded_text(value: &str, field: &'static str) -> PluginResult<()> {
    if value.trim().is_empty() {
        return Err(PluginSectionError::MalformedField { field });
    }
    if value.len() > MAX_MANIFEST_TEXT_BYTES {
        return Err(PluginSectionError::FieldTooLong { field });
    }
    if value.chars().any(char::is_control) {
        return Err(PluginSectionError::MalformedField { field });
    }
    Ok(())
}

/// `[a-z][a-z0-9_]*` segments joined by `.` — the same shape the claim
/// predicate grammar uses, so a section id can never carry a delimiter the
/// renderer would have to escape structurally.
fn valid_section_id(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_SECTION_ID_BYTES {
        return false;
    }
    value.split('.').all(|segment| {
        let mut bytes = segment.bytes();
        match bytes.next() {
            Some(first) if first.is_ascii_lowercase() => {}
            _ => return false,
        }
        bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    })
}

/// Schema, identifiers, recipe completeness, the exported verb allowlist, and
/// the resolvable state/authority/budget references. Shared by BOTH phases:
/// admission repeats every proposal check rather than trusting the proposal.
pub(super) fn validate_manifest_shape(
    envelope: &SectionManifestEnvelope,
    bindings: &dyn SectionBindingResolver,
    verbs: &SectionVerbAllowlist,
) -> PluginResult<()> {
    if envelope.schema_version != SECTION_MANIFEST_SCHEMA_VERSION {
        return Err(PluginSectionError::UnsupportedSchemaVersion {
            found: envelope.schema_version,
            expected: SECTION_MANIFEST_SCHEMA_VERSION,
        });
    }
    let manifest = &envelope.manifest;

    if !valid_section_id(&manifest.section_id.0) {
        return Err(PluginSectionError::MalformedField {
            field: "section_id",
        });
    }
    if CORE_SECTION_IDS
        .iter()
        .any(|core| core.eq_ignore_ascii_case(&manifest.section_id.0))
    {
        return Err(PluginSectionError::CoreSectionCollision {
            section_id: manifest.section_id.0.clone(),
        });
    }
    bounded_text(&manifest.name, "name")?;
    if CORE_SECTION_IDS
        .iter()
        .any(|core| core.eq_ignore_ascii_case(manifest.name.trim()))
    {
        return Err(PluginSectionError::CoreSectionCollision {
            section_id: manifest.name.clone(),
        });
    }

    // Recipe component 1 — typed state source.
    bounded_text(&manifest.state_family.family, "state_family")?;
    if !bindings.state_family_exists(&manifest.state_family) {
        return Err(PluginSectionError::UnresolvedStateFamily {
            family: manifest.state_family.family.clone(),
        });
    }

    // Recipe component 2 — typed verbs, through the closed chokepoint.
    if manifest.verbs.is_empty() {
        return Err(PluginSectionError::MissingVerbs);
    }
    if manifest.verbs.len() > MAX_MANIFEST_VERBS {
        return Err(PluginSectionError::FieldTooLong { field: "verbs" });
    }
    let mut seen: BTreeSet<&SectionVerbRef> = BTreeSet::new();
    for verb in &manifest.verbs {
        if !verbs.contains(verb) {
            return Err(PluginSectionError::UnknownVerb {
                verb: verb.0.clone(),
            });
        }
        if !seen.insert(verb) {
            return Err(PluginSectionError::DuplicateVerb {
                verb: verb.0.clone(),
            });
        }
    }

    // Recipe component 3 — authority lane.
    bounded_text(&manifest.authority_lane.0, "authority_lane")?;
    if !bindings.authority_lane_exists(&manifest.authority_lane) {
        return Err(PluginSectionError::UnresolvedAuthorityLane {
            lane: manifest.authority_lane.0.clone(),
        });
    }

    // Recipe component 4 — budget policy, mapped through the frame-owned
    // closed table. Unknown or plugin-PINNING policies fail closed.
    bounded_text(&manifest.budget_policy.0, "budget_policy")?;
    if !bindings.budget_policy_exists(&manifest.budget_policy) {
        return Err(PluginSectionError::UnresolvedBudgetPolicy {
            policy: manifest.budget_policy.0.clone(),
        });
    }
    let policy = section_policy_for_budget_ref(&manifest.budget_policy).map_err(|_| {
        PluginSectionError::UnresolvedBudgetPolicy {
            policy: manifest.budget_policy.0.clone(),
        }
    })?;
    if policy.pinned || policy.shed_rank != Some(ShedRank::PluginSections) {
        return Err(PluginSectionError::NonPluginSectionPolicy);
    }

    bounded_text(&manifest.provenance.pack_id, "provenance.pack_id")?;
    bounded_text(&manifest.provenance.skill_id, "provenance.skill_id")?;
    bounded_text(
        &manifest.provenance.skill_version,
        "provenance.skill_version",
    )?;
    digest_from_hex(&manifest.provenance.content_hash_hex).map_err(|_| {
        PluginSectionError::MalformedField {
            field: "provenance.content_hash_hex",
        }
    })?;
    Ok(())
}

/// Compares manifest provenance against a real `SkillRecord`'s exact identity.
/// Lifecycle is deliberately NOT checked here — the phases differ on exactly
/// that axis.
pub(super) fn provenance_matches_record(
    provenance: &SectionManifestProvenance,
    record: &SkillRecord,
) -> PluginResult<()> {
    let content_hash = record
        .content_hash
        .ok_or(PluginSectionError::ProvenanceMismatch)?;
    if record.skill_id != provenance.skill_id
        || record.version != provenance.skill_version
        || content_hash.to_hex() != provenance.content_hash_hex
    {
        return Err(PluginSectionError::ProvenanceMismatch);
    }
    Ok(())
}

/// **Phase 1 — proposal validation.** Schema, identifiers, recipe completeness,
/// core-section collisions, exact package/version/hash provenance, the exported
/// verb allowlist, and resolvable state/authority/budget references.
///
/// It accepts an exact fetched package OR an existing `Candidate`/`Active`
/// skill; it deliberately does **not** require `Active` and writes no package
/// bytes. `target` names which of those two the proposal is about — the
/// analogue of `installed_skill` in the admission phase.
pub fn validate_manifest_for_proposal(
    manifest: SectionManifestEnvelope,
    target: &PluginInstallTarget,
    source: &dyn PluginInstallSource,
    bindings: &dyn SectionBindingResolver,
    verbs: &SectionVerbAllowlist,
) -> PluginResult<ValidatedSectionManifest> {
    validate_manifest_shape(&manifest, bindings, verbs)?;
    let provenance = &manifest.manifest.provenance;

    match target {
        PluginInstallTarget::ExistingSkill { skill_ref } => {
            let record = source.skill_record(skill_ref)?.ok_or_else(|| {
                PluginSectionError::MissingInstallTarget {
                    reference: skill_ref.to_hex(),
                }
            })?;
            // Candidate is a legal PROPOSAL target: consent covers install plus
            // admission, so requiring Active here would make the gate
            // unreachable for anything not already installed.
            if matches!(
                record.lifecycle_status,
                SkillLifecycle::Superseded | SkillLifecycle::Quarantined
            ) {
                return Err(PluginSectionError::SkillNotActive {
                    found: record.lifecycle_status,
                });
            }
            provenance_matches_record(provenance, &record)?;
        }
        PluginInstallTarget::HubPackage { hub_ref, .. } => {
            // Read-only fetch: the exact pinned bytes are inspected, and NOT
            // one of them is written before consent.
            let package = source.hub_package(hub_ref)?;
            let canonical = package
                .content_hash()
                .map_err(|_| PluginSectionError::ProvenanceMismatch)?;
            if canonical.to_hex() != provenance.content_hash_hex
                || package.record.skill_id != provenance.skill_id
                || package.record.version != provenance.skill_version
            {
                return Err(PluginSectionError::ProvenanceMismatch);
            }
        }
    }

    Ok(ValidatedSectionManifest(manifest))
}

/// **Phase 2 — admission validation.** Repeats every proposal check against the
/// persisted/fetched bytes AFTER consent, and additionally requires the
/// installed `SkillRecord` to be `Active` with the exact approved
/// version/content hash.
pub fn validate_manifest_for_admission(
    manifest: SectionManifestEnvelope,
    installed_skill: &SkillRecord,
    bindings: &dyn SectionBindingResolver,
    verbs: &SectionVerbAllowlist,
) -> PluginResult<ValidatedSectionManifest> {
    validate_manifest_shape(&manifest, bindings, verbs)?;
    if !installed_skill.lifecycle_status.loads_as_canon() {
        return Err(PluginSectionError::SkillNotActive {
            found: installed_skill.lifecycle_status,
        });
    }
    provenance_matches_record(&manifest.manifest.provenance, installed_skill)?;
    Ok(ValidatedSectionManifest(manifest))
}
