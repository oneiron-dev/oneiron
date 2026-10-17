//! Build-embedded bootstrap skills; import and activation commit together on first open.

use rmpv::Value;

use super::{HubAdmissionProof, HubFile, HubPackage, HubPin, HubRef, SkillCapabilitySurface};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::entity_id::derived_domains::BOOTSTRAP_SKILL;
use crate::error::{ArtifactError, Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::skill::{SkillGovernanceTier, SkillLifecycle, SkillRecord, SkillRole};
use crate::team::{PatternSkill, TeamAxis, TeamPattern};
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

impl Vault {
    pub(crate) fn admit_optimized_skill_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        proposal: &EntityId,
        occurred: crate::TimeRange,
        learned_at: u64,
    ) -> Result<Option<crate::skill_optimize::SkillEditDisposition>> {
        crate::skill_optimize::with_optimized_skill_admission(
            self,
            txn,
            proposal,
            learned_at,
            |txn, data| {
                let proof = HubAdmissionProof::optimized(*proposal, &data);
                self.admit_hub_skill_record_in_txn(txn, occurred, learned_at, data, proof)
            },
        )
    }
}

/// Marker (engine version string) that the built-in bootstrap skill set has
/// been seeded.
const SEEDED: SideTable<(), String, Raw> = SideTable::new(&side_table::SKILL_HUB_BOOTSTRAP_SEED);
const FILES: [(&str, &str); 12] = [
    (
        "skill-optimize",
        include_str!("../../../../skills/skill-optimize/SKILL.md"),
    ),
    ("judge", include_str!("../../../../skills/judge/SKILL.md")),
    (
        "goal-intake",
        include_str!("../../../../skills/goal-intake/SKILL.md"),
    ),
    ("wake", include_str!("../../../../skills/wake/SKILL.md")),
    (
        "team-shape",
        include_str!("../../../../skills/team-shape/SKILL.md"),
    ),
    (
        "team-lead",
        include_str!("../../../../skills/team-lead/SKILL.md"),
    ),
    (
        "weave-report",
        include_str!("../../../../skills/weave-report/SKILL.md"),
    ),
    (
        "team-ceo-decides",
        include_str!("../../../../skills/team-ceo-decides/SKILL.md"),
    ),
    (
        "team-committee",
        include_str!("../../../../skills/team-committee/SKILL.md"),
    ),
    (
        "team-vote",
        include_str!("../../../../skills/team-vote/SKILL.md"),
    ),
    (
        "team-market",
        include_str!("../../../../skills/team-market/SKILL.md"),
    ),
    (
        "team-rotation",
        include_str!("../../../../skills/team-rotation/SKILL.md"),
    ),
];

/// The shipped coordination pattern skills (OF-540), each bound to the
/// pattern it teaches: its default setting, the `works well for` line from
/// ARCH-0079's pattern table, and the seed task types that line names. A
/// bound pattern skill is what the live planner offers as a team.
const PATTERNS: [(&str, TeamPattern, TeamAxis, &str, &[&str]); 5] = [
    (
        "team-ceo-decides",
        TeamPattern::CeoDecides,
        TeamAxis::Converge,
        "most work; work with independent advice streams",
        &[],
    ),
    (
        "team-committee",
        TeamPattern::Committee,
        TeamAxis::Converge,
        "researching what exists; refining",
        &["research", "refine"],
    ),
    (
        "team-vote",
        TeamPattern::Vote,
        TeamAxis::Converge,
        "judging between finished options",
        &["judge"],
    ),
    (
        "team-market",
        TeamPattern::Market,
        TeamAxis::Converge,
        "checkable work at width: tests, holdouts, a pinned judge",
        &[],
    ),
    (
        "team-rotation",
        TeamPattern::Rotation,
        TeamAxis::Diverge,
        "reframing, negotiation, open questions",
        &["negotiate"],
    ),
];

/// The binding for `name` when it is a shipped pattern skill, at `skill`.
fn pattern_binding(name: &str, skill: EntityId) -> Option<PatternSkill> {
    PATTERNS
        .iter()
        .find(|(pattern_name, ..)| *pattern_name == name)
        .map(|(_, pattern, axis, line, types)| PatternSkill {
            skill,
            pattern: *pattern,
            default_axis: *axis,
            works_well_for: (*line).to_owned(),
            works_well_for_types: types.iter().map(|node| (*node).to_owned()).collect(),
            at: 0,
        })
}

/// Binds `skill` when `name` is a shipped pattern skill, in the caller's
/// write transaction, on the seeded tree.
fn bind_shipped_pattern_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    name: &str,
    skill: EntityId,
) -> Result<()> {
    let Some(binding) = pattern_binding(name, skill) else {
        return Ok(());
    };
    let tree_version = u32::try_from(crate::task_type::SEEDED_TREE_VERSION)
        .map_err(|_| Error::InvariantViolation("seeded task-type tree version"))?;
    crate::team::pattern::bind_pattern_skill_in_txn(vault, txn, &binding, tree_version)
}

fn stable_id(name: &str) -> Result<EntityId> {
    EntityId::derive(BOOTSTRAP_SKILL, &[name.as_bytes()])
}

fn package(name: &str, markdown: &str) -> Result<HubPackage> {
    // The shipped format is deliberately small: the same SKILL.md bytes are
    // exported to a hub, embedded into the binary, and retained as provenance.
    let front = markdown
        .strip_prefix("---\n")
        .and_then(|text| text.split_once("\n---\n"))
        .ok_or(Error::Artifact(ArtifactError::InvalidSkillBody(
            "missing skill frontmatter",
        )))?;
    let description = front
        .0
        .lines()
        .find_map(|line| line.strip_prefix("description: "))
        .filter(|desc| !desc.trim().is_empty())
        .ok_or(Error::Artifact(ArtifactError::InvalidSkillBody(
            "missing skill description",
        )))?;
    if !front.0.lines().any(|line| line == format!("name: {name}")) || front.1.trim().is_empty() {
        return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
            "invalid skill name or body",
        )));
    }
    let record = SkillRecord::new(
        name,
        description,
        env!("CARGO_PKG_VERSION"),
        ClaimApprovalStatus::Auto,
        SkillLifecycle::Candidate,
        ClaimSource::Imported,
        1.0,
        false,
        true,
        Vec::new(),
        Value::Map(vec![
            (
                Value::from("engineVersion"),
                Value::from(env!("CARGO_PKG_VERSION")),
            ),
            (Value::from("skillMarkdown"), Value::from(markdown)),
        ]),
    )
    .with_governance_tier(SkillGovernanceTier::Standard)
    .with_role(
        // The CEO starter, the team-shape planner and the coordination
        // patterns are workflows: the leader path loads only workflows.
        if name == "team-lead"
            || name == crate::agent_dispatch::TEAM_SHAPE_SKILL_NAME
            || PATTERNS
                .iter()
                .any(|(pattern_name, ..)| *pattern_name == name)
        {
            SkillRole::Workflow
        } else {
            SkillRole::Knowledge
        },
        None,
    );
    let mut files = vec![HubFile::new("SKILL.md", markdown.as_bytes())];
    // The vault task-type tree lives in the team-shape skill (ARCH-0079): it
    // ships as the seeded tree, and receipts fork it from there.
    if name == crate::agent_dispatch::TEAM_SHAPE_SKILL_NAME {
        let tree =
            serde_json::to_vec_pretty(&crate::task_type::TaskTypeTree::seeded()).map_err(|_| {
                Error::Artifact(ArtifactError::InvalidSkillBody(
                    "seeded task-type tree does not encode",
                ))
            })?;
        files.push(HubFile::new(
            crate::agent_dispatch::TASK_TYPE_TREE_FILE,
            tree,
        ));
    }
    // Native format: the shipped markdown carries no versioned folder
    // frontmatter (version rides the record), so the folder parser must not be
    // asked to re-derive the record from it on export/import round trips.
    let mut package = HubPackage::new(record, files, SkillCapabilitySurface::default());
    package.format = super::SkillPackageFormat::Native;
    Ok(package)
}

pub(crate) fn seed_bootstrap_skills(vault: &Vault) -> Result<()> {
    let rtxn = vault.store.env.read_txn()?;
    if SEEDED.contains(&vault.store, &rtxn, &())? {
        return Ok(());
    }
    drop(rtxn);
    // A malformed policy must remain readable for owner repair. Do not turn
    // first-run imports into an open failure or bypass its fail-closed gate.
    if crate::gate::resolve_policy_manifest(&vault.store, &vault.store.env.read_txn()?)?
        .diagnostics()
        .loaded_manifest_forces_fail_closed()
    {
        return Ok(());
    }
    let mut wtxn = vault.store.env.write_txn()?;
    if SEEDED.contains(&vault.store, &wtxn, &())? {
        return Ok(());
    }
    let occurred = TimeRange { start: 0, end: 0 };
    for (name, markdown) in FILES {
        let package = package(name, markdown)?;
        let seed_id = stable_id(name)?;
        let content_hash = package.content_hash()?;
        // A caller-chosen record (or a deleted seed) owns this ID regardless
        // of its files. Never offer it to the import/update door: doing so
        // could rewrite the holder or make Vault::open fail on immutable fields.
        let deletion =
            crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, &wtxn, &seed_id)?;
        if crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &wtxn, &seed_id)?.is_some()
            || deletion.deleted
            || deletion.stale
        {
            continue;
        }
        // A prior import already holds these exact files. Its entity ID is
        // not bootstrap admission, even when it equals our deterministic ID.
        // Check before the import door can attach provenance, scans, receipts
        // or capabilities, and promote only a record minted by this pass.
        if vault
            .skill_entity_for_content_hash_in_txn(&wtxn, content_hash)?
            .is_some()
        {
            continue;
        }
        let hub_ref = HubRef::new(
            stable_id("hub")?,
            name,
            HubPin::ContentHash(content_hash.to_hex()),
        )?;
        let id = vault
            .import_skill_from_hub_in_txn(&mut wtxn, &hub_ref, &package, seed_id, occurred, 0)?;
        if id != seed_id {
            // A different holder cannot appear while this write transaction owns
            // the preflight and import; roll back rather than mutate it.
            return Err(Error::InvariantViolation("bootstrap skill holder changed"));
        }
        let mut record = vault.read_skill_record_in_txn(&wtxn, &id)?;
        // Local seed admission, not a remote package's approval stamp. The
        // ordinary update/scan gates still run. Reopen never reactivates edits.
        if record.lifecycle_status == SkillLifecycle::Candidate {
            record.lifecycle_status = SkillLifecycle::Active;
            let data = crate::skill::encode_skill_record(&record)?;
            let proof = HubAdmissionProof::bootstrap(id, &data);
            vault.admit_hub_skill_record_in_txn(&mut wtxn, occurred, 0, data, proof)?;
        }
        // A pattern skill is a team the planner can offer only once bound
        // (OF-540), in the transaction that admitted it.
        bind_shipped_pattern_in_txn(vault, &mut wtxn, name, id)?;
    }
    SEEDED.put(
        &vault.store,
        &mut wtxn,
        &(),
        &env!("CARGO_PKG_VERSION").to_owned(),
    )?;
    wtxn.commit()?;
    Ok(())
}

impl Vault {
    pub(super) fn default_skill_present_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        source: &HubRef,
        hash: crate::skill::SkillContentHash,
        name: &str,
    ) -> Result<Option<EntityId>> {
        for (id, record) in self.structured_skills_for_content_hash_in_txn(txn, hash)? {
            if record.skill_id != name
                || !matches!(
                    record.lifecycle_status,
                    SkillLifecycle::Candidate | SkillLifecycle::Active
                )
            {
                continue;
            }
            if self.default_skill_present_for_entity_in_txn(txn, &id, source)? {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    pub(super) fn default_skill_present_for_entity_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        source: &HubRef,
    ) -> Result<bool> {
        for (claim_id, claim, _) in
            self.active_claims_for_predicate_in_txn(txn, id, super::PREDICATE_SKILL_HUB_PROVENANCE)?
        {
            if let Some(value) = super::support::map_value(&claim.value, "hubRef")
                && HubRef::from_value(value)? == *source
                && crate::gate::claim_consolidation_eligible_in_txn(
                    &self.store,
                    txn,
                    &claim_id,
                    crate::gate::ConsolidationReader::HubDefaultPresence,
                )?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[cfg(test)]
    pub(crate) fn hub_default_source_present_for_test(
        &self,
        entity: &EntityId,
        source: &HubRef,
    ) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        self.default_skill_present_for_entity_in_txn(&txn, entity, source)
    }

    /// Explicitly re-imports missing or locally retired shipped bootstrap
    /// skills from the bytes embedded in this engine build. An unchanged
    /// default is left alone. Restored skills get new IDs and enter as
    /// Candidates through the ordinary scanner/import door; unlike first-open
    /// seeding, this verb never grants activation authority.
    pub fn restore_default_skills(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<Vec<EntityId>> {
        let mut txn = self.store.env.write_txn()?;
        self.check_restore_owner_in_txn(&txn, owner)?;
        let mut restored = Vec::new();
        for (name, markdown) in FILES {
            let package = package(name, markdown)?;
            let hash = package.content_hash()?;
            let source = HubRef::new(stable_id("hub")?, name, HubPin::ContentHash(hash.to_hex()))?;
            if self
                .default_skill_present_in_txn(&txn, &source, hash, name)?
                .is_some()
            {
                continue;
            }
            let id = self.store.clock.entity_id()?;
            let restored_id = self.restore_default_skill_in_txn(
                &mut txn, owner, &source, &package, id, occurred, learned_at,
            )?;
            // A restored pattern stays a Candidate the planner skips until
            // admitted, but it is bound under its fresh id.
            bind_shipped_pattern_in_txn(self, &mut txn, name, restored_id)?;
            restored.push(id);
        }
        txn.commit()?;
        Ok(restored)
    }
}

#[cfg(test)]
mod tests;
