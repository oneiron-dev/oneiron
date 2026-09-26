//! Build-embedded bootstrap skills; import and activation commit together on first open.

use rmpv::Value;

use super::{HubFile, HubPackage, HubPin, HubRef, SkillCapabilitySurface};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::entity_id::derived_domains::BOOTSTRAP_SKILL;
use crate::error::{ArtifactError, Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::skill::{SkillGovernanceTier, SkillLifecycle, SkillRecord};
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

/// Exact-record activation proof, issued after local consent and held-out replay,
/// or at bootstrap: the vault's own genesis authorizes the embedded install set,
/// which is why first-open seeding needs no separately minted owner consent.
#[derive(Debug)]
pub(crate) struct HubAdmissionProof {
    id: EntityId,
    binding: blake3::Hash,
}
impl HubAdmissionProof {
    pub(super) fn id(&self) -> EntityId {
        self.id
    }

    pub(crate) fn binds(&self, id: &EntityId, data: &[u8]) -> bool {
        self.id == *id && self.binding == blake3::hash(data)
    }

    pub(super) fn consent(
        store: &crate::store::Store,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        data: &[u8],
        authorization: &crate::consent::ApproveOnceAuthorization,
    ) -> Result<Self> {
        crate::consent::spend_approve_once_in_txn(store, txn, authorization)?;
        Ok(Self {
            id,
            binding: blake3::hash(data),
        })
    }
}

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
                let proof = HubAdmissionProof {
                    id: *proposal,
                    binding: blake3::hash(&data),
                };
                self.admit_hub_skill_record_in_txn(txn, occurred, learned_at, data, proof)
            },
        )
    }
}

/// Marker (engine version string) that the built-in bootstrap skill set has
/// been seeded.
const SEEDED: SideTable<(), String, Raw> = SideTable::new(&side_table::SKILL_HUB_BOOTSTRAP_SEED);
const FILES: [(&str, &str); 4] = [
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
];

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
    .with_governance_tier(SkillGovernanceTier::Standard);
    // Native format: the shipped markdown carries no versioned folder
    // frontmatter (version rides the record), so the folder parser must not be
    // asked to re-derive the record from it on export/import round trips.
    let mut package = HubPackage::new(
        record,
        vec![HubFile::new("SKILL.md", markdown.as_bytes())],
        SkillCapabilitySurface::default(),
    );
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
            let proof = HubAdmissionProof {
                id,
                binding: blake3::hash(&data),
            };
            vault.admit_hub_skill_record_in_txn(&mut wtxn, occurred, 0, data, proof)?;
        }
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

#[cfg(test)]
mod tests;
