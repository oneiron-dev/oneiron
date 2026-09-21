//! Build-embedded bootstrap skills; import and activation commit together on first open.

use rmpv::Value;

use super::{HubFile, HubPackage, HubPin, HubRef, SkillCapabilitySurface};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::error::{ArtifactError, Error, Result};
use crate::skill::{SkillGovernanceTier, SkillLifecycle, SkillRecord};
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

const SEED_KEY: &[u8] = b"bootstrap_skills/seeded/v1";
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
    let hash = blake3::hash(format!("oneiron/bootstrap/v1/{name}").as_bytes());
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&hash.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    EntityId::from_bytes(bytes)
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
    Ok(HubPackage::new(
        record,
        vec![HubFile::new("SKILL.md", markdown.as_bytes())],
        SkillCapabilitySurface::default(),
    ))
}

pub(crate) fn seed_bootstrap_skills(vault: &Vault) -> Result<()> {
    let rtxn = vault.store.env.read_txn()?;
    if vault.store.vault_meta.get(&rtxn, SEED_KEY)?.is_some() {
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
    if vault.store.vault_meta.get(&wtxn, SEED_KEY)?.is_some() {
        return Ok(());
    }
    let occurred = TimeRange { start: 0, end: 0 };
    for (name, markdown) in FILES {
        let package = package(name, markdown)?;
        let hub_ref = HubRef::new(
            stable_id("hub")?,
            name,
            HubPin::ContentHash(package.content_hash()?.to_hex()),
        )?;
        let id = vault.import_skill_from_hub_in_txn(
            &mut wtxn,
            &hub_ref,
            &package,
            stable_id(name)?,
            occurred,
            0,
        )?;
        let mut record = vault.read_skill_record_in_txn(&wtxn, &id)?;
        // Local seed admission, not a remote package's approval stamp. The
        // ordinary update/scan gates still run. Reopen never reactivates edits.
        if record.lifecycle_status == SkillLifecycle::Candidate {
            record.lifecycle_status = SkillLifecycle::Active;
            vault.apply_hub_import_skill_record(&mut wtxn, &id, &record, occurred, 0)?;
        }
    }
    vault
        .store
        .vault_meta
        .put(&mut wtxn, SEED_KEY, env!("CARGO_PKG_VERSION").as_bytes())?;
    wtxn.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests;
