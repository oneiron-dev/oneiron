//! Census cases for what the activation gate decides about a skill.
use super::Case;
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::edge::EdgeKind;
use crate::skill::{SkillContentHash, SkillLifecycle, SkillRecord, canonical_skill_tree_hash};
use crate::skill_hub::{
    ScanCompleteness, ScanRiskLevel, ScanVerdict, SkillGovernance, SkillScanReceipt,
};
use crate::test_util::entity;
use crate::{EntityId, Error, Result, TimeRange, Vault, VaultConfig};

fn open_vault() -> (tempfile::TempDir, Vault) {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    crate::test_util::open_test_vault_with(config)
}

/// One scanner's verdict at `risk` on the bytes `skill` carries.
fn scan(
    vault: &Vault,
    skill: &EntityId,
    bytes: SkillContentHash,
    provider: &str,
    risk: ScanRiskLevel,
) -> Result<EntityId> {
    let receipt = SkillScanReceipt::new(
        provider,
        10,
        ScanVerdict::Unknown,
        risk,
        ScanCompleteness::Complete,
        SkillGovernance::Recommended,
    )?;
    vault.ingest_skill_scan_verdict(skill, bytes, &receipt, TimeRange { start: 10, end: 10 }, 10)
}

/// The gate reads a skill's verdicts through the `claim_of` edges of its
/// bytes' content anchor. A verdict above the dial whose edge reaches the
/// anchor since the backup, its body unchanged, is one a restore would take
/// off it; a verdict below the dial changes nothing.
pub(super) fn skill_activations() -> Result<Case> {
    let (dir, vault) = open_vault();
    let skill = entity(0xC1);
    let bytes = canonical_skill_tree_hash([("SKILL.md", b"# fixture skill\n".as_slice())])?;
    let mut record = SkillRecord::new(
        "fixture.skill",
        "fixture description",
        "1.0.0",
        ClaimApprovalStatus::Auto,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("fixture"),
        )]),
    );
    record.content_hash = Some(bytes);
    vault.put_skill_record(&skill, &record, TimeRange { start: 5, end: 5 }, 5)?;
    let flagged = scan(
        &vault,
        &skill,
        bytes,
        "fixture.scanner",
        ScanRiskLevel::High,
    )?;
    let Some(ClaimSubject::Entity(anchor)) = vault.get_claim(&flagged)?.map(|claim| claim.subject)
    else {
        return Err(Error::EntityNotFound);
    };
    vault.delete_edge(&flagged, EdgeKind::ClaimOf, &anchor)?;
    Case::after_backup(
        "skill activations",
        (dir, vault),
        move |vault| scan(vault, &skill, bytes, "fixture.linter", ScanRiskLevel::Low).map(drop),
        move |vault| vault.put_edge(&flagged, EdgeKind::ClaimOf, &anchor, 1.0),
    )
}
