use rmpv::Value;

use super::*;
use crate::VaultConfig;
use crate::claim::ClaimSource;
use crate::entity_id::EntityId;
use crate::skill::{SkillLifecycle, canonical_skill_tree_hash};
use crate::skill_hub::{HubFile, HubPin, HubRef, SkillCapabilitySurface};
use crate::temporal::TimeRange;

/// A synthetic GitHub-token-shaped fixture. Not a credential: the detector
/// keys on shape, and this string is 36 hex-ish characters of nothing.
const SECRET_FIXTURE: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";

fn t(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn open_vault() -> (tempfile::TempDir, Vault) {
    let temp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(temp.path(), VaultConfig::default()).expect("open vault");
    (temp, vault)
}

fn record(skill_id: &str) -> SkillRecord {
    SkillRecord::new(
        skill_id,
        "scan fixture description",
        "1.0.0",
        ClaimApprovalStatus::Auto,
        SkillLifecycle::Candidate,
        ClaimSource::Imported,
        1.0,
        false,
        true,
        Vec::new(),
        Value::Map(vec![(Value::from("source"), Value::from("fixture"))]),
    )
}

fn package_of(skill_id: &str, content: &[u8], capabilities: SkillCapabilitySurface) -> HubPackage {
    let mut record = record(skill_id);
    record.content_hash =
        Some(canonical_skill_tree_hash([("SKILL.md", content)]).expect("fixture hash"));
    HubPackage::new(
        record,
        vec![HubFile::new("SKILL.md", content.to_vec())],
        capabilities,
    )
}

fn hub_ref() -> HubRef {
    HubRef::new(EntityId::now(), "skills/scan-fixture", HubPin::None).expect("hub ref")
}

fn authored_scan_candidate(vault: &Vault, package: &HubPackage, at: u64) -> Result<EntityId> {
    let id = EntityId::now();
    let mut record = package.record.clone();
    record.source = ClaimSource::UserStated;
    record.approval_status = ClaimApprovalStatus::Auto;
    vault.put_skill_record(&id, &record, t(at), at)?;
    let scan = run_static_skill_scan(package, at)?;
    vault.ingest_skill_scan_verdict(&id, package.content_hash()?, &scan, t(at), at)?;
    Ok(id)
}

// ═══ the static pass ════════════════════════════════════════════════════════

#[test]
fn a_credential_parked_past_the_first_megabyte_is_still_found() -> Result<()> {
    // The exact bypass an earlier 1 MiB-per-file budget left open: hub files
    // are admitted up to 16 MiB, so a credential below the scanned prefix rode
    // in at `risk = None` and the gate — which reads `riskLevel` and nothing
    // else — waved it through as auto-eligible.
    let mut content = vec![b'a'; 1024 * 1024 + 4096];
    content.push(b'\n');
    content.extend_from_slice(SECRET_FIXTURE.as_bytes());
    assert!(content.len() < crate::skill_hub::MAX_HUB_FILE_BYTES);

    let package = package_of(
        "fixture.deep-secret",
        &content,
        SkillCapabilitySurface::default(),
    );
    let receipt = run_static_skill_scan(&package, 7)?;

    assert_eq!(receipt.risk_level, ScanRiskLevel::High);
    assert_eq!(receipt.verdict, ScanVerdict::Suspicious);
    assert_eq!(
        receipt.completeness,
        ScanCompleteness::Complete,
        "an importable file is read in full, so coverage is not partial"
    );
    Ok(())
}

// ═══ the activation consult ═════════════════════════════════════════════════

#[test]
fn activation_escalates_auto_to_proposed_without_refusing() -> Result<()> {
    let (_temp, vault) = open_vault();
    let body = format!("# skill\nexport TOKEN={SECRET_FIXTURE}\n");
    let package = package_of(
        "fixture.activate-risky",
        body.as_bytes(),
        SkillCapabilitySurface::default(),
    );
    let entity = authored_scan_candidate(&vault, &package, 1)?;

    let mut active = vault.get_skill_record(&entity)?.expect("authored skill");
    active.lifecycle_status = SkillLifecycle::Active;
    active.approval_status = ClaimApprovalStatus::Auto;
    vault.update_skill_record(&entity, &active, t(3), 4)?;

    let stored = vault.get_skill_record(&entity)?.expect("activated skill");
    assert_eq!(
        stored.lifecycle_status,
        SkillLifecycle::Active,
        "the dial escalates consent; it never blocks the activation"
    );
    assert_eq!(stored.approval_status, ClaimApprovalStatus::Proposed);
    Ok(())
}

#[test]
fn activation_leaves_clean_skills_and_owner_approvals_alone() -> Result<()> {
    let (_temp, vault) = open_vault();

    let clean = package_of(
        "fixture.activate-clean",
        b"# clean skill\n",
        SkillCapabilitySurface::default(),
    );
    let clean_entity = authored_scan_candidate(&vault, &clean, 1)?;
    let mut active = vault
        .get_skill_record(&clean_entity)?
        .expect("authored skill");
    active.lifecycle_status = SkillLifecycle::Active;
    active.approval_status = ClaimApprovalStatus::Auto;
    vault.update_skill_record(&clean_entity, &active, t(3), 4)?;
    assert_eq!(
        vault
            .get_skill_record(&clean_entity)?
            .expect("activated skill")
            .approval_status,
        ClaimApprovalStatus::Auto
    );

    // An owner tap already answered the question this dial asks, so the
    // escalation never rewrites it.
    let body = format!("# skill\nexport TOKEN={SECRET_FIXTURE}\n");
    let risky = package_of(
        "fixture.activate-approved",
        body.as_bytes(),
        SkillCapabilitySurface::default(),
    );
    let risky_entity = authored_scan_candidate(&vault, &risky, 5)?;
    let mut approved = vault
        .get_skill_record(&risky_entity)?
        .expect("authored skill");
    approved.lifecycle_status = SkillLifecycle::Active;
    approved.approval_status = ClaimApprovalStatus::Approved;
    vault.update_skill_record(&risky_entity, &approved, t(7), 8)?;
    assert_eq!(
        vault
            .get_skill_record(&risky_entity)?
            .expect("activated skill")
            .approval_status,
        ClaimApprovalStatus::Approved
    );
    Ok(())
}

#[test]
fn a_hub_package_cannot_declare_its_own_approval_past_the_gate() -> Result<()> {
    let (_temp, vault) = open_vault();
    let body = format!("# skill\nexport TOKEN={SECRET_FIXTURE}\n");
    let mut package = package_of(
        "fixture.self-approved",
        body.as_bytes(),
        SkillCapabilitySurface::default(),
    );
    // The hostile shape: a remote package answering the owner's question for
    // him. The consult only escalates `auto`, so a self-declared `approved`
    // would walk a credential-bearing skill into `active` with no tap.
    package.record.approval_status = ClaimApprovalStatus::Approved;
    let entity = vault.import_skill_from_hub(&hub_ref(), &package, t(1), 2)?;

    let imported = vault.get_skill_record(&entity)?.expect("imported skill");
    assert_eq!(
        imported.approval_status,
        ClaimApprovalStatus::Auto,
        "consent is a local act; the import door stamps it rather than copying it"
    );

    let mut active = imported;
    active.lifecycle_status = SkillLifecycle::Active;
    assert_eq!(
        vault
            .update_skill_record(&entity, &active, t(3), 4)
            .expect_err("publisher approval cannot bypass local admission")
            .kind(),
        crate::error::ErrorKind::InvalidSkillBody
    );
    assert_eq!(
        vault
            .get_skill_record(&entity)?
            .expect("candidate")
            .lifecycle_status,
        SkillLifecycle::Candidate
    );
    Ok(())
}

#[test]
fn a_raw_entity_put_cannot_activate_around_the_scan_gate() -> Result<()> {
    let (_temp, vault) = open_vault();
    let body = format!("# skill\nexport TOKEN={SECRET_FIXTURE}\n");
    let package = package_of(
        "fixture.raw-put",
        body.as_bytes(),
        SkillCapabilitySurface::default(),
    );
    let entity = authored_scan_candidate(&vault, &package, 1)?;

    // `put_entity` and `batch().put` are update doors of their own: they reach
    // a SKILL body without passing the typed update door, so the consult has
    // to live where they converge.
    let mut active = vault.get_skill_record(&entity)?.expect("authored skill");
    active.lifecycle_status = SkillLifecycle::Active;
    active.approval_status = ClaimApprovalStatus::Auto;
    let data = encode_skill_record(&active)?;
    vault.put_entity(&entity, ENTITY_TYPE_SKILL, t(3), 4, &data)?;

    let stored = vault.get_skill_record(&entity)?.expect("activated skill");
    assert_eq!(stored.lifecycle_status, SkillLifecycle::Active);
    assert_eq!(
        stored.approval_status,
        ClaimApprovalStatus::Proposed,
        "the raw put lands active, and lands asking for the owner tap"
    );
    Ok(())
}
